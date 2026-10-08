package emulator

import (
	"fmt"
	"io"
)

type modeFrame struct {
	name    string
	context map[string]string
}
type terminalSession struct {
	id                             uint64
	console, username, interaction string
	stack                          []modeFrame
	input                          []byte
	commandPrompt                  string // Last prompt actually emitted for command input.
	skipLF                         bool
	ansi                           int
	ansiParams                     string
	history                        commandHistory
	echo                           string
	attempts                       int
	monitor                        bool
	pageLines                      int
	candidate                      map[string]any
	baseRevision                   uint64
	args                           map[string]string
	answer, dialog                 string
	actions                        []Action
	actionIndex                    int
	generation                     uint64
	pageRest                       string
	deferred                       []Event
	attachment                     *Session
}

func (s *terminalSession) mode() modeFrame { return s.stack[len(s.stack)-1] }
func (s *terminalSession) reset(p *Profile) {
	id, console, attachment, generation := s.id, s.console, s.attachment, s.generation
	*s = terminalSession{id: id, console: console, attachment: attachment, generation: generation + 1, interaction: "editing", stack: []modeFrame{{p.def.InitialMode, map[string]string{}}}, echo: p.def.Terminal.Echo, pageLines: p.def.Terminal.PageLines, args: map[string]string{}}
}

// Session is one attachment. Read supports one reader; Input and Close may be
// called concurrently. A persistent console's state survives Session.Close.
type Session struct {
	device   *Device
	terminal *terminalSession
	output   chan []byte
	done     chan struct{}
	err      error
	pending  []byte
}

func (d *Device) Attach(o AttachOptions) (*Session, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, ErrClosed
	}
	if o.Console == "" && !d.ready {
		return nil, ErrNotReady
	}
	s := d.consoles[o.Console]
	if o.Console == "" {
		s = nil
	}
	fresh := s == nil
	if s != nil && s.attachment != nil {
		return nil, ErrConsoleBusy
	}
	if fresh {
		d.nextSession++
		s = &terminalSession{id: d.nextSession, console: o.Console}
		s.reset(d.profile)
		if o.Console != "" {
			d.consoles[o.Console] = s
		}
		d.sessions[s.id] = s
		if !d.ready {
			s.interaction = "boot"
		} else if o.Console != "" || !o.Authenticated {
			s.interaction = "username"
		} else {
			s.username = o.Username
		}
	}
	a := &Session{device: d, terminal: s, output: make(chan []byte, d.options.OutputBuffer), done: make(chan struct{})}
	s.attachment = a
	d.record(s, "attach", o.Console)
	if fresh && s.interaction == "editing" {
		d.trigger("authenticated", s)
	}
	if s.interaction != "executing" && s.interaction != "boot" {
		d.prompt(s)
	}
	d.advanceTo(d.now)
	return a, nil
}

func (s *Session) Input(data []byte) error {
	d := s.device
	d.mu.Lock()
	defer d.mu.Unlock()
	if s.terminal.attachment != s {
		if s.err != nil {
			return s.err
		}
		return io.EOF
	}
	d.batch = s.terminal
	defer d.flushBatch()
	for _, b := range data {
		if s.terminal.attachment != s {
			break
		}
		d.inputByte(s.terminal, b)
		d.advanceTo(d.now)
	}
	return nil
}

func (s *Session) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(s.pending) == 0 {
		b, ok := <-s.output
		if !ok {
			if err := s.Err(); err != nil {
				return 0, err
			}
			return 0, io.EOF
		}
		s.pending = b
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}

func (s *Session) Done() <-chan struct{} { return s.done }
func (s *Session) Err() error            { s.device.mu.Lock(); defer s.device.mu.Unlock(); return s.err }
func (s *Session) Close() error {
	d := s.device
	d.mu.Lock()
	defer d.mu.Unlock()
	if s.terminal.attachment == s {
		d.detach(s.terminal, nil)
	}
	return nil
}

func (d *Device) detach(s *terminalSession, err error) {
	if d.batch == s {
		d.flushBatch()
	}
	if a := s.attachment; a != nil {
		a.err = err
		close(a.output)
		close(a.done)
		s.attachment = nil
		d.record(s, "detach", "")
	}
	if s.console == "" {
		s.generation++
		delete(d.sessions, s.id)
	}
}

func (d *Device) emit(s *terminalSession, text string) {
	if text == "" || s.attachment == nil {
		return
	}
	if d.batch == s {
		if len(d.batchText)+len(text) > 1<<20 {
			d.batch = nil
			d.batchText = ""
			d.detach(s, fmt.Errorf("output exceeds 1 MiB"))
			return
		}
		d.batchText += text
		return
	}
	if len(text) > 1<<20 {
		d.detach(s, fmt.Errorf("output exceeds 1 MiB"))
		return
	}
	select {
	case s.attachment.output <- []byte(text):
	default:
		d.detach(s, ErrSlowConsumer)
	}
}

func (d *Device) flushBatch() {
	s, text := d.batch, d.batchText
	d.batch = nil
	d.batchText = ""
	if s != nil {
		d.emit(s, text)
	}
}

func (d *Device) failure(s *terminalSession, err error) {
	// Template/action errors are emulator defects, not fake device syntax errors.
	d.record(s, "emulator-error", err.Error())
	d.detach(s, fmt.Errorf("emulator: %w", err))
}

// Output exposes owned output chunks as an alternative to Read. Do not mix the two.
func (s *Session) Output() <-chan []byte { return s.output }
