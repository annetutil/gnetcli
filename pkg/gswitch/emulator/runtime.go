package emulator

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrClosed       = errors.New("emulator closed")
	ErrNotReady     = errors.New("device login service not ready")
	ErrConsoleBusy  = errors.New("console already attached")
	ErrSlowConsumer = errors.New("terminal output queue full")
	ErrReboot       = errors.New("device rebooted")
)

type Options struct {
	Username     string
	Password     string
	Scenario     *Scenario
	OutputBuffer int
}

type AttachOptions struct {
	// Console names a persistent line. Empty means a new management session.
	Console string
	// Authenticated is set only by a transport which has authenticated Username.
	// Console access always uses its own login, independent of transport auth.
	Authenticated bool
	Username      string
}

type Snapshot struct {
	Now        time.Duration
	Lifecycle  string
	LoginReady bool
	Running    map[string]any
	Startup    map[string]any
	Sessions   []SessionSnapshot
}

type SessionSnapshot struct {
	ID          uint64
	Console     string
	Attached    bool
	Username    string
	Mode        string
	Interaction string
	Candidate   map[string]any
}

// Trace describes semantic events only: passwords and raw input are never stored.
type Trace struct {
	At           time.Duration
	Session      uint64
	Kind, Detail string
}

// Device serializes all state transitions under one lock. No transition does
// network I/O or waits for a consumer. Manual Advance and Run are exclusive.
type Device struct {
	mu                           sync.Mutex
	profile                      *Profile
	options                      Options
	running, startup             map[string]any
	revision                     uint64
	now                          time.Duration
	lifecycle                    string
	ready, closed, realtime      bool
	epoch, sequence, nextSession uint64
	queue                        eventQueue
	sessions                     map[uint64]*terminalSession
	consoles                     map[string]*terminalSession
	trace                        []Trace
	batch                        *terminalSession
	batchText                    string
}

type scheduled struct {
	at         time.Duration
	seq, epoch uint64
	run        func()
}
type eventQueue []scheduled

func (q eventQueue) Len() int { return len(q) }
func (q eventQueue) Less(i, j int) bool {
	if q[i].at == q[j].at {
		return q[i].seq < q[j].seq
	}
	return q[i].at < q[j].at
}
func (q eventQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *eventQueue) Push(x any)   { *q = append(*q, x.(scheduled)) }
func (q *eventQueue) Pop() any {
	old := *q
	x := old[len(old)-1]
	old[len(old)-1] = scheduled{}
	*q = old[:len(old)-1]
	return x
}

func New(profile *Profile, options Options) (*Device, error) {
	if profile == nil {
		return nil, fmt.Errorf("nil profile")
	}
	if options.OutputBuffer < 0 {
		return nil, fmt.Errorf("negative output buffer")
	}
	if options.OutputBuffer == 0 {
		options.OutputBuffer = 64
	}
	if options.Scenario != nil {
		// Copy public scenario data, so callers cannot race with the runtime.
		s := *options.Scenario
		s.Timeline = append([]Event(nil), s.Timeline...)
		s.Triggers = append([]Trigger(nil), s.Triggers...)
		options.Scenario = &s
		if err := validateScenario(&s, nil); err != nil {
			return nil, err
		}
		checkpoints := map[string]bool{}
		for _, c := range profile.commands {
			for _, a := range c.Actions {
				if a.Op == "checkpoint" {
					checkpoints[a.Name] = true
				}
			}
		}
		for _, dialog := range profile.def.Dialogs {
			for _, answer := range dialog.Answers {
				for _, a := range answer.Actions {
					if a.Op == "checkpoint" {
						checkpoints[a.Name] = true
					}
				}
			}
		}
		for _, t := range s.Triggers {
			if strings.HasPrefix(t.On, "checkpoint:") && !checkpoints[strings.TrimPrefix(t.On, "checkpoint:")] {
				return nil, fmt.Errorf("unknown trigger checkpoint %q", t.On)
			}
			if strings.HasPrefix(t.On, "command:") {
				if _, ok := profile.commands[strings.TrimPrefix(t.On, "command:")]; !ok {
					return nil, fmt.Errorf("unknown trigger command %q", t.On)
				}
			}
		}
	}
	d := &Device{profile: profile, options: options, running: cloneMap(profile.def.InitialState), startup: cloneMap(profile.def.InitialState), sessions: map[uint64]*terminalSession{}, consoles: map[string]*terminalSession{}}
	d.startBoot()
	d.advanceTo(0)
	return d, nil
}

func clone(v any) any {
	switch x := v.(type) {
	case map[string]any:
		return cloneMap(x)
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = clone(v)
		}
		return out
	default:
		return x
	}
}
func cloneMap(v map[string]any) map[string]any {
	if v == nil {
		return nil
	}
	out := make(map[string]any, len(v))
	for k, v := range v {
		out[k] = clone(v)
	}
	return out
}

func (d *Device) record(s *terminalSession, kind, detail string) {
	id := uint64(0)
	if s != nil {
		id = s.id
	}
	if len(d.trace) == 256 {
		copy(d.trace, d.trace[1:])
		d.trace = d.trace[:255]
	}
	d.trace = append(d.trace, Trace{d.now, id, kind, detail})
}

func (d *Device) Trace() []Trace {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Trace(nil), d.trace...)
}

func (d *Device) Snapshot() Snapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := Snapshot{Now: d.now, Lifecycle: d.lifecycle, LoginReady: d.ready, Running: cloneMap(d.running), Startup: cloneMap(d.startup)}
	for _, s := range d.orderedSessions() {
		out.Sessions = append(out.Sessions, SessionSnapshot{ID: s.id, Console: s.console, Attached: s.attachment != nil, Username: s.username, Mode: s.mode().name, Interaction: s.interaction, Candidate: cloneMap(s.candidate)})
	}
	return out
}

func (d *Device) orderedSessions() []*terminalSession {
	out := make([]*terminalSession, 0, len(d.sessions))
	for _, s := range d.sessions {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

func (d *Device) schedule(after time.Duration, f func()) {
	d.sequence++
	heap.Push(&d.queue, scheduled{d.now + after, d.sequence, d.epoch, f})
}

func (d *Device) advanceTo(target time.Duration) {
	for len(d.queue) > 0 && d.queue[0].at <= target {
		e := heap.Pop(&d.queue).(scheduled)
		d.now = e.at
		if e.epoch == d.epoch {
			e.run()
		}
	}
	d.now = target
}

// Advance runs scheduled events in timestamp/sequence order without sleeping.
func (d *Device) Advance(delta time.Duration) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}
	if d.realtime {
		return fmt.Errorf("manual Advance is disabled during Run")
	}
	if delta < 0 || d.now+delta < d.now {
		return fmt.Errorf("invalid time advance")
	}
	d.advanceTo(d.now + delta)
	return nil
}

// Run drives logical time using a 5 ms wall-clock tick. It does not accelerate
// the clocks or deadlines of external clients. Cancel does not close Device.
func (d *Device) Run(ctx context.Context) error {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return ErrClosed
	}
	if d.realtime {
		d.mu.Unlock()
		return fmt.Errorf("device clock already running")
	}
	d.realtime = true
	base := d.now
	d.mu.Unlock()
	defer func() { d.mu.Lock(); d.realtime = false; d.mu.Unlock() }()
	start := time.Now()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			d.mu.Lock()
			if d.closed {
				d.mu.Unlock()
				return ErrClosed
			}
			d.advanceTo(base + time.Since(start))
			d.mu.Unlock()
		}
	}
}

func (d *Device) startBoot() {
	d.lifecycle = "booting"
	d.ready = len(d.profile.def.Boot) == 0
	if d.ready {
		d.lifecycle = "operational"
	}
	for _, event := range d.profile.def.Boot {
		d.schedule(event.At, func() { d.event(event, nil) })
	}
	if s := d.options.Scenario; s != nil {
		for _, event := range s.Timeline {
			d.schedule(event.At, func() { d.event(event, nil) })
		}
	}
}

func (d *Device) trigger(name string, s *terminalSession) {
	d.record(s, name, "")
	if scenario := d.options.Scenario; scenario != nil {
		for _, t := range scenario.Triggers {
			if t.On == name {
				d.schedule(t.After, func() { d.event(t.Event, s) })
			}
		}
	}
}

func (d *Device) event(e Event, target *terminalSession) {
	d.record(target, "event", e.Source+":"+e.Kind)
	switch e.Kind {
	case "lifecycle":
		d.lifecycle = e.Text
	case "ready":
		d.ready = e.Text == "true"
		if d.ready {
			for _, s := range d.orderedSessions() {
				if s.interaction == "boot" {
					s.interaction = "username"
					d.prompt(s)
				}
			}
		}
	case "raw", "log":
		for _, s := range d.orderedSessions() {
			if e.Route == "session" && s != target {
				continue
			}
			if e.Route == "console" && s.console == "" {
				continue
			}
			if e.Route == "monitor" && !s.monitor {
				continue
			}
			// Direct console/kernel bytes bypass the per-session monitor setting.
			if e.Kind == "raw" {
				d.emit(s, e.Text)
			} else {
				d.log(s, e)
			}
		}
	}
}

// Inject emits a validated event immediately. It is useful as a test control API.
func (d *Device) Inject(e Event) error {
	if e.File != "" || e.At != 0 || e.Route == "session" {
		return fmt.Errorf("Inject requires immediate, in-memory, non-session event")
	}
	if err := compileEvent(&e, nil); err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}
	d.event(e, nil)
	return nil
}

func (d *Device) Reboot() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return ErrClosed
	}
	d.reboot()
	d.advanceTo(d.now)
	return nil
}

func (d *Device) reboot() {
	d.epoch++
	d.queue = nil
	d.running = cloneMap(d.startup)
	d.revision++
	for _, s := range d.orderedSessions() {
		if s.console == "" {
			d.detach(s, ErrReboot)
			continue
		}
		s.reset(d.profile)
		s.interaction = "boot"
	}
	d.record(nil, "reboot", "")
	d.startBoot()
	if d.ready {
		for _, s := range d.orderedSessions() {
			s.interaction = "username"
			d.prompt(s)
		}
	}
}

func (d *Device) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	d.queue = nil
	for _, s := range d.orderedSessions() {
		d.detach(s, ErrClosed)
	}
	return nil
}

func (d *Device) config(s *terminalSession) map[string]any {
	if s.candidate != nil {
		return s.candidate
	}
	return d.running
}
func (d *Device) data(s *terminalSession) map[string]any {
	return map[string]any{"Config": d.config(s), "Running": d.running, "Startup": d.startup, "Args": s.args, "Context": s.mode().context, "Username": s.username, "Dirty": s.candidate != nil && !reflect.DeepEqual(s.candidate, d.running), "Input": s.answer}
}
