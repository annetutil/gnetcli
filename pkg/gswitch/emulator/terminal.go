package emulator

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

func (d *Device) newline(text string) string {
	return strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\n", d.profile.def.Terminal.Newline)
}

func (d *Device) promptText(s *terminalSession) (string, error) {
	switch s.interaction {
	case "boot", "executing":
		return "", nil
	case "username":
		return d.profile.def.Login.UsernamePrompt, nil
	case "password":
		return d.profile.def.Login.PasswordPrompt, nil
	case "paging":
		return d.profile.def.Terminal.Pager, nil
	case "dialog":
		return d.profile.render(d.profile.def.Dialogs[s.dialog].Prompt, d.data(s))
	default:
		return d.profile.render(d.profile.def.Modes[s.mode().name].Prompt, d.data(s))
	}
}

func (d *Device) secret(s *terminalSession) bool {
	return s.interaction == "password" || (s.interaction == "dialog" && d.profile.def.Dialogs[s.dialog].Secret)
}

func (d *Device) prompt(s *terminalSession) {
	p, err := d.promptText(s)
	if err != nil {
		d.failure(s, err)
		return
	}
	if s.interaction == "editing" {
		s.commandPrompt = p
	}
	d.emit(s, p)
	if !d.secret(s) && s.echo == "character" {
		d.emit(s, string(s.input))
	}
}

func (d *Device) log(s *terminalSession, e Event) {
	policy := e.Policy
	if policy == "" {
		policy = d.profile.def.Terminal.LogPolicy
	}
	if policy == "defer" && (s.interaction != "editing" || len(s.input) > 0) {
		if len(s.deferred) < 64 {
			s.deferred = append(s.deferred, e)
		} else {
			d.record(s, "log-dropped", "deferred queue full")
		}
		return
	}
	text := d.newline(e.Text)
	if !strings.HasSuffix(text, d.profile.def.Terminal.Newline) {
		text += d.profile.def.Terminal.Newline
	}
	if policy == "redraw" && s.interaction != "executing" && s.interaction != "boot" {
		d.emit(s, "\r\x1b[2K"+text)
		d.prompt(s)
	} else {
		d.emit(s, text)
	}
}

func (d *Device) inputByte(s *terminalSession, b byte) {
	if d.consumeEscape(s, b) {
		return
	}
	if s.skipLF {
		s.skipLF = false
		if b == '\n' {
			return
		}
	}
	if s.interaction == "boot" {
		return
	}
	if b == 3 { // Ctrl-C cancels only this interaction, not the connection/device.
		s.generation++
		s.actions = nil
		s.pageRest = ""
		s.input = nil
		s.history.resetNavigation()
		s.answer = ""
		if s.interaction == "username" || s.interaction == "password" {
			s.interaction = "username"
		} else {
			s.interaction = "editing"
		}
		d.emit(s, "^C"+d.profile.def.Terminal.Newline)
		d.finish(s)
		return
	}
	if s.interaction == "executing" {
		return
	}
	if s.interaction == "paging" {
		switch b {
		case 'q', 'Q':
			s.pageRest = ""
			s.actions = nil
			d.emit(s, "\r\x1b[2K")
			d.finish(s)
		case ' ', '\r', '\n':
			if b == '\r' {
				s.skipLF = true
			}
			d.emit(s, "\r\x1b[2K")
			count := s.pageLines
			if b != ' ' {
				count = 1
			}
			s.interaction = "executing"
			if !d.page(s, s.pageRest, count) {
				d.continueTask(s)
			}
		}
		return
	}
	if b == 4 && len(s.input) == 0 {
		_, _ = d.action(s, Action{Op: "logout"})
		return
	}
	if b == '\t' && s.interaction == "editing" {
		d.complete(s)
		return
	}
	if b == '?' && s.interaction == "editing" {
		d.showHelp(s)
		return
	}
	if b == 8 || b == 127 {
		if len(s.input) > 0 {
			s.input = s.input[:len(s.input)-1]
			if !d.secret(s) && s.echo == "character" {
				d.emit(s, "\b \b")
			}
		}
		return
	}
	if b == 21 { // Ctrl-U
		if !d.secret(s) && s.echo == "character" {
			d.emit(s, strings.Repeat("\b \b", len(s.input)))
		}
		s.input = nil
		return
	}
	if b == '\r' || b == '\n' {
		s.skipLF = b == '\r'
		line := string(s.input)
		if !d.secret(s) && s.echo == "line" {
			d.emit(s, line)
		}
		s.input = nil
		d.emit(s, d.profile.def.Terminal.Newline)
		switch s.interaction {
		case "username":
			s.username = line
			s.interaction = "password"
			d.prompt(s)
		case "password":
			if s.username == d.options.Username && line == d.options.Password {
				s.interaction = "editing"
				s.attempts = 0
				d.trigger("authenticated", s)
				d.finish(s)
			} else {
				s.attempts++
				d.emit(s, d.newline(d.profile.def.Login.Failure)+d.profile.def.Terminal.Newline)
				if s.attempts >= d.profile.def.Login.Attempts {
					s.interaction = "username"
					s.username = ""
					s.attempts = 0
					d.detach(s, nil)
				} else {
					s.interaction = "username"
					d.prompt(s)
				}
			}
		case "dialog":
			d.answerDialog(s, line)
		default:
			d.command(s, line)
		}
		return
	}
	// The first editor is deliberately ASCII. Unsupported control/ANSI bytes are
	// not interpreted as commands. Full cursor/UTF-8 editing belongs in a frontend.
	if b < 32 || b > 126 {
		return
	}
	if len(s.input) >= d.profile.def.Terminal.MaxInput {
		d.emit(s, "\a")
		return
	}
	s.input = append(s.input, b)
	if !d.secret(s) && s.echo == "character" {
		d.emit(s, string(b))
	}
}

func (d *Device) command(s *terminalSession, line string) {
	s.history.remember(line, *d.profile.def.Terminal.HistorySize)
	if strings.TrimSpace(line) == "" {
		d.finish(s)
		return
	}
	m, err := d.profile.Parse(s.mode().name, line)
	if err != nil {
		kind, offset := "invalid", 0
		if e, ok := err.(*ParseError); ok {
			kind, offset = e.Kind, e.Offset
		}
		// The line editor currently accepts single-line ASCII input. Use the last
		// emitted CLI prompt, not a freshly rendered one: another session may have
		// changed the shared hostname while this command was being typed.
		column := utf8.RuneCountInString(s.commandPrompt) + offset
		expectedColumn := column
		last, _ := utf8.DecodeLastRuneInString(line)
		if kind == "incomplete" && line != "" && !unicode.IsSpace(last) {
			expectedColumn++
		}
		text, renderErr := d.profile.render(d.profile.def.Errors[kind], map[string]any{
			"Line": line, "Offset": offset, "Prompt": s.commandPrompt,
			"Caret":         strings.Repeat(" ", column) + "^",
			"ExpectedCaret": strings.Repeat(" ", expectedColumn) + "^",
		})
		if renderErr != nil {
			d.failure(s, renderErr)
			return
		}
		d.emit(s, d.newline(text))
		d.finish(s)
		return
	}
	s.args = m.Args
	s.generation++
	s.actions = d.profile.commands[m.Command].Actions
	s.actionIndex = 0
	s.interaction = "executing"
	d.trigger("command:"+m.Command, s)
	d.advanceTo(d.now)
	d.continueTask(s)
}

func (d *Device) finish(s *terminalSession) {
	if s.interaction != "username" && s.interaction != "password" {
		s.interaction = "editing"
	}
	s.answer = ""
	s.actions = nil
	s.pageRest = ""
	deferred := s.deferred
	s.deferred = nil
	for _, e := range deferred {
		e.Policy = "raw"
		d.log(s, e)
	}
	d.prompt(s)
}

func (d *Device) page(s *terminalSession, text string, count int) bool {
	if count <= 0 {
		d.emit(s, text)
		s.pageRest = ""
		return false
	}
	end := 0
	for i := 0; i < count; i++ {
		n := strings.IndexByte(text[end:], '\n')
		if n < 0 {
			d.emit(s, text)
			s.pageRest = ""
			return false
		}
		end += n + 1
	}
	d.emit(s, text[:end])
	s.pageRest = text[end:]
	if s.pageRest == "" {
		return false
	}
	s.interaction = "paging"
	d.prompt(s)
	return true
}

func (d *Device) answerDialog(s *terminalSession, line string) {
	dialog := d.profile.def.Dialogs[s.dialog]
	for _, a := range dialog.Answers {
		if a.Input == line {
			s.answer = line
			s.interaction = "executing"
			// Resume the original command after the selected answer's actions.
			remaining := append([]Action(nil), s.actions[s.actionIndex:]...)
			s.actions = append(append([]Action(nil), a.Actions...), remaining...)
			s.actionIndex = 0
			d.continueTask(s)
			return
		}
	}
	d.emit(s, "Invalid answer"+d.profile.def.Terminal.Newline)
	d.prompt(s)
}
