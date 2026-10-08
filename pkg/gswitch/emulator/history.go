package emulator

import "strings"

const (
	defaultHistorySize = 100
	maxHistorySize     = 1000
)

// commandHistory belongs to a logical CLI session, not the device or transport.
// Only submitted command lines enter it, never login/password/dialogue input.
type commandHistory struct {
	entries []string
	cursor  int // len(entries) is the current, not-yet-submitted draft
	draft   string
}

func (h *commandHistory) resetNavigation() {
	h.cursor = len(h.entries)
	h.draft = ""
}

func (h *commandHistory) remember(line string, limit int) {
	defer h.resetNavigation()
	if limit == 0 || strings.TrimSpace(line) == "" {
		return
	}
	if len(h.entries) == limit {
		copy(h.entries, h.entries[1:])
		h.entries = h.entries[:len(h.entries)-1]
	}
	h.entries = append(h.entries, line)
}

func (h *commandHistory) move(direction int, current string) (string, bool) {
	next := h.cursor + direction
	if next < 0 || next > len(h.entries) || len(h.entries) == 0 {
		return current, false
	}
	if h.cursor == len(h.entries) {
		h.draft = current
	}
	h.cursor = next
	if next == len(h.entries) {
		return h.draft, true
	}
	return h.entries[next], true
}

func (d *Device) recallHistory(s *terminalSession, direction int) {
	line, changed := s.history.move(direction, string(s.input))
	if !changed {
		d.emit(s, "\a")
		return
	}
	s.input = []byte(line)
	if s.echo == "character" {
		d.emit(s, "\r\x1b[2K")
		d.prompt(s)
	}
}

// consumeEscape accepts normal CSI (ESC [ A/B) and application-cursor SS3
// (ESC O A/B) Up/Down keys. State survives fragmented Input calls. Other
// CSI/SS3 sequences, including modified cursor keys, are consumed without becoming
// command text. History is inaccessible while logging in or answering a dialog.
func (d *Device) consumeEscape(s *terminalSession, b byte) bool {
	if b == 27 {
		s.ansi, s.ansiParams = 1, ""
		return true
	}
	if s.ansi == 0 {
		return false
	}
	if b == 3 { // An incomplete escape must not swallow Ctrl-C.
		s.ansi, s.ansiParams = 0, ""
		return false
	}
	if s.ansi == 1 {
		if b == '[' || b == 'O' {
			s.ansi = 2
		} else {
			s.ansi = 0
		}
		return true
	}
	if b >= 0x40 && b <= 0x7e {
		plain := s.ansiParams == "" || s.ansiParams == "1"
		s.ansi, s.ansiParams = 0, ""
		if plain && s.interaction == "editing" {
			switch b {
			case 'A':
				d.recallHistory(s, -1)
			case 'B':
				d.recallHistory(s, 1)
			}
		}
	} else if b >= 0x20 && b <= 0x3f && len(s.ansiParams) < 16 {
		// Once full, the retained non-plain prefix makes this sequence ineligible
		// for history. No unbounded buffer is allocated for malformed input.
		s.ansiParams += string(b)
	}
	return true
}
