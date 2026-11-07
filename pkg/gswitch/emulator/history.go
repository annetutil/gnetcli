package emulator

import (
	"strconv"
	"strings"
)

const (
	defaultHistorySize = 100
	maxHistorySize     = 1000
)

// commandHistory belongs to a logical CLI session, not the device or transport.
// Only submitted command lines enter it, never login/password/dialogue input.
type commandHistory struct {
	entries     []string
	cursor      int // len(entries) is the current, not-yet-submitted draft
	draftCursor int
	draft       string
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
	if s.history.cursor == len(s.history.entries) {
		s.history.draftCursor = s.cursor
	}
	line, changed := s.history.move(direction, string(s.input))
	if !changed {
		d.emit(s, "\a")
		return
	}
	s.input = []byte(line)
	s.cursor = len(s.input)
	if s.history.cursor == len(s.history.entries) {
		s.cursor = min(s.history.draftCursor, len(s.input))
	}
	if s.echo == "character" {
		d.redrawEditor(s)
	}
}

// consumeEscape accepts CSI/SS3 history/cursor navigation and Home/End/Delete.
// State survives fragmented Input; unsupported/modified sequences are discarded.
// Navigation is inaccessible during login, dialogues, paging and execution.
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
		params := s.ansiParams
		s.ansi, s.ansiParams = 0, ""
		if s.interaction == "editing" {
			plain := params == "" || params == "1"
			switch b {
			case 'A':
				if plain {
					d.recallHistory(s, -1)
				}
			case 'B':
				if plain {
					d.recallHistory(s, 1)
				}
			case 'H':
				if plain {
					d.moveCursor(s, 0)
				}
			case 'F':
				if plain {
					d.moveCursor(s, len(s.input))
				}
			case 'C', 'D':
				count := 1
				var err error
				if params != "" {
					count, err = strconv.Atoi(params)
				}
				if err == nil && count > 0 && count <= 4096 {
					if b == 'D' {
						count = -count
					}
					d.moveCursor(s, s.cursor+count)
				}
			case '~':
				switch params {
				case "1", "7":
					d.moveCursor(s, 0)
				case "4", "8":
					d.moveCursor(s, len(s.input))
				case "3":
					d.deleteByte(s)
				}
			}
		}
	} else if b >= 0x20 && b <= 0x3f && len(s.ansiParams) < 16 {
		// Once full, the retained non-plain prefix makes this sequence ineligible
		// for history. No unbounded buffer is allocated for malformed input.
		s.ansiParams += string(b)
	}
	return true
}
