package emulator

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

func editorPosition(s *terminalSession, cursor int) (row, column int) {
	total := utf8.RuneCountInString(s.commandPrompt) + cursor
	if s.columns <= 0 {
		return 0, total
	}
	row, column = total/s.columns, total%s.columns
	// Terminals defer wrapping until the next printable character.
	if cursor == len(s.input) && total > 0 && column == 0 {
		row--
		column = s.columns - 1
	}
	return
}

func (d *Device) trackEditor(s *terminalSession) {
	if s.echo != "character" || s.interaction != "editing" {
		s.renderRows = 0
		return
	}
	row, _ := editorPosition(s, len(s.input))
	s.renderRows = row + 1
	s.renderRow, _ = editorPosition(s, s.cursor)
}

func (d *Device) positionEditorCursor(s *terminalSession, from int) {
	if s.echo != "character" || s.cursor == from {
		return
	}
	if s.columns <= 0 {
		delta := s.cursor - from
		direction := "C"
		if delta < 0 {
			delta = -delta
			direction = "D"
		}
		d.emit(s, fmt.Sprintf("\x1b[%d%s", delta, direction))
		return
	}
	fromRow, _ := editorPosition(s, from)
	row, col := editorPosition(s, s.cursor)
	text := "\r"
	delta := row - fromRow
	if delta < 0 {
		text += fmt.Sprintf("\x1b[%dA", -delta)
	}
	if delta > 0 {
		text += fmt.Sprintf("\x1b[%dB", delta)
	}
	if col > 0 {
		text += fmt.Sprintf("\x1b[%dC", col)
	}
	d.emit(s, text)
}

func (d *Device) moveCursor(s *terminalSession, to int) {
	to = max(0, min(to, len(s.input)))
	old := s.cursor
	s.cursor = to
	d.positionEditorCursor(s, old)
	d.trackEditor(s)
}

func (d *Device) clearEditor(s *terminalSession) {
	var text strings.Builder
	text.WriteString("\r")
	rows := min(4096, max(1, s.renderRows))
	row := min(rows-1, s.renderRow)
	if s.columns > 0 && row > 0 {
		fmt.Fprintf(&text, "\x1b[%dA", row)
	}
	text.WriteString("\x1b[2K")
	for i := 1; i < rows; i++ {
		text.WriteString("\x1b[1B\r\x1b[2K")
	}
	if rows > 1 {
		fmt.Fprintf(&text, "\x1b[%dA", rows-1)
	}
	d.emit(s, text.String())
}

func (d *Device) redrawEditor(s *terminalSession) {
	if s.echo == "character" {
		d.clearEditor(s)
		d.prompt(s)
	}
}

func (d *Device) insertByte(s *terminalSession, b byte) {
	if s.interaction != "editing" {
		s.cursor = len(s.input)
	}
	atEnd := s.cursor == len(s.input)
	s.input = append(s.input, 0)
	copy(s.input[s.cursor+1:], s.input[s.cursor:len(s.input)-1])
	s.input[s.cursor] = b
	s.cursor++
	if !d.secret(s) && s.echo == "character" {
		if atEnd {
			d.emit(s, string(b))
			d.trackEditor(s)
		} else {
			d.redrawEditor(s)
		}
	}
}

func (d *Device) backspace(s *terminalSession) {
	if s.interaction != "editing" {
		s.cursor = len(s.input)
	}
	if s.cursor == 0 {
		return
	}
	atEnd := s.cursor == len(s.input)
	copy(s.input[s.cursor-1:], s.input[s.cursor:])
	s.input = s.input[:len(s.input)-1]
	s.cursor--
	if !d.secret(s) && s.echo == "character" {
		if atEnd && s.columns == 0 {
			d.emit(s, "\b \b")
			d.trackEditor(s)
		} else {
			d.redrawEditor(s)
		}
	}
}

func (d *Device) deleteByte(s *terminalSession) {
	if s.cursor >= len(s.input) {
		return
	}
	copy(s.input[s.cursor:], s.input[s.cursor+1:])
	s.input = s.input[:len(s.input)-1]
	d.redrawEditor(s)
}

func (d *Device) pageLength(s *terminalSession) int {
	count := s.pageLines
	if count > 0 && s.rows > 0 {
		count = min(count, max(1, s.rows-1))
	}
	return count
}

// pageBoundary counts ASCII/Unicode code points as cells, skips CSI styling,
// and accounts for soft wraps. Wide glyphs/combining characters are not modeled.
func pageBoundary(text string, rows, columns int) int {
	if columns <= 0 {
		end := 0
		for i := 0; i < rows; i++ {
			n := strings.IndexByte(text[end:], '\n')
			if n < 0 {
				return len(text)
			}
			end += n + 1
		}
		return end
	}
	used, col := 1, 0
	for i := 0; i < len(text); {
		if text[i] == 27 && i+1 < len(text) && text[i+1] == '[' {
			i += 2
			for i < len(text) {
				b := text[i]
				i++
				if b >= 0x40 && b <= 0x7e {
					break
				}
			}
			continue
		}
		r, size := utf8.DecodeRuneInString(text[i:])
		if r == '\r' {
			col = 0
			i += size
			continue
		}
		if r == '\n' {
			i += size
			if used >= rows {
				return i
			}
			used++
			col = 0
			continue
		}
		if r >= 32 {
			if col >= columns {
				if used >= rows {
					return i
				}
				used++
				col = 0
			}
			col++
		}
		i += size
	}
	return len(text)
}

func (d *Device) editorOutputEnd(s *terminalSession) {
	cursor := s.cursor
	d.moveCursor(s, len(s.input))
	s.cursor = cursor
}
