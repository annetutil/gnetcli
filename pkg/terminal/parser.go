/*
Package terminal implements terminal evaluation functions.
*/
package terminal

import (
	"bytes"
	"fmt"
	"strconv"
)

// https://xfree86.org/4.8.0/ctlseqs.html
// https://gist.github.com/fnky/458719343aabd01cfb17a3a4f7296797
const (
	RETURN  = '\r'
	NEWLINE = '\n'
	ESCAPE  = 0x1B
	CSI     = '['
	CUB     = 'D'
	ELINE   = 'K'
	SGR     = 'm'
	CUP     = 'H'
	ED      = 'J'
)

func sliceEdit(s []byte, begin, finish int) []byte {
	return append(s[:begin], s[finish:]...)
}

type Parser struct {
	pos  int
	data []byte
}

func Parse(data []byte) ([]byte, error) {
	parser := Parser{
		pos:  -1, // The first call to consume will set pos to 0 character of the string
		data: data,
	}
	return parser.parse()
}

func (m *Parser) consume() (byte, error) {
	if m.pos+1 == len(m.data) {
		return 0, fmt.Errorf("length is exceeded")
	}
	m.pos++
	return m.data[m.pos], nil
}

func (m *Parser) unconsume() {
	m.pos--
}

func (m *Parser) parse() ([]byte, error) {
	lastNewline := -1
	for m.pos+1 < len(m.data) {
		char, err := m.consume()
		if err != nil {
			return nil, err
		}

		if char == ESCAPE {
			escStart := m.pos
			// check [
			char, err := m.consume()
			if err != nil {
				return nil, err
			}
			// Controls beginning with ESC
			if char == '>' { // DECKPNM
				m.data = sliceEdit(m.data, escStart, m.pos+1)
				m.pos = escStart - 1
				continue
			}
			if char != CSI {
				continue
			}

			parameter := []byte{}
			for { // parameter bytes
				char, err := m.consume()
				if err != nil {
					return nil, err
				}
				if char >= 0x30 && char <= 0x3F { // any including none bytes
					parameter = append(parameter, char)
				} else {
					m.unconsume()
					break
				}
			}

			//intermediate := []byte{}
			for { // intermediate bytes
				char, err := m.consume()
				if err != nil {
					return nil, err
				}
				if char >= 0x20 && char < 0x2F {
					//intermediate = append(intermediate, char)
				} else {
					m.unconsume()
					break
				}
			}

			// final byte
			final := uint8(0)
			char, err = m.consume()
			if err != nil {
				return nil, err
			}
			if char >= 0x40 && char < 0x7E {
				final = char
			} else {
				return nil, fmt.Errorf("unxpected final byte")
			}

			switch final {
			case CUB:
				nArgsInt, err := strconv.Atoi(string(parameter))
				if err != nil {
					return nil, fmt.Errorf("wrong arg %v", parameter)
				}
				if nArgsInt == 0 {
					nArgsInt = 1
				}
				// The number of characters may be bigger than valid number
				begin := max(lastNewline+1, escStart-nArgsInt)
				m.data = sliceEdit(m.data, begin, m.pos+1)
				m.pos = begin - 1

			case ELINE, SGR:
				m.data = sliceEdit(m.data, escStart, m.pos+1)
				// Rolling back to the place of the deleted esc-1, consume moved to the esc old pos
				// Necessary in case of two esc sequences in a row
				m.pos = escStart - 1
			case CUP, ED: // not implemented
				m.data = sliceEdit(m.data, escStart, m.pos+1)
				m.pos = escStart - 1
				continue
			default:
				if (final == 'l' || final == 'h') && bytes.Equal(parameter, []byte("?1")) { // private
					m.data = sliceEdit(m.data, escStart, m.pos+1)
					m.pos = escStart - 1
					continue
				}
				start := max(m.pos-50, 0)
				finish := min(m.pos+50, len(m.data))
				return nil, fmt.Errorf("unknown esc %c ...%s... ", char, m.data[start:finish])
			}
		} else if char == RETURN {
			if m.pos+1 < len(m.data) && (m.data[m.pos+1] == NEWLINE || m.data[m.pos+1] == RETURN) {
				continue
			}
			lineStart := bytes.LastIndexByte(m.data[0:m.pos], NEWLINE)
			if lineStart == -1 {
				lineStart = 0
				m.data = m.data[m.pos+1:]
			} else {
				m.data = sliceEdit(m.data, lineStart+1, m.pos+1)
			}
			m.pos = lineStart - 1
		} else if char == NEWLINE {
			lastNewline = m.pos
		}
	}

	return m.data, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
