package main

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
)

func (s *CLISession) readCommand(echoEnabled bool) (string, string, error) {
	line := make([]byte, 0, 100)
	ansiBuffer := make([]byte, 0, 10)
	telnetBuffer := make([]byte, 0, 20)
	inAnsiSequence := false
	inTelnetSequence := false

	for {
		char, err := s.reader.ReadByte()
		if err != nil {
			return "", "", err
		}
		// ? is a special command for help, no need to wait enter
		if char == '?' {
			return "command", "?", nil
		}

		// Handle Telnet IAC commands
		if char == 255 { // IAC - start of Telnet command
			inTelnetSequence = true
			telnetBuffer = append(telnetBuffer, char)
			continue
		}

		if inTelnetSequence {
			telnetBuffer = append(telnetBuffer, char)

			// Check if Telnet command is complete
			if processed, shouldLog := s.processTelnetCommand(telnetBuffer); processed > 0 {
				if shouldLog {
					s.logger.Debug("processed telnet command",
						zap.String("raw", fmt.Sprintf("% x", telnetBuffer[:processed])))
				}
				// Reset buffer
				telnetBuffer = telnetBuffer[:0]
				inTelnetSequence = false
				continue
			}

			// If buffer is too large, reset it
			if len(telnetBuffer) > 20 {
				s.logger.Debug("telnet buffer overflow, resetting")
				telnetBuffer = telnetBuffer[:0]
				inTelnetSequence = false
			}
			continue
		}

		// Handle ANSI escape sequences
		if char == 27 { // ESC - start of ANSI sequence
			inAnsiSequence = true
			ansiBuffer = append(ansiBuffer, char)
			continue
		}

		if inAnsiSequence {
			ansiBuffer = append(ansiBuffer, char)

			// Check ANSI sequence completion
			if s.isAnsiSequenceComplete(ansiBuffer) {
				s.logger.Debug("received ANSI sequence",
					zap.String("sequence", fmt.Sprintf("%q", ansiBuffer)),
					zap.String("hex", fmt.Sprintf("% x", ansiBuffer)))

				// Handle special ANSI codes
				s.handleAnsiSequence(ansiBuffer)

				// Reset buffer and flag
				ansiBuffer = ansiBuffer[:0]
				inAnsiSequence = false
				continue
			}

			// If sequence is too long, consider it complete
			if len(ansiBuffer) > 10 {
				s.logger.Debug("received long ANSI sequence (truncated)",
					zap.String("sequence", fmt.Sprintf("%q", ansiBuffer)),
					zap.String("hex", fmt.Sprintf("% x", ansiBuffer)))
				ansiBuffer = ansiBuffer[:0]
				inAnsiSequence = false
			}
			continue
		}

		// Normal character processing
		if char == '\r' || char == '\n' {
			s.writer.Write([]byte{'\r', '\n'})
			break
		}

		if char == 3 { // Ctrl+C
			return "cancel", "", nil
		}

		if char == 127 || char == 8 { // Backspace/Delete
			if len(line) > 0 {
				line = line[:len(line)-1]
				// Send backspace sequence: \b \b (erase character)
				s.writer.Write([]byte{8, ' ', 8})
			}
			continue
		}
		// Printable ASCII characters
		if char >= 32 && char <= 126 {
			if echoEnabled {
				s.writer.Write([]byte{char})
			}
			line = append(line, char)
		}
	}

	return "command", strings.TrimSpace(string(line)), nil
}

// isAnsiSequenceComplete checks if ANSI sequence is complete
func (s *CLISession) isAnsiSequenceComplete(buffer []byte) bool {
	if len(buffer) < 2 {
		return false
	}

	// ESC [ ... (CSI - Control Sequence Introducer)
	if len(buffer) >= 3 && buffer[0] == 27 && buffer[1] == '[' {
		// CSI sequences end with character in range 0x40-0x7E
		lastChar := buffer[len(buffer)-1]
		return lastChar >= 0x40 && lastChar <= 0x7E
	}

	// ESC O ... (SS3 - Single Shift Three)
	if len(buffer) >= 2 && buffer[0] == 27 && buffer[1] == 'O' {
		// SS3 sequences usually have length 3
		return len(buffer) >= 3
	}

	// Simple ESC sequences (ESC + one character)
	if len(buffer) >= 2 && buffer[0] == 27 {
		secondChar := buffer[1]
		// If second character is not [ or O, it's a simple sequence
		if secondChar != '[' && secondChar != 'O' {
			return true
		}
	}

	return false
}

// handleAnsiSequence handles ANSI sequences
func (s *CLISession) handleAnsiSequence(sequence []byte) {
	if len(sequence) < 2 {
		return
	}

	// Determine sequence type
	sequenceType := "unknown"
	description := ""

	if sequence[0] == 27 && sequence[1] == '[' {
		// CSI sequences
		sequenceType = "CSI"
		lastChar := sequence[len(sequence)-1]

		switch lastChar {
		case 'A':
			description = "Cursor Up"
		case 'B':
			description = "Cursor Down"
		case 'C':
			description = "Cursor Forward"
		case 'D':
			description = "Cursor Back"
		case 'H':
			description = "Cursor Home"
		case 'F':
			description = "Cursor End"
		case '~':
			// Function keys
			if len(sequence) >= 4 {
				switch string(sequence[2 : len(sequence)-1]) {
				case "1":
					description = "Home key"
				case "2":
					description = "Insert key"
				case "3":
					description = "Delete key"
				case "4":
					description = "End key"
				case "5":
					description = "Page Up"
				case "6":
					description = "Page Down"
				default:
					description = fmt.Sprintf("Function key (%s)", string(sequence[2:len(sequence)-1]))
				}
			}
		default:
			description = fmt.Sprintf("CSI command (%c)", lastChar)
		}
	} else if sequence[0] == 27 && sequence[1] == 'O' {
		// SS3 sequences (usually function keys)
		sequenceType = "SS3"
		if len(sequence) >= 3 {
			switch sequence[2] {
			case 'P':
				description = "F1"
			case 'Q':
				description = "F2"
			case 'R':
				description = "F3"
			case 'S':
				description = "F4"
			case 'H':
				description = "Home"
			case 'F':
				description = "End"
			default:
				description = fmt.Sprintf("SS3 key (%c)", sequence[2])
			}
		}
	} else if sequence[0] == 27 && len(sequence) == 2 {
		// Simple ESC sequences
		sequenceType = "ESC"
		switch sequence[1] {
		case '[':
			description = "Left bracket (incomplete CSI?)"
		case 'O':
			description = "Letter O (incomplete SS3?)"
		default:
			description = fmt.Sprintf("ESC + %c", sequence[1])
		}
	}

	s.logger.Debug("processed ANSI sequence",
		zap.String("type", sequenceType),
		zap.String("description", description),
		zap.String("raw", fmt.Sprintf("%q", sequence)))
}

func (s *CLISession) write(text string) {
	s.writer.Write([]byte(text))
}

func (s *CLISession) writeLine(text string) {
	s.writer.Write([]byte(text + "\r\n"))
}

func (s *CLISession) writePrompt() {
	prompt := s.vendor.promptMaker(s.state)
	s.write(prompt)
}

func (s *CLISession) getModeString() string {
	switch s.state.mode {
	case ModeLogin:
		return "login"
	case ModeUser:
		return "user"
	case ModeEnable:
		return "enable"
	case ModeConfig:
		return "config"
	default:
		return "unknown"
	}
}
