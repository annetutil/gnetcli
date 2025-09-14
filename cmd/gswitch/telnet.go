package main

import (
	"fmt"

	"go.uber.org/zap"
)

// Telnet commands and options
const (
	TelnetIAC  = 255 // Interpret As Command
	TelnetDONT = 254 // Don't
	TelnetDO   = 253 // Do
	TelnetWONT = 252 // Won't
	TelnetWILL = 251 // Will
	TelnetSB   = 250 // Subnegotiation Begin
	TelnetSE   = 240 // Subnegotiation End

	// Telnet options
	TelnetEcho              = 1  // Echo
	TelnetSuppressGoAhead   = 3  // Suppress Go Ahead
	TelnetStatus            = 5  // Status
	TelnetTimingMark        = 6  // Timing Mark
	TelnetTerminalType      = 24 // Terminal Type
	TelnetWindowSize        = 31 // Window Size
	TelnetTerminalSpeed     = 32 // Terminal Speed
	TelnetRemoteFlowControl = 33 // Remote Flow Control
	TelnetLinemode          = 34 // Linemode
	TelnetEnvironment       = 36 // Environment
)

// processTelnetCommand processes Telnet IAC commands
func (s *CLISession) processTelnetCommand(buffer []byte) (processed int, shouldLog bool) {
	if len(buffer) < 2 {
		return 0, false
	}

	if buffer[0] != TelnetIAC {
		return 0, false
	}

	command := buffer[1]

	switch command {
	case TelnetDO, TelnetDONT, TelnetWILL, TelnetWONT:
		if len(buffer) < 3 {
			return 0, false // Need one more byte for option
		}
		option := buffer[2]
		s.handleTelnetNegotiation(command, option)
		return 3, true

	case TelnetSB:
		// Subnegotiation - looking for SE
		for i := 2; i < len(buffer)-1; i++ {
			if buffer[i] == TelnetIAC && buffer[i+1] == TelnetSE {
				s.handleTelnetSubnegotiation(buffer[2:i])
				return i + 2, true
			}
		}
		return 0, false // Incomplete subnegotiation

	default:
		// Simple commands (2 bytes)
		s.logger.Debug("received telnet command",
			zap.String("command", getTelnetCommandName(command)),
			zap.String("raw", fmt.Sprintf("% x", buffer[:2])))
		return 2, true
	}
}

// handleTelnetNegotiation handles Telnet negotiation commands
func (s *CLISession) handleTelnetNegotiation(command, option byte) {
	commandName := getTelnetCommandName(command)
	optionName := getTelnetOptionName(option)

	s.logger.Debug("received telnet negotiation",
		zap.String("command", commandName),
		zap.String("option", optionName),
		zap.String("raw", fmt.Sprintf("% x", []byte{TelnetIAC, command, option})))

	// Respond to some negotiation commands
	var response []byte

	switch command {
	case TelnetDO:
		switch option {
		case TelnetEcho:
			// Client asks us to do echo - agree
			response = []byte{TelnetIAC, TelnetWILL, TelnetEcho}
		case TelnetSuppressGoAhead:
			// Client asks to suppress go-ahead - agree
			response = []byte{TelnetIAC, TelnetWILL, TelnetSuppressGoAhead}
		default:
			// Refuse other options
			response = []byte{TelnetIAC, TelnetWONT, option}
		}

	case TelnetWILL:
		switch option {
		case TelnetTerminalType, TelnetWindowSize:
			// Client offers to send terminal type or window size - agree
			response = []byte{TelnetIAC, TelnetDO, option}
		default:
			// Don't need other options
			response = []byte{TelnetIAC, TelnetDONT, option}
		}
	}

	if response != nil {
		s.writer.Write(response)
		s.logger.Debug("sent telnet response",
			zap.String("response", fmt.Sprintf("% x", response)))
	}
}

// handleTelnetSubnegotiation handles Telnet subnegotiation
func (s *CLISession) handleTelnetSubnegotiation(data []byte) {
	if len(data) == 0 {
		return
	}

	option := data[0]
	optionName := getTelnetOptionName(option)

	s.logger.Debug("received telnet subnegotiation",
		zap.String("option", optionName),
		zap.String("data", fmt.Sprintf("% x", data)))

	switch option {
	case TelnetTerminalType:
		if len(data) >= 2 && data[1] == 0 { // IS
			termType := string(data[2:])
			s.logger.Debug("client terminal type", zap.String("type", termType))
		}
	case TelnetWindowSize:
		if len(data) >= 5 {
			width := (int(data[1]) << 8) | int(data[2])
			height := (int(data[3]) << 8) | int(data[4])
			s.logger.Debug("client window size",
				zap.Int("width", width),
				zap.Int("height", height))
		}
	}
}

// getTelnetCommandName returns Telnet command name
func getTelnetCommandName(command byte) string {
	switch command {
	case TelnetDONT:
		return "DONT"
	case TelnetDO:
		return "DO"
	case TelnetWONT:
		return "WONT"
	case TelnetWILL:
		return "WILL"
	case TelnetSB:
		return "SB"
	case TelnetSE:
		return "SE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", command)
	}
}

// getTelnetOptionName returns Telnet option name
func getTelnetOptionName(option byte) string {
	switch option {
	case TelnetEcho:
		return "ECHO"
	case TelnetSuppressGoAhead:
		return "SUPPRESS_GO_AHEAD"
	case TelnetStatus:
		return "STATUS"
	case TelnetTimingMark:
		return "TIMING_MARK"
	case TelnetTerminalType:
		return "TERMINAL_TYPE"
	case TelnetWindowSize:
		return "WINDOW_SIZE"
	case TelnetTerminalSpeed:
		return "TERMINAL_SPEED"
	case TelnetRemoteFlowControl:
		return "REMOTE_FLOW_CONTROL"
	case TelnetLinemode:
		return "LINEMODE"
	case TelnetEnvironment:
		return "ENVIRONMENT"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", option)
	}
}
