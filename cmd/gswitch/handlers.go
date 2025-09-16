package main

import (
	"fmt"

	"go.uber.org/zap"
)

// handleCommand processes command and returns true if session should be terminated
func (s *CLISession) handleCommand(command string) bool {
	switch s.state.mode {
	case ModeUser, ModeEnable:
		return s.handleUserCommand(command)
	case ModeConfig:
		return s.handleConfigCommand(command)
	}
	return false
}

// handleLoginCommand handles commands in login mode
func (s *CLISession) handleLoginCommand() error {
	if s.state.authenticated {
		return nil
	}
	loginPrompt := s.vendor.loginPromptMaker(s.state)
	s.write(loginPrompt)
	_, username, err := s.readCommand(true)
	if err != nil {
		return err
	}
	passwordPrompt := s.vendor.passwordPromptMaker(s.state)
	s.write(passwordPrompt)
	_, password, err := s.readCommand(false)
	if err != nil {
		return err
	}
	if username != s.state.username || password != s.state.password {
		return fmt.Errorf("auth failed")
	}
	s.state.authenticated = true
	s.state.mode = ModeUser
	return nil
}

// handleUserCommand handles commands in user mode
func (s *CLISession) handleUserCommand(command string) bool {
	result, message, err := s.vendor.handleCommand(s.state, command)
	s.logger.Debug("handleUserCommand", zap.String("command", command), zap.Any("result", result), zap.String("message", message), zap.Error(err))
	if err != nil {
		return false
	}
	s.writeLine(message)
	return result == commandResultExit
}

// handleConfigCommand handles commands in configuration mode
func (s *CLISession) handleConfigCommand(command string) bool {
	result, message, err := s.vendor.handleConfigCommand(s.state, command)
	s.logger.Debug("handleConfigCommand", zap.String("command", command), zap.Any("result", result), zap.String("message", message), zap.Error(err))
	if err != nil {
		return false
	}
	s.writeLine(message)
	return result == commandResultExit
}
