package main

import (
	"bufio"
	"context"
	"io"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

// CLIMode represents CLI operating mode
type CLIMode int

const (
	ModeLogin CLIMode = iota
	ModeUser
	ModeEnable
	ModeConfig
)

type commandResult int

const (
	commandResultContinue commandResult = iota
	commandResultExit
)

// CLIState stores CLI session state
type CLIState struct {
	mode          CLIMode
	subMode       string // any vendor specific mode
	hostname      string
	username      string
	password      string
	enablePass    string
	authenticated bool
	config        map[string]interface{}
}

func (s *CLIState) NewMode(mode CLIMode) {
	s.mode = mode
}

func (s *CLIState) NewSubMode(mode string) {
	s.subMode = mode
}

func NewCLIState(username, password string) *CLIState {
	return &CLIState{
		mode:          ModeUser,
		hostname:      "switch",
		username:      username,
		password:      password,
		enablePass:    password,
		authenticated: false,
		config:        make(map[string]interface{}),
	}
}

func NewCLIStateWithAuth(username, password string) *CLIState {
	return &CLIState{
		mode:          ModeLogin,
		hostname:      "switch",
		username:      username,
		password:      password,
		enablePass:    password,
		authenticated: false,
		config:        make(map[string]interface{}),
	}
}

type CLISession struct {
	conn   ssh.Channel
	state  *CLIState
	logger *zap.Logger
	reader *bufio.Reader
	writer io.Writer
	vendor vendor
}

// NewCLISession creates new CLI session
func NewCLISession(conn ssh.Channel, username, password string, logger *zap.Logger, vendor vendor) *CLISession {
	return &CLISession{
		conn:   conn,
		state:  NewCLIState(username, password),
		logger: logger,
		reader: bufio.NewReader(conn),
		writer: conn,
		vendor: vendor,
	}
}

func NewCLISessionWithAuth(conn ssh.Channel, username, password string, logger *zap.Logger) *CLISession {
	return &CLISession{
		conn:   conn,
		state:  NewCLIStateWithAuth(username, password),
		logger: logger,
		reader: bufio.NewReader(conn),
		writer: conn,
	}
}

func (s *CLISession) Run(ctx context.Context) error {
	defer s.conn.Close()
	s.writeLine("welcome")

	if s.state.mode == ModeLogin {
		err := s.handleLoginCommand()
		if err != nil {
			s.writeLine("auth failed")
			return err
		}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			s.writePrompt()
			op, opArgs, err := s.readCommand(true)
			s.logger.Debug("received command", zap.String("op", op), zap.String("opArgs", opArgs), zap.String("mode", s.getModeString()))
			if err != nil {
				if err == io.EOF {
					return nil
				}
				return err
			}
			switch op {
			case "command":
				isExit := s.handleCommand(opArgs)
				s.logger.Debug("command result", zap.Bool("isExit", isExit))

				if isExit {
					return nil
				}
			case "cancel":
				return nil
			}
		}
	}
}
