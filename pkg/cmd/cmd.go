/*
Package cmd describes command and command result interface and implementations.
*/
package cmd

import (
	"bytes"
	"fmt"
	"regexp"
	"time"

	"github.com/annetutil/gnetcli/pkg/expr"
)

const (
	defaultReadTimeout = 10 * time.Second
)

type Res struct {
	output []byte
	error  []byte
	status int
	extra  map[string]interface{}
}

func (m *Res) GetExtra(key string) (interface{}, bool) {
	res, ok := m.extra[key]
	return res, ok
}

func (m *Res) Output() []byte {
	return m.output
}

func (m *Res) Error() []byte {
	return m.error
}

func (m *Res) Status() int {
	return m.status
}

func (m *Res) SetExtra(key string, value interface{}) {
	if m.extra == nil {
		m.extra = map[string]interface{}{}
	}
	m.extra[key] = value
}

func NewCmdRes(output []byte) CmdRes {
	return NewCmdResFull(output, nil, 0, nil)
}

func NewCmdResFull(output, err []byte, status int, extra map[string]interface{}) CmdRes {
	return &Res{
		output: output,
		error:  err,
		status: status,
		extra:  extra,
	}
}

// CmdRes is an interface for command result.
type CmdRes interface {
	Output() []byte
	Error() []byte
	Status() int
	SetExtra(string, interface{})
	GetExtra(string) (interface{}, bool)
}

// Cmd is an interface for command.
type Cmd interface {
	// GetCmdTimeout returns command timeout
	GetCmdTimeout() time.Duration
	// GetReadTimeout returns timeout between sequential reads
	GetReadTimeout() time.Duration
	// Value returns command value
	Value() []byte
	// GetExprCallback returns mapping of expressions and callbacks
	// to call if matched.
	GetExprCallback() ([]string, map[string]string)
	// QuestionHandler is called when question is matched.
	QuestionHandler(question []byte) ([]byte, error)
	// GetQuestionExprs returns list of possible questions.
	GetQuestionExprs() []expr.Expr
	// ErrorHandler is called when where is an error found in output.
	ErrorHandler(error) error
	// GetAgentForward returns whether SSH agent should be forwarded during execution.
	GetAgentForward() bool
}

// CmdImpl implements Cmd interface.
type CmdImpl struct {
	command         []byte
	readTimeout     time.Duration
	cmdTimeout      time.Duration
	forward         bool
	questionAnswers []Answer
	exprCallbacks   []ExprCallback
	errorHandler    func(error) error
}

func (m CmdImpl) GetQuestionExprs() []expr.Expr {
	exprs := []expr.Expr{}
	for _, qa := range m.questionAnswers {
		exprs = append(exprs, qa.GetExpr())
	}
	return exprs
}

func (m CmdImpl) Value() []byte {
	return m.command
}

func (m CmdImpl) ErrorHandler(err error) error {
	return m.errorHandler(err)
}

func (m CmdImpl) GetCmdTimeout() time.Duration {
	return m.cmdTimeout
}

func (m CmdImpl) GetReadTimeout() time.Duration {
	return m.readTimeout
}

func (m CmdImpl) GetAgentForward() bool {
	return m.forward
}

func (m CmdImpl) GetExprCallback() ([]string, map[string]string) {
	var res []string
	exprToCB := map[string]string{}
	for _, expr := range m.exprCallbacks {
		res = append(res, expr.expr)
		exprToCB[expr.expr] = expr.write
	}
	return res, exprToCB
}

func (m CmdImpl) QuestionHandler(question []byte) ([]byte, error) {
	for _, cmdAnswer := range m.questionAnswers {
		ans, err := cmdAnswer.Match(question)
		if err != nil {
			return nil, err
		}
		if len(ans) > 0 {
			return ans, nil
		}
	}
	return nil, nil
}

type CmdOption func(*CmdImpl)

func NewCmd(command string, opts ...CmdOption) Cmd {
	cmd := CmdImpl{
		command:         []byte(command),
		readTimeout:     defaultReadTimeout,
		cmdTimeout:      0,
		forward:         false,
		questionAnswers: nil,
		exprCallbacks:   nil,
		errorHandler: func(err error) error {
			return err
		},
	}
	for _, opt := range opts {
		opt(&cmd)
	}
	return cmd
}

func NewCmdList(commands []string, opts ...CmdOption) []Cmd {
	var cmdList []Cmd
	for _, command := range commands {
		cmdList = append(cmdList, NewCmd(command, opts...))
	}
	return cmdList
}

func WithReadTimeout(timeout time.Duration) CmdOption {
	return func(h *CmdImpl) {
		h.readTimeout = timeout
	}
}

func WithAnswers(answers ...Answer) CmdOption {
	return func(h *CmdImpl) {
		h.questionAnswers = answers
	}
}

func WithErrorIgnore() CmdOption {
	return func(h *CmdImpl) {
		h.errorHandler = func(err error) error {
			return nil
		}
	}
}

func WithCmdTimeout(timeout time.Duration) CmdOption {
	return func(h *CmdImpl) {
		h.cmdTimeout = timeout
	}
}

func WithForwarding(forward bool) CmdOption {
	return func(h *CmdImpl) {
		h.forward = forward
	}
}

type Answer struct {
	question string
	answer   string
}

func (m Answer) Match(question []byte) ([]byte, error) {
	if len(m.question) == 0 {
		return nil, nil
	}
	if m.question[0] == '/' && m.question[len(m.question)-1] == '/' {
		match, err := regexp.Match(m.question[1:len(m.question)-1], question)
		if err != nil {
			return nil, fmt.Errorf("regexp error %w", err)
		}
		if match {
			return []byte(m.answer), nil
		}
	} else {
		match := bytes.Equal([]byte(m.question), question)
		if match {
			return []byte(m.answer), nil
		}
	}
	return nil, nil
}

func (m Answer) GetExpr() expr.Expr {
	if len(m.question) == 0 {
		return nil
	}
	var res expr.Expr
	if m.question[0] == '/' && m.question[len(m.question)-1] == '/' {
		res = expr.NewSimpleExpr(m.question[1 : len(m.question)-1])
	} else {
		res = expr.NewSimpleExpr(regexp.QuoteMeta(m.question))
	}
	return res
}

func NewAnswer(question, answer string) Answer {
	return Answer{question: question, answer: answer}
}

func WithExprCallback(exprCallbacks ...ExprCallback) CmdOption {
	return func(h *CmdImpl) {
		h.exprCallbacks = exprCallbacks
	}
}

type ExprCallback struct {
	expr  string
	write string
}

func NewExprCallback(expr, write string) ExprCallback {
	return ExprCallback{expr: expr, write: write}
}
