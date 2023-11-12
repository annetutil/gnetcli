/*
Package genericcli implements Device interface using regular expressions.
*/
package genericcli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"

	"go.uber.org/zap"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/gerror"
	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/annetutil/gnetcli/pkg/terminal"
)

var ErrorCLILogin = errors.New("CLI login is not supported")

const AnyNLPattern = `(\r\n|\n)`
const DefaultCLIConnectTimeout = 15 * time.Second

var defaultWriteNewLine = []byte("\n") // const

type GenericCLI struct {
	prompt           expr.Expr
	login            expr.Expr
	password         expr.Expr
	error            expr.Expr
	question         expr.Expr
	passwordError    expr.Expr
	pager            expr.Expr
	autoCommands     []cmd.Cmd
	echoExprFormat   func(cmd.Cmd) expr.Expr
	credsInterceptor func(credentials.Credentials) credentials.Credentials
	writeNewline     []byte
	forceManualAuth  bool
	sftpEnabled      bool
	defaultAnswers   []cmd.Answer
}

type GenericCLIOption func(*GenericCLI)

// WithLoginExprs implements login using Device (like telnet or console)
func WithLoginExprs(login, password, passwordError expr.Expr) GenericCLIOption {
	return func(h *GenericCLI) {
		h.login = login
		h.password = password
		h.passwordError = passwordError
	}
}

func WithAnswers(answers []cmd.Answer) GenericCLIOption {
	return func(h *GenericCLI) {
		h.defaultAnswers = answers
	}
}

// WithManualAuth forces manual auth
func WithManualAuth() GenericCLIOption {
	return func(h *GenericCLI) {
		h.forceManualAuth = true
	}
}

// WithPager implements pager
func WithPager(pager expr.Expr) GenericCLIOption {
	return func(h *GenericCLI) {
		h.pager = pager
	}
}

// WithAutoCommands add commands to run at the start
func WithAutoCommands(commands []cmd.Cmd) GenericCLIOption {
	return func(h *GenericCLI) {
		h.autoCommands = commands
	}
}

// WithSFTPEnabled use sftp to download or upload
func WithSFTPEnabled() GenericCLIOption {
	return func(h *GenericCLI) {
		h.sftpEnabled = true
	}
}

// WithEchoExprFn set echo expr fabric
func WithEchoExprFn(fn func(cmd.Cmd) expr.Expr) GenericCLIOption {
	return func(h *GenericCLI) {
		h.echoExprFormat = fn
	}
}

// WithQuestion implements question
func WithQuestion(question expr.Expr) GenericCLIOption {
	return func(h *GenericCLI) {
		h.question = question
	}
}

func WithCredentialInterceptor(inter func(credentials.Credentials) credentials.Credentials) GenericCLIOption {
	return func(h *GenericCLI) {
		h.credsInterceptor = inter
	}
}

func WithWriteNewLine(newline []byte) GenericCLIOption {
	return func(h *GenericCLI) {
		h.writeNewline = newline
	}
}

func MakeGenericCLI(prompt, error expr.Expr, opts ...GenericCLIOption) GenericCLI {
	res := GenericCLI{
		prompt:           prompt,
		login:            nil,
		password:         nil,
		error:            error,
		question:         nil,
		passwordError:    nil,
		pager:            nil,
		autoCommands:     nil,
		echoExprFormat:   nil,
		credsInterceptor: nil,
		writeNewline:     defaultWriteNewLine,
		forceManualAuth:  false,
		sftpEnabled:      false,
		defaultAnswers:   nil,
	}
	for _, opt := range opts {
		opt(&res)
	}
	return res
}

type GenericDevice struct {
	cli          GenericCLI
	connector    streamer.Connector
	logger       *zap.Logger
	cliConnected bool // whether connector.Init was called or not
}

var _ device.Device = (*GenericDevice)(nil)

type GenericDeviceOption func(*GenericDevice)

func WithDevLogger(logger *zap.Logger) GenericDeviceOption {
	return func(h *GenericDevice) {
		h.logger = logger
	}
}

func (m *GenericDevice) GetAux() map[string]any {
	return nil
}

func (m *GenericDevice) Connect(ctx context.Context) (err error) {
	m.connector.SetCredentialsInterceptor(m.cli.credsInterceptor)
	if m.cli.sftpEnabled {
		if sftpSupported, ok := m.connector.(device.SFTPSupport); ok {
			sftpSupported.EnableSFTP()
		}
	}
	err = m.connector.Init(ctx)
	m.cliConnected = false
	// We postpone CLI initialization to first Execute call because we don't have to do this for Download/Upload.
	return err
}

func (m *GenericDevice) connectCLI(ctx context.Context) (err error) {
	m.cliConnected = true
	if m.connector.HasFeature(streamer.AutoLogin) && !m.cli.forceManualAuth {
		exprs := expr.NewSimpleExprListNamed(map[string][]expr.Expr{"prompt": {m.cli.prompt}, "question": {m.cli.question}})
		match, err := m.connector.ReadTo(ctx, exprs)
		if err != nil {
			return err
		}
		matchName := exprs.GetName(match.GetPatternNo())
		switch matchName {
		case "prompt":
		case "question":
			answered := false
			question := match.GetMatched()
			for _, cmdAnswer := range m.cli.defaultAnswers {
				ans, err := cmdAnswer.Match(question)
				if err != nil {
					return err
				}
				if len(ans) > 0 {
					answered = true
					err := m.connector.Write(ans)
					if err != nil {
						return fmt.Errorf("write error %v", err)
					}
					break
				}
			}
			if !answered {
				return device.ThrowQuestionException(question)
			}
			_, err = m.connector.ReadTo(ctx, m.cli.prompt)
			if err != nil {
				return err
			}
		}
	} else { // login by Device
		if m.cli.login == nil {
			return ErrorCLILogin
		}
		err := genericLogin(ctx, m.connector, m.cli)
		if err != nil {
			return err
		}
	}
	_, err = m.ExecuteBulk(m.cli.autoCommands)
	if err != nil {
		return err
	}
	return err
}

func (m *GenericDevice) Execute(command cmd.Cmd) (cmd.CmdRes, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultCLIConnectTimeout)
	defer cancel()
	m.logger.Debug("exec", zap.ByteString("command", command.Value()))
	if !m.cliConnected {
		err := m.connectCLI(ctx)
		if err != nil {
			return nil, err
		}
	}
	return GenericExecute(command, m.connector, m.cli)
}

func (m *GenericDevice) Download(paths []string) (map[string]streamer.File, error) {
	m.logger.Debug("download", zap.Any("paths", paths))
	res, err := m.connector.Download(paths, true)
	return res, err
}
func (m *GenericDevice) Upload(paths map[string]streamer.File) error {
	m.logger.Debug("upload", zap.Any("paths", paths))
	err := m.connector.Upload(paths)
	return err
}

func (m *GenericDevice) ExecuteBulk(commands []cmd.Cmd) ([]cmd.CmdRes, error) {
	var res []cmd.CmdRes
	for _, command := range commands {
		out, err := m.Execute(command)
		if err != nil {
			return nil, err
		}
		res = append(res, out)
	}
	return res, nil
}

func (m *GenericDevice) Close() {
	m.connector.Close()
}

func MakeGenericDevice(cli GenericCLI, connector streamer.Connector, opts ...GenericDeviceOption) GenericDevice {
	res := GenericDevice{
		cli:          cli,
		connector:    connector,
		logger:       zap.NewNop(),
		cliConnected: false,
	}
	for _, opt := range opts {
		opt(&res)
	}
	return res
}

func genericLogin(ctx context.Context, connector streamer.Connector, cli GenericCLI) (err error) {
	if cli.login == nil {
		return errors.New("login Expr is not set but required for login procedure")
	}
	_, err = connector.ReadTo(ctx, cli.login)
	if err != nil {
		return err
	}

	username, err := connector.GetCredentials().GetUsername()
	if err != nil {
		return err
	}

	err = connector.Write([]byte(username))
	if err != nil {
		return err
	}
	newline := cli.writeNewline
	if len(newline) > 0 {
		err := connector.Write(newline)
		if err != nil {
			return fmt.Errorf("write error %w", err)
		}
	}

	_, err = connector.ReadTo(ctx, cli.password)
	if err != nil {
		return err
	}

	passwords := connector.GetCredentials().GetPasswords()
	if len(passwords) == 0 {
		return errors.New("empty password")
	}
	// TODO: add multiple password support
	err = connector.Write([]byte(passwords[0].Value()))
	if err != nil {
		return err
	}
	if len(newline) > 0 {
		err := connector.Write(newline)
		if err != nil {
			return fmt.Errorf("write error %w", err)
		}
	}

	exprs := expr.NewSimpleExprListNamed(map[string][]expr.Expr{"prompt": {cli.prompt}, "passwordError": {cli.passwordError}})
	readRes, err := connector.ReadTo(ctx, exprs)
	if err != nil {
		return err
	}

	matchedExprName := exprs.GetName(readRes.GetPatternNo())
	if matchedExprName == "passwordError" {
		return gerror.NewAuthException("cli auth user")
	}

	return err
}

func GenericExecute(command cmd.Cmd, connector streamer.Connector, cli GenericCLI) (cmd.CmdRes, error) {
	ctx := context.Background()
	if cmdTimeout := command.GetCmdTimeout(); cmdTimeout > 0 {
		newCtx, cancel := context.WithTimeout(ctx, cmdTimeout)
		ctx = newCtx
		defer cancel()
	}
	if readTimeout := command.GetReadTimeout(); readTimeout > 0 {
		prevTimeout := connector.SetReadTimeout(readTimeout)
		defer connector.SetReadTimeout(prevTimeout)
	}

	err := connector.Write(command.Value())
	if err != nil {
		return nil, fmt.Errorf("write error %w", err)
	}
	newline := cli.writeNewline
	if len(newline) > 0 {
		err := connector.Write(newline)
		if err != nil {
			return nil, fmt.Errorf("write error %w", err)
		}
	}

	// read echo
	var expCmdEcho expr.Expr
	if cli.echoExprFormat != nil {
		expCmdEcho = cli.echoExprFormat(command)
	} else {
		expCmdEcho = expr.NewSimpleExpr(fmt.Sprintf("%s%s", regexp.QuoteMeta(string(command.Value())), AnyNLPattern))
	}

	var buffer bytes.Buffer
	cmdQuestions := command.GetQuestionExprs()

	questions := []expr.Expr{cli.question}
	if len(cmdQuestions) > 0 {
		questions = append(questions, cmdQuestions...)
	}
	checkExprs := []expr.NamedExpr{
		{Name: "echo", Exprs: []expr.Expr{expCmdEcho}},
		{Name: "prompt", Exprs: []expr.Expr{cli.prompt}},
		{Name: "pager", Exprs: []expr.Expr{cli.pager}},
		{Name: "question", Exprs: questions},
	}
	exprs := expr.NewSimpleExprListNamedOrdered(checkExprs)

	exprsAdd, exprsAddMap := command.GetExprCallback()
	for _, exprCB := range exprsAdd {
		exprs.Add("cb", expr.NewSimpleExpr(exprCB))
	}
	cbLimit := 100
	seenEcho := false
	for { // pager loop
		match, err := connector.ReadTo(ctx, exprs)
		if err != nil {
			var perr *streamer.ReadTimeoutException
			if errors.As(err, &perr) {
				// in some cases device messing up with output
				outputErr := checkError(cli.error, perr.LastRead)
				if outputErr != nil {
					return nil, outputErr
				}
			}
			return nil, err
		}
		matchName := exprs.GetName(match.GetPatternNo())

		if matchName == "echo" {
			seenEcho = true
			exprs.Delete("echo")
			continue
		}
		if !seenEcho {
			return nil, device.ThrowEchoReadException(match.GetBefore())
		}
		if matchName == "prompt" {
			buffer.Write(match.GetBefore())
			break
		} else if matchName == "pager" { // next page
			buffer.Write(match.GetBefore())
			if store, ok := match.GetMatchedGroups()["store"]; ok {
				buffer.Write(store)
			}
			err = connector.Write([]byte(` `))
			if err != nil {
				return nil, fmt.Errorf("write error %v", err)
			}
		} else if matchName == "question" { // question
			question := match.GetMatched()
			answer, err := command.QuestionHandler(question)
			if err != nil {
				return nil, fmt.Errorf("QuestionHandler error %v", err)
			}
			if len(answer) > 0 {
				err := connector.Write(answer)
				if err != nil {
					return nil, fmt.Errorf("write error %v", err)
				}
				err = connector.Write([]byte("\n"))
				if err != nil {
					return nil, fmt.Errorf("write error %v", err)
				}
			} else {
				return nil, device.ThrowQuestionException(question)
			}
		} else if matchName == "cb" { // ExprCallback
			if cbLimit == 0 { // reset cbLimit in other cases
				return nil, fmt.Errorf("callback limit")
			}
			cbLimit--
			wr := exprsAddMap[exprsAdd[match.GetPatternNo()-3]]
			err := connector.Write([]byte(wr))
			if err != nil {
				return nil, fmt.Errorf("write error %v", err)
			}
		} else {
			panic("unknown option")
		}
	}

	res := buffer.Bytes()
	fondErr := checkError(cli.error, res)
	if fondErr != nil {
		fondErr = command.ErrorHandler(fondErr)
	}

	strippedRes, err := terminal.Parse(res)
	if err != nil {
		return nil, err
	}
	strippedRes = normalizeNewlines(strippedRes)
	status := 0
	var errorRes []byte
	if fondErr != nil {
		errorRes = strippedRes
		strippedRes = []byte{}
		status = 1
	}
	ret := cmd.NewCmdResFull(strippedRes, errorRes, status, nil)
	return ret, nil
}

func checkError(errorExpression expr.Expr, data []byte) error {
	mRes, ok := errorExpression.Match(data)
	if ok {
		return device.ThrowExecException(string(data[mRes.Start:mRes.End]))
	}

	return nil
}

func normalizeNewlines(data []byte) []byte {
	data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	data = bytes.ReplaceAll(data, []byte(" \n"), []byte("\n"))
	return data
}
