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

const (
	promptExprName    = "prompt"
	passwdErrExprName = "passwordError"
	questionExprName  = "question"
	passwordExprName  = "password"
	loginExprName     = "login"
	pagerExprName     = "pager"
	echoExprName      = "echo"
	cbExprName        = "cb"
)

var defaultWriteNewLine = []byte("\n") // const

type terminalParams struct {
	w int
	h int
}

type ResultCBType int

const (
	CBRaw ResultCBType = iota
)

type GenericCLI struct {
	prompt           expr.Expr
	login            expr.Expr
	password         expr.Expr
	error            expr.Expr
	question         expr.Expr
	loginCB          []cmd.ExprCallback // used only during login, before first prompt
	passwordError    expr.Expr
	pager            expr.Expr
	resultCB         func(ResultCBType, []byte) ([]byte, error)
	autoCommands     []cmd.Cmd
	initWait         time.Duration
	echoExprFormat   func(cmd.Cmd) expr.Expr
	credsInterceptor func(credentials.Credentials) credentials.Credentials
	writeNewline     []byte
	forceManualAuth  bool
	sftpEnabled      bool
	defaultAnswers   []cmd.Answer
	terminalParams   *terminalParams
	connectTimeout   time.Duration
}

func (m *GenericCLI) SetConnectTimeout(timeout time.Duration) time.Duration {
	oldTimeout := m.connectTimeout
	m.connectTimeout = timeout
	return oldTimeout
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

func WithResultCB(cb func(ResultCBType, []byte) ([]byte, error)) GenericCLIOption {
	return func(h *GenericCLI) {
		h.resultCB = cb
	}
}

// WithAutoCommands add commands to run at the start
func WithAutoCommands(commands []cmd.Cmd) GenericCLIOption {
	return func(h *GenericCLI) {
		h.autoCommands = commands
	}
}

// WithInitialWait sets sleep duration before first reading after login
func WithInitialWait(duration time.Duration) GenericCLIOption {
	return func(h *GenericCLI) {
		h.initWait = duration
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

func WithAdditionalLoginCallbacks(cb []cmd.ExprCallback) GenericCLIOption {
	return func(h *GenericCLI) {
		h.loginCB = append(h.loginCB, cb...)
	}
}

func WithLoginCallbacks(cb []cmd.ExprCallback) GenericCLIOption {
	return func(h *GenericCLI) {
		h.loginCB = cb
	}
}

func WithCredentialInterceptor(inter func(credentials.Credentials) credentials.Credentials) GenericCLIOption {
	return func(h *GenericCLI) {
		h.credsInterceptor = inter
	}
}

func WithTerminalParams(width, height int) GenericCLIOption {
	return func(h *GenericCLI) {
		if h.terminalParams == nil {
			h.terminalParams = &terminalParams{w: width, h: height}
		} else {
			h.terminalParams.h = height
			h.terminalParams.w = width
		}
	}
}

func WithWriteNewLine(newline []byte) GenericCLIOption {
	return func(h *GenericCLI) {
		h.writeNewline = newline
	}
}

func WithConnectTimeout(connectTimeout time.Duration) GenericCLIOption {
	return func(h *GenericCLI) {
		h.connectTimeout = connectTimeout
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
		initWait:         0,
		echoExprFormat:   nil,
		credsInterceptor: nil,
		writeNewline:     defaultWriteNewLine,
		forceManualAuth:  false,
		sftpEnabled:      false,
		defaultAnswers:   nil,
		terminalParams:   &terminalParams{w: 400, h: 0},
		loginCB:          []cmd.ExprCallback{},
		connectTimeout:   DefaultCLIConnectTimeout,
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

func WithDevAdditionalLoginCallbacks(cb []cmd.ExprCallback) GenericDeviceOption {
	return func(h *GenericDevice) {
		h.cli.loginCB = append(h.cli.loginCB, cb...)
	}
}

func WithDevLoginCallbacks(cb []cmd.ExprCallback) GenericDeviceOption {
	return func(h *GenericDevice) {
		h.cli.loginCB = cb
	}
}

func (m *GenericDevice) GetAux() map[string]any {
	return nil
}

type SetTerminalSize interface {
	SetTerminalSize(w int, h int)
}

func (m *GenericDevice) Connect(ctx context.Context) (err error) {
	m.connector.SetCredentialsInterceptor(m.cli.credsInterceptor)
	if m.cli.sftpEnabled {
		if sftpSupported, ok := m.connector.(device.SFTPSupport); ok {
			sftpSupported.EnableSFTP()
		}
	}

	if m.cli.terminalParams != nil {
		if v, ok := m.connector.(SetTerminalSize); ok {
			v.SetTerminalSize(m.cli.terminalParams.w, m.cli.terminalParams.h)
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
		exprMap := map[string][]expr.Expr{
			promptExprName:   {m.cli.prompt},
			questionExprName: {m.cli.question},
		}
		if len(m.cli.loginCB) > 0 {
			cbExprs := []expr.Expr{}
			for _, ex := range m.cli.loginCB {
				cbExprs = append(cbExprs, ex.GetExpr())
			}
			exprMap[cbExprName] = cbExprs
		}
		exprs := expr.NewSimpleExprListNamed(exprMap)
		for i := 0; i < 10; i++ {
			match, err := m.connector.ReadTo(ctx, exprs)
			if err != nil {
				return err
			}
			matchName := exprs.GetName(match.GetPatternNo())
			switch matchName {
			case promptExprName:
			case questionExprName:
				seenOk := false
				question := match.GetMatched()
				for _, cmdAnswer := range m.cli.defaultAnswers {
					ans, ok, err := cmdAnswer.Match(question)
					if err != nil {
						return err
					}
					if len(ans) > 0 {
						err := m.connector.Write(ans)
						if err != nil {
							return fmt.Errorf("write error %w", err)
						}
					}
					if ok {
						seenOk = true
						break
					}
				}
				if !seenOk {
					return device.ThrowQuestionException(question)
				}
				_, err = m.connector.ReadTo(ctx, m.cli.prompt)
				if err != nil {
					return err
				}
			case cbExprName:
				pos := match.GetUnderlyingRes().GetPatternNo()
				f := m.cli.loginCB[pos]
				err := m.connector.Write(f.GetAns())
				if err != nil {
					return fmt.Errorf("write error %w", err)
				}
				continue
			default:
				return fmt.Errorf("unknown expr name %q", matchName)
			}
			break
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
	// TODO: fix case with question or manual login
	if m.cli.initWait > 0 {
		time.Sleep(m.cli.initWait)
	}
	_, err = m.ExecuteBulk(m.cli.autoCommands)
	if err != nil {
		return err
	}
	return err
}

func (m *GenericDevice) Execute(command cmd.Cmd) (cmd.CmdRes, error) {
	ctx, cancel := context.WithTimeout(context.Background(), m.cli.connectTimeout)
	defer cancel()
	m.logger.Debug("exec", zap.ByteString("command", command.Value()))
	if !m.cliConnected {
		err := m.connectCLI(ctx)
		if err != nil {
			return nil, err
		}
	}
	return GenericExecute(command, m.connector, m.cli, m.logger)
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

type GetAllRegex interface {
	GetLogin() expr.Expr
	GetPassword() expr.Expr
	GetAuthError() expr.Expr
	GetPrompt() expr.Expr
}

func (m *GenericDevice) GetLogin() expr.Expr {
	return m.cli.login
}

func (m *GenericDevice) GetPassword() expr.Expr {
	return m.cli.password
}

func (m *GenericDevice) GetAuthError() expr.Expr {
	return m.cli.passwordError
}

func (m *GenericDevice) GetPrompt() expr.Expr {
	return m.cli.prompt
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

func (m *GenericDevice) SetCLIConnectTimeout(timeout time.Duration) time.Duration {
	return m.cli.SetConnectTimeout(timeout)
}

func genericLogin(ctx context.Context, connector streamer.Connector, cli GenericCLI) (err error) {
	if cli.login == nil {
		return errors.New("login Expr is not set but required for login procedure")
	}

	passwords := connector.GetCredentials().GetPasswords(ctx)
	if len(passwords) == 0 {
		return errors.New("empty password")
	}

	i := 0
	checkExprs := []expr.NamedExpr{
		{Name: loginExprName, Exprs: []expr.Expr{cli.login}},
		{Name: passwordExprName, Exprs: []expr.Expr{cli.password}},
		{Name: promptExprName, Exprs: []expr.Expr{cli.prompt}},
		{Name: passwdErrExprName, Exprs: []expr.Expr{cli.passwordError}},
	}

	for i < len(passwords) {

		exprsLogin := expr.NewSimpleExprListNamedOrdered(checkExprs)
		readResLogin, err := connector.ReadTo(ctx, exprsLogin)
		if err != nil {
			return err
		}

		matchedExprNameLogin := exprsLogin.GetName(readResLogin.GetPatternNo())
		if matchedExprNameLogin == loginExprName {
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
		} else if matchedExprNameLogin == passwordExprName {
			err = connector.Write([]byte(passwords[i].Value()))
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
			i++
		} else if matchedExprNameLogin == passwdErrExprName {
			continue
		} else if matchedExprNameLogin == promptExprName {
			return nil
		}
	}
	exprs := expr.NewSimpleExprListNamedOrdered(checkExprs)
	readResLogin, err := connector.ReadTo(ctx, exprs)
	if err != nil {
		return err
	}

	matchedExprNameLogin := exprs.GetName(readResLogin.GetPatternNo())
	if matchedExprNameLogin == promptExprName {
		return nil
	}

	return gerror.NewAuthException("cli auth user")

}

func GenericExecute(command cmd.Cmd, connector streamer.Connector, cli GenericCLI, logger *zap.Logger) (cmd.CmdRes, error) {
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
		expCmdEcho = expr.NewSimpleExpr().FromPattern(fmt.Sprintf("%s%s", regexp.QuoteMeta(string(command.Value())), AnyNLPattern))
	}

	var buffer bytes.Buffer
	cmdQuestions := command.GetQuestionExprs()

	questions := []expr.Expr{cli.question}
	if len(cmdQuestions) > 0 {
		questions = append(cmdQuestions, questions...)
	}
	checkExprs := []expr.NamedExpr{
		{Name: echoExprName, Exprs: []expr.Expr{expCmdEcho}},
		{Name: promptExprName, Exprs: []expr.Expr{cli.prompt}},
		{Name: pagerExprName, Exprs: []expr.Expr{cli.pager}},
		{Name: questionExprName, Exprs: questions},
	}
	exprs := expr.NewSimpleExprListNamedOrdered(checkExprs)

	exprsAdd, exprsAddMap := command.GetExprCallback()
	for _, exprCB := range exprsAdd {
		exprs.Add("cb", expr.NewSimpleExpr().FromPattern(exprCB))
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
		matchId := match.GetPatternNo()
		matchName := exprs.GetName(matchId)

		if matchName == echoExprName {
			seenEcho = true
			exprs.Delete(echoExprName)
			continue
		}
		mbefore := match.GetBefore()
		if !seenEcho {
			if matchName == questionExprName { // caught question before echo
				// check for echo, drop it and proceed with question
				termParsedEcho, err := terminal.ParseDropLastReturn(mbefore)
				if err != nil {
					return nil, fmt.Errorf("echo terminal parse error %w", err)
				}
				mres, ok := exprs.Match(termParsedEcho)
				if !ok {
					return nil, device.ThrowEchoReadException(mbefore, true)
				}
				if exprs.GetName(mres.PatternNo) == echoExprName {
					seenEcho = true
				}
				mbefore = termParsedEcho[mres.End:]
			}
		}

		if !seenEcho {
			promptFound := matchName == promptExprName
			// case where we caught prompt before echo because of term codes in echo
			if len(mbefore) < 2 || !promptFound { // don't bother to do complex logic
				return nil, device.ThrowEchoReadException(mbefore, promptFound)
			}

			termParsedEcho, err := terminal.ParseDropLastReturn(mbefore)
			if err != nil {
				return nil, fmt.Errorf("echo terminal parse error %w", err)
			}
			mres, ok := exprs.Match(termParsedEcho)
			if !ok {
				// prompt expression may consume newline from echo, but it must be presented in echo
				if mbefore[len(mbefore)-1] != '\n' {
					mbefore = append(mbefore, '\n')
				}
				termParsedEcho, err = terminal.ParseDropLastReturn(mbefore)
				if err != nil {
					return nil, fmt.Errorf("echo terminal parse error %w", err)
				}
				mres, ok = exprs.Match(termParsedEcho)
				if !ok {
					return nil, device.ThrowEchoReadException(mbefore, promptFound)
				}
			}
			// assuring that it is echo
			if exprs.GetName(mres.PatternNo) != echoExprName {
				return nil, device.ThrowEchoReadException(mbefore, promptFound)
			}
			if mres.End > len(termParsedEcho) {
				return nil, errors.New("termParsedEcho len less than mres.End")
			}
			seenEcho = true
			exprs.Delete(echoExprName)
			// delete echo
			mbefore = termParsedEcho[mres.End:]
		}
		if matchName == promptExprName {
			buffer.Write(mbefore)
			if store, ok := match.GetMatchedGroups()["store"]; ok {
				buffer.Write(store)
			}
			break
		} else if matchName == pagerExprName { // next page
			buffer.Write(mbefore)
			if store, ok := match.GetMatchedGroups()["store"]; ok {
				buffer.Write(store)
			}
			logger.Debug("auto answer to pager")
			err = connector.Write([]byte(` `))
			if err != nil {
				return nil, fmt.Errorf("write error %w", err)
			}
		} else if matchName == questionExprName { // question
			question := match.GetMatched()
			logger.Debug("QuestionHandler question", zap.ByteString("question", question))
			answer, err := command.QuestionHandler(question)
			if err != nil {
				if errors.Is(err, cmd.ErrNotFoundAnswer) {
					return nil, device.ThrowQuestionException(question)
				}
				return nil, fmt.Errorf("QuestionHandler error %w", err)
			}
			logger.Debug("QuestionHandler answer", zap.ByteString("answer", answer))
			err = connector.Write(answer)
			if err != nil {
				return nil, fmt.Errorf("write error %w", err)
			}
		} else if matchName == "cb" { // ExprCallback
			if cbLimit == 0 { // reset cbLimit in other cases
				return nil, fmt.Errorf("callback limit")
			}
			cbLimit--
			wr := exprsAddMap[exprsAdd[matchId-3]]
			logger.Debug("write callback result")
			err := connector.Write([]byte(wr))
			if err != nil {
				return nil, fmt.Errorf("write error %w", err)
			}
		} else {
			panic("unknown option")
		}
	}

	res := buffer.Bytes()
	if cli.resultCB != nil {
		cbRes, err := cli.resultCB(CBRaw, res)
		if err != nil {
			return nil, err
		}
		res = cbRes
	}
	fondErr := checkError(cli.error, res)
	if fondErr != nil {
		fondErr = command.ErrorHandler(fondErr)
	}

	strippedRes, err := terminal.ParseDropLastReturn(res)
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
	data = bytes.ReplaceAll(data, []byte("\r"), nil)
	return data
}
