/*
Package ros implements RouterOS CLI using genericcli.
*/
package ros

import (
	"context"
	"strings"

	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	// line may be like this "\r\n\r\r\r\r[admin@mk-rb3011-test] >   (~1000 space)   \r[admin@mk-rb3011-test] > "
	hiddenPrompt       = `(\[\S+@\S+\]\s+(\/[\/\w\s-]+)?(<SAFE)?>\s+)?`
	visiblePrompt      = `\[(?P<login>\S+)@(?P<hostname>\S+)\]\s+(?P<cfg_path>\/[\/\w\s-]+)?(<(?P<safe_mode>SAFE))?> $`
	promptExpression   = `(?P<store>(\r\n|\n|\r|^))` + hiddenPrompt + visiblePrompt
	errorExpression    = `(\r|^)(bad command name.*\(line \d+ column \d+\).*$|syntax error.*\(line \d+ column \d+\).*$|\[(?P<question>Safe mode released by another user)\]|expected end of command \(line \d+ column \d+\)|expected command name \(line \d+ column \d+\)|failure: duplicate address)`
	questionExpression = `((?P<question>.+\?)\s*\[y/N\]: \r\n$|(?P<question>\x1b\[c)|\rnumbers: )`
	pagerExpression    = `-- \[Q quit\|D dump\|down\]$`
)

func NewDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast(1500).FromPattern(promptExpression),
		expr.NewSimpleExprLast200().FromPattern(errorExpression),
		genericcli.WithQuestion(
			expr.NewSimpleExprLast200().FromPattern(questionExpression),
		),
		genericcli.WithPager(expr.NewSimpleExprLast200().FromPattern(pagerExpression)),
		genericcli.WithCredentialInterceptor(credentialLoginModifier),
		genericcli.WithWriteNewLine([]byte("\r\n")),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}

func credentialLoginModifier(creds credentials.Credentials) credentials.Credentials {
	return newRosUsernameWrapper(creds)
}

type rosUsernameWrapper struct {
	creds credentials.Credentials
}

func (m rosUsernameWrapper) GetUsername() (string, error) {
	username, err := m.creds.GetUsername()
	if err != nil {
		return "", err
	}
	if !strings.Contains(username, "+") {
		username = username + "+cte999w255h"
	}
	return username, err
}

func (m rosUsernameWrapper) GetPasswords(ctx context.Context) []credentials.Secret {
	return m.creds.GetPasswords(ctx)
}

func (m rosUsernameWrapper) GetPrivateKeys() [][]byte {
	return m.creds.GetPrivateKeys()
}

func (m rosUsernameWrapper) GetPassphrase() credentials.Secret {
	return m.creds.GetPassphrase()
}

func (m rosUsernameWrapper) GetAgentSocket() string {
	return m.creds.GetAgentSocket()
}

func newRosUsernameWrapper(creds credentials.Credentials) rosUsernameWrapper {
	return rosUsernameWrapper{
		creds: creds,
	}
}
