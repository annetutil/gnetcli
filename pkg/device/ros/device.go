/*
Package ros implements RouterOS CLI using genericcli.
*/
package ros

import (
	"strings"

	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	// line may be like this "\r\n\r\r\r\r[admin@mk-rb3011-test] >   (~1000 space)   \r[admin@mk-rb3011-test] > "
	hiddenPrompt       = `((\r\n|\r+|^)\[\S+@\S+\]\s+(\/[\/\w\s-]+)?(<SAFE)?>\s+)?`
	visiblePrompt      = `(\r\n|\r|^)\[(?P<login>\S+)@(?P<hostname>\S+)\]\s+(?P<cfg_path>\/[\/\w\s-]+)?(<(?P<safe_mode>SAFE))?> $`
	promptExpression   = hiddenPrompt + visiblePrompt
	errorExpression    = `(^bad command name.*\(line \d+ column \d+\).*$|^syntax error.*\(line \d+ column \d+\).*$|\[(?P<question>Safe mode released by another user)\])`
	questionExpression = `((?P<question>.+\?)\s*\[y/N\]:$|(?P<question>\x1b\[c))`
	pagerExpression    = `-- \[Q quit\|D dump\|down\]$`
)

func NewDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast(promptExpression, 1500),
		expr.NewSimpleExprLast200(errorExpression),
		genericcli.WithQuestion(
			expr.NewSimpleExprLast200(questionExpression),
		),
		genericcli.WithPager(expr.NewSimpleExprLast200(pagerExpression)),
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

func (m rosUsernameWrapper) GetPasswords() []credentials.Secret {
	return m.creds.GetPasswords()
}

func (m rosUsernameWrapper) GetPrivateKey() []byte {
	return m.creds.GetPrivateKey()
}

func (m rosUsernameWrapper) GetPassphrase() credentials.Secret {
	return m.creds.GetPassphrase()
}

func (m rosUsernameWrapper) AgentEnabled() bool {
	return m.creds.AgentEnabled()
}

func newRosUsernameWrapper(creds credentials.Credentials) rosUsernameWrapper {
	return rosUsernameWrapper{
		creds: creds,
	}
}
