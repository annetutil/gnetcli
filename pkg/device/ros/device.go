/*
Package ros implements RouterOS CLI using genericcli.
*/
package ros

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"time"

	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	// line may be like this "\r\n\r\r\r\r[admin@mk-rb3011-test] >   (~1000 space)   \r[admin@mk-rb3011-test] > "
	hiddenPrompt       = `(?P<hidden>[\[<](\S*@)?[^\]]+\]\s+(\/[\/\w\s-]+)?(<SAFE)?>\s+)?`
	visiblePrompt      = `[\[<]((?P<login>[^@\r\n]*)@)?(?P<hostname>[^\]\r\n]+)\]\s+(?P<cfg_path>\/[\/\w\s-]+)?(<(?P<safe_mode>SAFE))?>[^\n]*$`
	promptExpression   = `(?P<store>(\r\n|\n|\r|^))` + visiblePrompt
	errorExpression    = `(\r|^)(bad command name.*\(line \d+ column \d+\).*($|\r)|syntax error.*\(line \d+ column \d+\).*$|\[(?P<question>Safe mode released by another user)\]|expected end of command \(line \d+ column \d+\)|expected command name \(line \d+ column \d+\)|failure: duplicate address|failure: item with this name already exists)`
	questionExpression = `((?P<question>.+\?)\s*\[y/N\]: \r\n$|(?P<question>\x1b\[c)|\rnumbers: )`
	pagerExpression    = `-- \[Q quit\|D dump\|(right\|)?(up\|)?down\]$`
)

var promptHack = regexp.MustCompile(`\r+\[(\S+)@(\S+)\]\s{1,2}(\/[\/\w\s-]+)?(<SAFE)?>  {100,}\r\[(\S+)@(\S+)\]\s{1,2}(\/[\/\w\s-]+)?(<SAFE)?> \r\[(\S+)@(\S+)\]\s{1,2}(\/[\/\w\s-]+)?(<SAFE)?> \r\n\r+\[(\S+)@(\S+)\]\s{1,2}(\/[\/\w\s-]+)?(<SAFE)?>  {100,}\r`)

func dataCallback(cbType genericcli.ResultCBType, data []byte) ([]byte, error) {
	// cli returns:
	// new rw="DATA    \r\r\n\r\r\r\rPROMPT space * terminal width \rPROMPT\rPROMPT\r\n\r\r\r\r\rPROMPT space * terminal width \rPROMPT \r\n"
	// try to drop
	if cbType == genericcli.CBRaw {
		if bytes.HasSuffix(data, []byte("                             \r")) {
			data = promptHack.ReplaceAll(data, nil)
		}
		return data, nil
	}
	return data, nil
}

func NewDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(
		// RouterOS pads each line (incl. the prompt) to terminal width and redraws
		// it via \r, so the real prompt can sit far from the tail (e.g. ping) -> a
		// smaller match window misses it. Keep a large one.
		expr.NewSimpleExprLast(65536).FromPattern(promptExpression),
		expr.NewSimpleExprLast(2500).FromPattern(errorExpression),
		genericcli.WithQuestion(
			expr.NewSimpleExprLast200().FromPattern(questionExpression),
		),
		genericcli.WithPager(expr.NewSimpleExprLast200().FromPattern(pagerExpression)),
		genericcli.WithResultCB(dataCallback),
		genericcli.WithCredentialInterceptor(credentialLoginModifier),
		// Narrow PTY width limits per-keystroke redraw padding; tall height disables
		// the pager. Matches the +cte80w4098h login modifier below.
		genericcli.WithTerminalParams(80, 4098),
		// Throttle writes: RouterOS can drop the session on a full-line paste.
		genericcli.WithWriteDelay(12*time.Millisecond),
		genericcli.WithWriteNewLine([]byte("\r\n")),
		genericcli.WithSFTPEnabled(),
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
		username = username + "+cte80w4098h"
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
