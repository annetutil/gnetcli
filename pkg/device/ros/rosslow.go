/*
Package ros also provides a "slow" RouterOS variant for weak CPE (old RB2011 and
similar) that tear down the session right after command submit even at the
standard write delay. It is identical to NewDevice except for a larger
per-keystroke write delay. Kept as a separate device type so the heavy delay
applies only to devices explicitly routed to it, not to healthy RouterOS on the
standard profile.
*/
package ros

import (
	"time"

	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

// slowWriteDelay is the per-keystroke throttle for weak RouterOS CPE. The
// standard profile uses 12ms; these devices need more headroom between
// characters to avoid dropping the session mid-redraw.
const slowWriteDelay = 50 * time.Millisecond

// NewSlowDevice builds a RouterOS genericcli device tuned for weak CPE.
func NewSlowDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast(65536).FromPattern(promptExpression),
		expr.NewSimpleExprLast(2500).FromPattern(errorExpression),
		genericcli.WithQuestion(
			expr.NewSimpleExprLast200().FromPattern(questionExpression),
		),
		genericcli.WithPager(expr.NewSimpleExprLast200().FromPattern(pagerExpression)),
		genericcli.WithResultCB(dataCallback),
		genericcli.WithCredentialInterceptor(credentialLoginModifier),
		genericcli.WithTerminalParams(80, 4098),
		genericcli.WithWriteDelay(slowWriteDelay),
		genericcli.WithWriteNewLine([]byte("\r\n")),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
