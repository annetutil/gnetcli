/*
Package sitonica implements IPN CLI using genericcli.
Currently, it is a full copy of the h3c device implementation. A separate
device is introduced because their paths and features are expected to diverge
in the future.
*/
package sitonica

import (
	"fmt"
	"regexp"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	questionExpression = `\n(?P<question>.*Continue\? \[Y/N\]:)$`
	promptExpression   = `(\r\r?\n|^|\x00)(?P<prompt>((\(M\))?[<\[][\w\-/]+[>\]]|\[[~*]?[/\w\-.:]+\]))$`
	errorExpression    = `(` +
		`(\^\r\n)?( % )?Error:(?P<error>.+) at '\^' position\.` +
		`|\r\n % (Unrecognized command|Too many parameters|Incomplete command) found at '\^' position\.` +
		`)`
	pagerExpression = `(?P<store>(\r\n|\n))?  ---- More ----$`
)

var autoCommands = []cmd.Cmd{
	cmd.NewCmd("screen-length disable", cmd.WithErrorIgnore()),
	cmd.NewCmd("terminal mmi-mode enable", cmd.WithErrorIgnore()),
}

func NewDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast200().FromPattern(promptExpression),
		expr.NewSimpleExprLast200().FromPattern(errorExpression),
		genericcli.WithPager(
			expr.NewSimpleExprLast200().FromPattern(pagerExpression),
		),
		genericcli.WithAutoCommands(autoCommands),
		genericcli.WithQuestion(
			expr.NewSimpleExprLast200().FromPattern(questionExpression),
		),
		genericcli.WithSFTPEnabled(),
		genericcli.WithTerminalParams(400, 0),
		// sitonica adds extra \r in the echo
		genericcli.WithEchoExprFn(func(c cmd.Cmd) expr.Expr {
			return expr.NewSimpleExpr().FromPattern(fmt.Sprintf(`%s\r*\n`, regexp.QuoteMeta(string(c.Value()))))
		}),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
