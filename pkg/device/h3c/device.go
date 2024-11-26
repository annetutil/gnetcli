/*
Package h3c implements huawei CLI using genericcli.
It is a copy of huawei device with small changes
*/
package h3c

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
	promptExpression   = `(\r\n|^)(?P<prompt>(<[\w\-]+>|\[[~*]?[/\w\-.:]+\]))$`
	errorExpression    = `(` +
		`\^\r\n( % )?Error: (?P<error>.+) at '\^' position\.` +
		// check expr bellow on h3c
		`|\ +\^\nError(?:\[\d+\])?:\s*(?P<msg>.*?) found at '\^' position.` +
		`|^Error:\s*(?P<msg>(No|You do not have) permission.*)` +
		`|Error(?:\[\d+\])?:\s*(?P<msg>.+?)` +
		`)`
	pagerExpression = `(?P<store>(\r\n|\n))?  ---- More ----$`
)

var autoCommands = []cmd.Cmd{
	cmd.NewCmd("screen-length disable", cmd.WithErrorIgnore()),
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
		// h3c adds extra \r in the echo
		genericcli.WithEchoExprFn(func(c cmd.Cmd) expr.Expr {
			return expr.NewSimpleExpr().FromPattern(fmt.Sprintf(`%s\r*\n`, regexp.QuoteMeta(string(c.Value()))))
		}),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
