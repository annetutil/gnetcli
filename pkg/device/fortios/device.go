/*
Package fortios implements FortiOS CLI using genericcli.
*/
package fortios

import (
	"fmt"
	"regexp"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	questionExpression = `(?P<question>[dD]o you want to continue\? \(y/n\))\s{0,1}$`
	promptExpression   = `(?P<prompt>[\w\-()~ ]+)[#$]\s$`
	errorExpression    = `(` +
		`Command fail\.?` +
		`|Unknown action` +
		`|Node not found` +
		`|Entry not found` +
		`|Parse error` +
		`|Incomplete command` +
		`|Ambiguous command` +
		`|Permission denied` +
		`|Invalid value` +
		`|Input is not a valid` +
		`|failover status: unset` +
		`|Unknown phase2` +
		`)`
	pagerExpression = `--\s?[Mm]ore\s?--`
)

var autoCommands = []cmd.Cmd{
	cmd.NewCmd("config system console", cmd.WithErrorIgnore()),
	cmd.NewCmd("set output standard", cmd.WithErrorIgnore()),
	cmd.NewCmd("end", cmd.WithErrorIgnore()),
}

func NewDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast200().FromPattern(promptExpression),
		expr.NewSimpleExprLast200().FromPattern(errorExpression),
		genericcli.WithPager(
			expr.NewSimpleExprLast200().FromPattern(pagerExpression)),
		genericcli.WithQuestion(
			expr.NewSimpleExprLast200().FromPattern(questionExpression)),
		genericcli.WithAutoCommands(autoCommands),
		genericcli.WithEchoExprFn(func(c cmd.Cmd) expr.Expr {
			return expr.NewSimpleExpr().FromPattern(fmt.Sprintf(`%s\r\r\n`, regexp.QuoteMeta(string(c.Value()))))
		}),
		genericcli.WithTerminalParams(400, 0),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
