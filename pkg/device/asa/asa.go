/*
Package cisco implements Cisco ASA CLI using genericcli.
*/
package ciscoasa

import (
	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	loginExpression    = `.*Username:\s?$`
	questionExpression = `\n(?P<question>.*Continue\? \[Y/N\]:)$`
	promptExpression   = `(?P<prompt>[\w\-.:/_]+(\(conf(ig)?(-[^)]+)*\))?)(>|#)\s*$`
	errorExpression    = `(` +
		`\r\n% Invalid input detected at '\^' marker.\r\n` +
		`|^\r? +\^\n(% )?Invalid [\w ()]+ at '\^' marker\.` +
		`|ERROR: % Invalid input detected at '\^' marker\.` +
		`|ERROR: % Unrecognized command` +
		`|(\s+\^\n)?% Ambiguous command(: +\".+\"+| at .+)` +
		`|\r?% Permission denied for the role` +
		`|\n?% ?Bad (OID|IP address|host name)(%[\ \w,]+)?` +
		`|\r?% This command is not authorized` +
		`|\r?% Failed to commit .+` +
		`|\r?% Specify .+` +
		`|^% Invalid input` +
		`|Permission denied.+\[Errno \d+\] Permission denied` +
		`)`
	passwordExpression      = `.*(?i)password:\s?$`
	passwordErrorExpression = `\n\% Authentication failed(\r\n|\n)`
	pagerExpression         = `<--- More --->`
)

var autoCommands = []cmd.Cmd{
	cmd.NewCmd("terminal no monitor", cmd.WithErrorIgnore()),      // ios, ios-xe
	cmd.NewCmd("terminal monitor disable", cmd.WithErrorIgnore()), // ios xr
	cmd.NewCmd("terminal length 0", cmd.WithErrorIgnore()),
	cmd.NewCmd("terminal width 0", cmd.WithErrorIgnore()),
	cmd.NewCmd("enable", cmd.WithErrorIgnore(), cmd.WithAddAnswers(cmd.NewAnswerWithNL("Password: ", ""))),
}

func NewDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(expr.NewSimpleExprLast200().FromPattern(promptExpression), expr.NewSimpleExprLast200().FromPattern(errorExpression),
		genericcli.WithLoginExprs(
			expr.NewSimpleExprLast200().FromPattern(loginExpression),
			expr.NewSimpleExprLast200().FromPattern(passwordExpression),
			expr.NewSimpleExprLast200().FromPattern(passwordErrorExpression)),
		genericcli.WithPager(
			expr.NewSimpleExprLast200().FromPattern(pagerExpression)),
		genericcli.WithQuestion(
			expr.NewSimpleExprLast200().FromPattern(questionExpression)),
		genericcli.WithAutoCommands(autoCommands),
		genericcli.WithTerminalParams(400, 0),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
