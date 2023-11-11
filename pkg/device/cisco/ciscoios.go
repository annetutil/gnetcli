/*
Package cisco implements Cisco Catalyst CLI using genericcli.
*/
package cisco

import (
	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	loginExpression    = `.*Username:$`
	questionExpression = `\n(?P<question>.*Continue\? \[Y/N\]:)$`
	promptExpression   = `(?P<prompt>[\w\-]+)[>|#]$`
	errorExpression    = `(` +
		`\r\n% Invalid input detected at '\^' marker.\r\n\r\n` +
		`|^\r? +\^\n(% )?Invalid [\w ()]+ at '\^' marker\.` +
		`|(\s+\^\n)?% Ambiguous command(: +\".+\"+| at .+)` +
		`|\r?% Permission denied for the role` +
		`|\n?% ?Bad (OID|IP address or host name%[\ \w,]+)` +
		`|\r?% This command is not authorized` +
		`|\r?% Failed to commit .+` +
		`|^% Invalid input` +
		`|Permission denied.+\[Errno \d+\] Permission denied` +
		`)`
	passwordExpression      = `.*Password:$`
	passwordErrorExpression = `\^\r\n\% Authentication failed\n`
	pagerExpression         = `\r\n --More-- $`
)

var autoCommands = []cmd.Cmd{
	cmd.NewCmd("terminal length 0", cmd.WithErrorIgnore()),
}

func NewDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(expr.NewSimpleExprLast200(promptExpression), expr.NewSimpleExprLast200(errorExpression),
		genericcli.WithLoginExprs(
			expr.NewSimpleExprLast200(loginExpression),
			expr.NewSimpleExprLast200(passwordExpression),
			expr.NewSimpleExprLast200(passwordErrorExpression)),
		genericcli.WithPager(
			expr.NewSimpleExprLast200(pagerExpression)),
		genericcli.WithQuestion(
			expr.NewSimpleExprLast200(questionExpression)),
		genericcli.WithAutoCommands(autoCommands),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
