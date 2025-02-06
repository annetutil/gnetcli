/*
Package huawei implements huawei CLI using genericcli.
*/
package huawei

import (
	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	loginExpression    = `.*Username:$`
	questionExpression = `(?P<question>.*Continue\? \[Y/N\]:)$`
	promptExpression   = `(\r\n|^)(?P<prompt>(<[\w\-]+>|\[[~*]?[/\w\-.:]+\]))$`
	errorExpression    = `(` +
		`\^\r\nError: (?P<error>.+) at '\^' position\.` +
		`|Error: You do not have permission to run the command or the command is incomplete` +
		`|\ +\^\nError(?:\[\d+\])?:\s*(?P<msg>.*?) found at '\^' position.` +
		`|^Error:\s*(?P<msg>(No|You do not have) permission.*)` +
		`|Error(?:\[\d+\])?:\s*(?P<msg>.+?)` +
		`)`
	passwordExpression      = `(\r\n|^)Password:$`
	passwordErrorExpression = `.*Error: Username or password error\.\r\n$|.*Authentication fail(\x00\r\n)?$|Error: The password is invalid.\r\n$`
	pagerExpression         = `(?P<store>(\r\n|\n))?  ---- More ----$`
)

var autoCommands = []cmd.Cmd{
	cmd.NewCmd("screen-length 0 temporary", cmd.WithErrorIgnore()),
	cmd.NewCmd("terminal echo-mode line", cmd.WithErrorIgnore()),
}

func NewDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast200().FromPattern(promptExpression),
		expr.NewSimpleExprLast200().FromPattern(errorExpression),
		genericcli.WithLoginExprs(
			expr.NewSimpleExprLast200().FromPattern(loginExpression),
			expr.NewSimpleExprLast200().FromPattern(passwordExpression),
			expr.NewSimpleExprLast200().FromPattern(passwordErrorExpression),
		),
		genericcli.WithPager(
			expr.NewSimpleExprLast200().FromPattern(pagerExpression),
		),
		genericcli.WithAutoCommands(autoCommands),
		genericcli.WithQuestion(
			expr.NewSimpleExprLast200().FromPattern(questionExpression),
		),
		genericcli.WithSFTPEnabled(),
		genericcli.WithTerminalParams(400, 0),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
