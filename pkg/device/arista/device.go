package arista

import (
	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	promptExpression       = `(\r\n|^)[^\n]*(?P<prompt>.+)(\(config.*\))?[>#]$`
	errorExpression        = `^%%?\s.*`
	excludeErrorExpression = `^% Writing.*`
	pagerExpression        = `\x1b\[7m --More-- \x1b\[27m\x1b\[K`
)

var autoCommands = []cmd.Cmd{
	cmd.NewCmd("terminal length 0", cmd.WithErrorIgnore()),
	cmd.NewCmd("enable"),
}

func NewDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast200().FromPattern(promptExpression),
		expr.NewSimpleExprLast200().FromPattern(errorExpression),
		genericcli.WithPager(
			expr.NewSimpleExprLast200().FromPattern(pagerExpression),
		),
		genericcli.WithQuestion(expr.NewSimpleExprLast200().FromPattern("Password:")),
		genericcli.WithAnswers([]cmd.Answer{cmd.NewAnswer("Password:", "\n\n", false)}),
		genericcli.WithAutoCommands(autoCommands),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
