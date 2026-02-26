/*
Package juniper implements juniper CLI using genericcli.
*/
package juniper

import (
	"fmt"
	"regexp"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	promptExpression = `(\r\n({master}\[edit\]|{master}|{master:\d}|\[edit\]))?\r\n(?P<prompt>[\w\-.]+@[\w\-.]+[>#]) $`
	errorExpression  = `(\n|^)(syntax error\.|syntax error, expecting <command>.|unknown command\.|error: (configuration check-out failed|configuration database modified|commit failed: \([\w ]+\))|configure exclusive error: .+)\r\n`
	pagerExpression  = `\n---\(more( \d+%)?\)---$`
)

var autoCommands = []cmd.Cmd{
	cmd.NewCmd("set cli complete-on-space off"),
	cmd.NewCmd("set cli screen-length 0"),
	cmd.NewCmd("set cli screen-width 1024"),
	cmd.NewCmd("set cli terminal ansi"),
}

func NewDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast200().FromPattern(promptExpression),
		expr.NewSimpleExprLast200().FromPattern(errorExpression),
		genericcli.WithPager(
			expr.NewSimpleExprLast200().FromPattern(pagerExpression),
		),
		genericcli.WithAutoCommands(autoCommands),
		genericcli.WithSFTPEnabled(),
		genericcli.WithEchoExprFn(func(c cmd.Cmd) expr.Expr {
			return expr.NewSimpleExpr().FromPattern(fmt.Sprintf(`%s *\r\n`, regexp.QuoteMeta(string(c.Value()))))
		}),
		genericcli.WithTerminalParams(400, 0),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
