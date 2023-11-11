/*
Package nxos implements Cisco Nexus CLI using genericcli.
*/
package nxos

import (
	"fmt"
	"regexp"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

// Some unusual behavior here.
// For example 'n9k-test \r\n\rn9k-test#' - extra \r after typical \r\n.

const (
	promptExpression = `(\r\n\r)?(?P<prompt>[\w\-()]+)# $`
	errorExpression  = `% (Invalid|Incomplete) .+ '\^' marker.`
	pagerExpression  = `\x1b\[7m--More--\x1b\[(27)?m`
)

var autoCommands = []cmd.Cmd{
	cmd.NewCmd("terminal length 0", cmd.WithErrorIgnore()),
}

func NewDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(expr.NewSimpleExprLast200(promptExpression), expr.NewSimpleExprLast200(errorExpression),
		genericcli.WithPager(
			expr.NewSimpleExprLast200(pagerExpression)),
		genericcli.WithEchoExprFn(func(c cmd.Cmd) expr.Expr {
			return expr.NewSimpleExpr(fmt.Sprintf(`%s\r\r\n`, regexp.QuoteMeta(string(c.Value()))))
		}),
		genericcli.WithAutoCommands(autoCommands),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
