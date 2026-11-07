/*
Package fsos implements a gnetcli CLI device for FS.com switches running FSOS.

FSOS presents an IOS-like CLI (">" user mode, "#" enable, "% Invalid input
detected at '^' marker." style errors) but does not support the usual
terminal/init commands (terminal length/width/monitor) — sending them returns
"% Unknown command." and breaks the session. This profile therefore sends no
auto commands, reads from user mode, tolerates the command echo terminated by
an extra CR ("\r\r\n"), and answers the pager reactively since FSOS has no
pager-disable command.
*/
package fsos

import (
	"fmt"
	"regexp"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	promptExpression = `(\r\n|\n|\r|^)[\w\-.:/]+[>#]\s*$`
	errorExpression  = `(\r|\n|^)(% Unknown command\.|% Invalid input detected at '\^' marker\.|% Ambiguous command:.*|% Incomplete command\.|% Unrecognized host or address.*|% Access denied)`
	pagerExpression  = `\r?\n? *--More-- *$`
)

func echoExpr(c cmd.Cmd) expr.Expr {
	return expr.NewSimpleExpr().FromPattern(fmt.Sprintf(`%s\r*\n`, regexp.QuoteMeta(string(c.Value()))))
}

// NewDevice creates a gnetcli device for FS.com FSOS switches.
func NewDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast200().FromPattern(promptExpression),
		expr.NewSimpleExprLast200().FromPattern(errorExpression),
		genericcli.WithPager(expr.NewSimpleExprLast200().FromPattern(pagerExpression)),
		genericcli.WithEchoExprFn(echoExpr),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
