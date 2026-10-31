/*
ciscoxr.go implements a Cisco IOS-XR CLI profile using genericcli.

IOS-XR differs from classic IOS/Catalyst:
  - The exec prompt is "RP/0/RSP0/CPU0:host#" (route-processor path + ":" +
    hostname), with config/admin submodes like "...host(config)#",
    "...host(config-if)#", "...host(admin)#".
  - There is no privileged ("enable") mode — the session is already privileged,
    so sending "enable" (as the IOS profile does) yields "% Invalid input" and
    leaves the exec loop waiting on a Password: answer that never comes,
    desyncing the session.

This profile keeps the IOS error/login/pager handling, drops "enable", and uses
an XR-aware prompt. Kept separate from NewDevice so the Catalyst path is
untouched.
*/
package cisco

import (
	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

// xrPromptExpression matches "RP/0/RSP0/CPU0:host#", user mode "...host>", and a
// single optional "(submode)" for config/admin modes.
const xrPromptExpression = `(?P<prompt>[\w\-.:/]+(\([^)]+\))?)(>|#)$`

var xrAutoCommands = []cmd.Cmd{
	cmd.NewCmd("terminal length 0", cmd.WithErrorIgnore()),
	cmd.NewCmd("terminal width 0", cmd.WithErrorIgnore()),
	cmd.NewCmd("terminal exec prompt no-timestamp", cmd.WithErrorIgnore()),
	cmd.NewCmd("terminal monitor disable", cmd.WithErrorIgnore()),
}

// NewXRDevice builds a genericcli device for Cisco IOS-XR over ssh/telnet.
func NewXRDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast200().FromPattern(xrPromptExpression),
		expr.NewSimpleExprLast200().FromPattern(errorExpression),
		genericcli.WithLoginExprs(
			expr.NewSimpleExprLast200().FromPattern(loginExpression),
			expr.NewSimpleExprLast200().FromPattern(passwordExpression),
			expr.NewSimpleExprLast200().FromPattern(passwordErrorExpression)),
		genericcli.WithPager(
			expr.NewSimpleExprLast200().FromPattern(pagerExpression)),
		genericcli.WithQuestion(
			expr.NewSimpleExprLast200().FromPattern(questionExpression)),
		genericcli.WithAutoCommands(xrAutoCommands),
		genericcli.WithTerminalParams(400, 0),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
