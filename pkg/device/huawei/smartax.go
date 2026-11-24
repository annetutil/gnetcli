/*
Package huawei — SmartAX / MA5800 GPON OLT variant.

MA5800 OLTs share Huawei's error/login/question grammar but use a bare
"HOST>" / "HOST#" / "HOST(config)#" prompt, reject VRP session-setup commands
(e.g. "screen-length 0 temporary"), and drive an interactive input assistant:
after a command they may print a "{ <cr>|... }:" parameter menu that must be
confirmed with a CR, and they submit lines with CR rather than LF.
*/
package huawei

import (
	"fmt"
	"regexp"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	smartaxPromptExpression = `(\r\n|^)(?P<prompt>[/\w\-.:]+(\([\w\-.:/]+\))?[>#])$`
	smartaxPagerExpression  = `(?P<store>(\r\n|\n))?\s*---- More.*----\s*$`
	// Parameter menu that offers "<cr>" => the command is complete (Enter runs it).
	smartaxCrMenuExpression = `\{[^\r\n]*<cr>[^\r\n]*\}:\s*$`
	// Prompt redrawn with the command still typed and a trailing space (an async
	// warning aborted the menu) => re-run it with Enter.
	smartaxRedrawExpression   = `(\r\n|^)[/\w\-.:]+(\([\w\-.:/]+\))?[>#][^\r\n]+ $`
	smartaxQuestionExpression = `(?P<question>.*(privilege level|Continue)\s?\?\s?\[Y/N\]:?$|` + smartaxCrMenuExpression + `|` + smartaxRedrawExpression + `)`
)

// NewSmartAXDevice builds a gnetcli device for Huawei SmartAX / MA5800 OLTs.
func NewSmartAXDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(
		expr.NewSimpleExprLast200().FromPattern(smartaxPromptExpression),
		expr.NewSimpleExprLast200().FromPattern(errorExpression),
		genericcli.WithLoginExprs(
			expr.NewSimpleExprLast200().FromPattern(loginExpression),
			expr.NewSimpleExprLast200().FromPattern(passwordExpression),
			expr.NewSimpleExprLast200().FromPattern(passwordErrorExpression),
		),
		genericcli.WithPager(expr.NewSimpleExprLast200().FromPattern(smartaxPagerExpression)),
		genericcli.WithQuestion(expr.NewSimpleExprLast200().FromPattern(smartaxQuestionExpression)),
		// Confirm the "{ <cr>|... }:" menu / line-redraw with a bare CR. Answer.Match
		// returns the answer verbatim (no newline appended), so the answer is the CR.
		genericcli.WithAnswers([]cmd.Answer{
			cmd.NewAnswer("/"+smartaxCrMenuExpression+"/", "\r", true),
			cmd.NewAnswer("/"+smartaxRedrawExpression+"/", "\r", true),
		}),
		// Flush the async "default password" warning after login with one empty line.
		genericcli.WithAutoCommands([]cmd.Cmd{cmd.NewCmd("", cmd.WithErrorIgnore())}),
		genericcli.WithSFTPEnabled(),
		genericcli.WithTerminalParams(400, 0),
		// The OLT submits lines with CR, not LF (a bare LF only pops the menu).
		genericcli.WithWriteNewLine([]byte("\r")),
		genericcli.WithEchoExprFn(func(command cmd.Cmd) expr.Expr {
			// The input assistant may append a trailing space to the echoed command.
			return expr.NewSimpleExpr().FromPattern(fmt.Sprintf(`%s\s*(\r\n|\n)`, regexp.QuoteMeta(string(command.Value()))))
		}),
	)
	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
