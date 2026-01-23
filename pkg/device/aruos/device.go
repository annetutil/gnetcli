package aruos

import (
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

const (
	promptExpression        = `(\r\n)?(?P<prompt>[\w\-():]+) ?# $`
	errorExpression         = `% (Parse error|Incomplete command)`
	passwordExpression      = `.*Password: $`
	loginExpression         = `.*User: $`
	passwordErrorExpression = `.*Login incorrect, reason code \d(\r\n)?$`
)

func NewDevice(connector streamer.Connector, opts ...genericcli.GenericDeviceOption) genericcli.GenericDevice {
	cli := genericcli.MakeGenericCLI(expr.NewSimpleExprLast200().FromPattern(promptExpression),
		expr.NewSimpleExprLast200().FromPattern(errorExpression),
		genericcli.WithLoginExprs(expr.NewSimpleExprLast200().FromPattern(loginExpression),
			expr.NewSimpleExprLast200().FromPattern(passwordExpression),
			expr.NewSimpleExprLast200().FromPattern(passwordErrorExpression)),
	)

	return genericcli.MakeGenericDevice(cli, connector, opts...)
}
