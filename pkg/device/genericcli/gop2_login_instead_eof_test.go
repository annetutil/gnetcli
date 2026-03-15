package genericcli

// Tests for GOP-2: Login Expression Detection in Execution Loop for Console Streamers.
// See docs/gop/gop2.md for the full proposal.

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	gmock "github.com/annetutil/gnetcli/pkg/testutils/mock"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

type connectorLoginInsteadEOF struct {
	streamer.Connector
}

func (c *connectorLoginInsteadEOF) HasFeature(feature streamer.Const) bool {
	if feature == streamer.LoginInsteadEOF {
		return true
	}
	return c.Connector.HasFeature(feature)
}

func newDeviceWithLogin(connector streamer.Connector, logger *zap.Logger) GenericDevice {
	promptExpression := `(\r\n|^)(?P<prompt>(<\w+>))$`
	errorExpression := `(\r\n|^)Error: .+$`
	loginExpression := `.*Username:$`
	passwordExpression := `.*Password:$`
	passwordErrorExpression := `.*Authentication failed$`
	cli := MakeGenericCLI(
		expr.NewSimpleExprLast200().FromPattern(promptExpression),
		expr.NewSimpleExprLast200().FromPattern(errorExpression),
		WithLoginExprs(
			expr.NewSimpleExprLast200().FromPattern(loginExpression),
			expr.NewSimpleExprLast200().FromPattern(passwordExpression),
			expr.NewSimpleExprLast200().FromPattern(passwordErrorExpression),
		),
	)
	return MakeGenericDevice(cli, connector, WithDevLogger(logger))
}

func TestExitCmdLoginPromptOnConsole(t *testing.T) {
	logger := zap.Must(zap.NewDevelopmentConfig().Build())

	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("exit\n"),
			gmock.SendEcho("exit\r\n"),
			gmock.Send("Username:"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	_, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		wrapped := &connectorLoginInsteadEOF{Connector: connector}
		dev := newDeviceWithLogin(wrapped, logger)
		return &dev
	}, actions, []cmd.Cmd{cmd.NewCmd("exit")}, logger)

	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.Error(t, resErr)
	var eofErr *streamer.EOFException
	require.ErrorAs(t, resErr, &eofErr)
}

func TestExitCmdLoginPromptOnSSH(t *testing.T) {
	logger := zap.Must(zap.NewDevelopmentConfig().Build())

	// On SSH, exit causes the server to close the connection (EOF),
	// not a login prompt. The login expression should not be in the
	// execution loop, so the SSH EOF is returned directly.
	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("exit\n"),
			gmock.SendEcho("exit\r\n"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	_, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		dev := newDeviceWithLogin(connector, logger)
		return &dev
	}, actions, []cmd.Cmd{cmd.NewCmd("exit")}, logger)

	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.Error(t, resErr)
	var eofErr2 *streamer.EOFException
	require.ErrorAs(t, resErr, &eofErr2)
}

func TestCmdThenExitOnConsole(t *testing.T) {
	logger := zap.Must(zap.NewDevelopmentConfig().Build())

	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("show version\n"),
			gmock.SendEcho("show version\r\n"),
			gmock.Send("Software version 1.0\r\n"),
			gmock.Send("<device>"),
			gmock.Expect("exit\n"),
			gmock.SendEcho("exit\r\n"),
			gmock.Send("Username:"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	cmdRes, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		wrapped := &connectorLoginInsteadEOF{Connector: connector}
		dev := newDeviceWithLogin(wrapped, logger)
		return &dev
	}, actions, []cmd.Cmd{cmd.NewCmd("show version"), cmd.NewCmd("exit")}, logger)

	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.Error(t, resErr)
	var eofErr3 *streamer.EOFException
	require.ErrorAs(t, resErr, &eofErr3)
	require.Len(t, cmdRes, 1)
	require.Equal(t, "Software version 1.0", string(cmdRes[0].Output()))
}
