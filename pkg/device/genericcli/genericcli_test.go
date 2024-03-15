package genericcli

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

const (
	fullQuestion    = `(\r\n|^)Are you sure\? \[Y/N\]:$`
	croppedQuestion = `\[Y/N\]:$`
)

func newDevice(questionExpression string, connector streamer.Connector, logger *zap.Logger) GenericDevice {
	promptExpression := `(\r\n|^)(?P<prompt>(<\w+>))$`
	errorExpression := `(\r\n|^)Error: .+$`
	cli := MakeGenericCLI(
		expr.NewSimpleExprLast200(promptExpression),
		expr.NewSimpleExprLast200(errorExpression),
		WithQuestion(
			expr.NewSimpleExprLast200(questionExpression),
		),
	)
	return MakeGenericDevice(cli, connector, WithDevLogger(logger))
}

func TestQuestionWithoutAnswer(t *testing.T) {
	logConfig := zap.NewDevelopmentConfig()
	logger := zap.Must(logConfig.Build())

	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("ack\n"),
			gmock.SendEcho("ack\r\n"),
			gmock.Send("Are you sure? [Y/N]:"),
			gmock.Expect("Y\n"),
			gmock.Send("<device>"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	expErr := device.ThrowQuestionException([]byte("Are you sure? [Y/N]:"))
	cmdRes, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		dev := newDevice(fullQuestion, connector, logger)
		return &dev
	}, actions, []cmd.Cmd{cmd.NewCmd("ack")}, logger)

	require.ErrorAs(t, resErr, &expErr)
	require.Empty(t, cmdRes)
	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.NoError(t, err)
}

func TestQuestionCmdOverlap(t *testing.T) {
	logger := zap.Must(zap.NewDevelopmentConfig().Build())
	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("ack\n"),
			gmock.SendEcho("ack\r\n"),
			gmock.Send("Are you sure? [Y/N]:"),
			gmock.Expect("Y\n"),
			gmock.Send("<device>"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	cmds := []cmd.Cmd{
		cmd.NewCmd("ack", cmd.WithAnswers(cmd.NewAnswer("/Are.+\\? \\[Y/N\\]:/", "Y"))),
	}

	cmdRes, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		dev := newDevice(fullQuestion, connector, logger)
		return &dev
	}, actions, cmds, logger)
	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.NoError(t, resErr)
	require.Equal(t, cmdRes, []cmd.CmdRes{cmd.NewCmdRes(nil)})
}

func TestQuestionWithAnswer(t *testing.T) {
	logConfig := zap.NewDevelopmentConfig()
	logger := zap.Must(logConfig.Build())

	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("ack\n"),
			gmock.SendEcho("ack\r\n"),
			gmock.Send("Are you sure? [Y/N]:"),
			gmock.Expect("Y\n"),
			gmock.Send("<device>"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	cmds := []cmd.Cmd{
		cmd.NewCmd("ack", cmd.WithAnswers(cmd.NewAnswer("Are you sure? [Y/N]:", "Y"))),
	}

	cmdRes, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		dev := newDevice(fullQuestion, connector, logger)
		return &dev
	}, actions, cmds, logger)
	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.NoError(t, resErr)
	require.Equal(t, cmdRes, []cmd.CmdRes{cmd.NewCmdRes(nil)})
}

func TestMultipleQuestionsWithAnswer(t *testing.T) {
	logConfig := zap.NewDevelopmentConfig()
	logger := zap.Must(logConfig.Build())

	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("ack\n"),
			gmock.SendEcho("ack\r\n"),
			gmock.Send("Are you sure? [Y/N]:"),
			gmock.Expect("Y\n"),
			gmock.Send("Are you really sure? [Y/N]:"),
			gmock.Expect("Y\n"),
			gmock.Send("<device>"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	cmds := []cmd.Cmd{
		cmd.NewCmd("ack", cmd.WithAnswers(
			cmd.NewAnswer("Are you sure? [Y/N]:", "Y"),
			cmd.NewAnswer("Are you really sure? [Y/N]:", "Y"),
		)),
	}

	cmdRes, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		dev := newDevice(fullQuestion, connector, logger)
		return &dev
	}, actions, cmds, logger)
	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.NoError(t, resErr)
	require.Equal(t, cmdRes, []cmd.CmdRes{cmd.NewCmdRes(nil)})
}

func TestQuestionCmdAnswerDontMatchDeviceQuestion(t *testing.T) {
	logger := zap.Must(zap.NewDevelopmentConfig().Build())
	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("ack\n"),
			gmock.SendEcho("ack\r\n"),
			gmock.Send("Are you sure? [Y/N]:"),
			gmock.Expect("Y\n"),
			gmock.Send("<device>"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	cmds := []cmd.Cmd{
		cmd.NewCmd("ack", cmd.WithAnswers(cmd.NewAnswer("/Are.+\\? \\[Y/N\\]:/", "Y"))),
	}

	cmdRes, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		dev := newDevice(croppedQuestion, connector, logger)
		return &dev
	}, actions, cmds, logger)
	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.NoError(t, resErr)
	require.Equal(t, cmdRes, []cmd.CmdRes{cmd.NewCmdRes(nil)})
}
