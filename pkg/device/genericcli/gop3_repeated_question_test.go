package genericcli

// Tests for GOP-3: Repeated Question Detection in Execution Loop.
// See docs/gop/gop3.md for the full proposal.

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	gmock "github.com/annetutil/gnetcli/pkg/testutils/mock"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

func TestRepeatedQuestionAborts(t *testing.T) {
	logger := zap.Must(zap.NewDevelopmentConfig().Build())

	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("set master-key\n"),
			gmock.SendEcho("set master-key\r\n"),
			gmock.Send("Enter the user password:"),
			gmock.Expect("mypass\n"),
			gmock.Send("Error: Incorrect password.\r\nEnter the user password:"),
			gmock.Expect("mypass\n"),
			gmock.Send("Error: Incorrect password.\r\nEnter the user password:"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	cmds := []cmd.Cmd{
		cmd.NewCmd("set master-key", cmd.WithAddAnswers(
			cmd.NewAnswerWithNL("Enter the user password:", "mypass"),
		)),
	}

	_, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		dev := newDevice(fullQuestion, connector, logger)
		return &dev
	}, actions, cmds, logger)

	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.Error(t, resErr)
	var qErr *cmd.QuestionExceptionRepeated
	require.ErrorAs(t, resErr, &qErr)
}

func TestDifferentQuestionsDoNotTriggerLimit(t *testing.T) {
	logger := zap.Must(zap.NewDevelopmentConfig().Build())

	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("change-password\n"),
			gmock.SendEcho("change-password\r\n"),
			gmock.Send("Enter new password:"),
			gmock.Expect("newpass\n"),
			gmock.Send("Confirm new password:"),
			gmock.Expect("newpass\n"),
			gmock.Send("result ok\r\n"),
			gmock.Send("<device>"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	cmds := []cmd.Cmd{
		cmd.NewCmd("change-password", cmd.WithAddAnswers(
			cmd.NewAnswerWithNL("Enter new password:", "newpass"),
			cmd.NewAnswerWithNL("Confirm new password:", "newpass"),
		)),
	}

	cmdRes, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		dev := newDevice(`(Enter new password:|Confirm new password:)$`, connector, logger)
		return &dev
	}, actions, cmds, logger)

	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.NoError(t, resErr)
	require.Len(t, cmdRes, 1)
	require.Equal(t, "result ok", string(cmdRes[0].Output()))
}

func TestSameQuestionTwiceIsAllowed(t *testing.T) {
	logger := zap.Must(zap.NewDevelopmentConfig().Build())

	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("set key\n"),
			gmock.SendEcho("set key\r\n"),
			gmock.Send("Enter password:"),
			gmock.Expect("pass\n"),
			gmock.Send("Enter password:"),
			gmock.Expect("pass\n"),
			gmock.Send("key set ok\r\n"),
			gmock.Send("<device>"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	cmds := []cmd.Cmd{
		cmd.NewCmd("set key", cmd.WithAddAnswers(
			cmd.NewAnswerWithNL("Enter password:", "pass"),
		)),
	}

	cmdRes, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		dev := newDevice(`Enter password:$`, connector, logger)
		return &dev
	}, actions, cmds, logger)

	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.NoError(t, resErr)
	require.Len(t, cmdRes, 1)
	require.Equal(t, "key set ok", string(cmdRes[0].Output()))
}
