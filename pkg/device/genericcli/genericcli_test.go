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
		expr.NewSimpleExprLast200().FromPattern(promptExpression),
		expr.NewSimpleExprLast200().FromPattern(errorExpression),
		WithQuestion(
			expr.NewSimpleExprLast200().FromPattern(questionExpression),
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
		cmd.NewCmd("ack", cmd.WithAddAnswers(cmd.NewAnswerWithNL("/Are.+\\? \\[Y/N\\]:/", "Y"))),
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
		cmd.NewCmd("ack", cmd.WithAddAnswers(cmd.NewAnswerWithNL("Are you sure? [Y/N]:", "Y"))),
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
		cmd.NewCmd("ack", cmd.WithAddAnswers(
			cmd.NewAnswerWithNL("Are you sure? [Y/N]:", "Y"),
			cmd.NewAnswerWithNL("Are you really sure? [Y/N]:", "Y"),
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
		cmd.NewCmd("ack", cmd.WithAddAnswers(cmd.NewAnswerWithNL("/Are.+\\? \\[Y/N\\]:/", "Y"))),
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

func TestEscTermInEcho(t *testing.T) {
	logConfig := zap.NewDevelopmentConfig()
	logger := zap.Must(logConfig.Build())

	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("ip community-filter basic TEST index 10 permit 10000:999\n"),
			gmock.SendEcho("ip community-filter basic TEST index 10 permit 10000 \u001b[1D:999\r\n"),
			gmock.Send("olo\r\n"),
			gmock.Send("<device>"),
			gmock.Expect("quit\n"),
			gmock.Send("quit\n"),
			gmock.Send("<device>"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	cmdRes, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		dev := newDevice(fullQuestion, connector, logger)
		return &dev
	}, actions, []cmd.Cmd{cmd.NewCmd("ip community-filter basic TEST index 10 permit 10000:999"), cmd.NewCmd("quit")}, logger)

	require.NoError(t, resErr)
	require.Equal(t, cmdRes, []cmd.CmdRes{cmd.NewCmdRes([]byte("olo")), cmd.NewCmdRes(nil)})
	require.NoError(t, err)
	require.NoError(t, serverErr)
}

func TestEscTermInEchoEmptyCmd(t *testing.T) {
	logConfig := zap.NewDevelopmentConfig()
	logger := zap.Must(logConfig.Build())

	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("ip community-filter basic TEST index 10 permit 10000:999\n"),
			gmock.SendEcho("ip community-filter basic TEST index 10 permit 10000 \u001b[1D:999\r\n"),
			gmock.Send("<device>"),
			gmock.Expect("quit\n"),
			gmock.Send("quit\n"),
			gmock.Send("<device>"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	cmdRes, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		dev := newDevice(fullQuestion, connector, logger)
		return &dev
	}, actions, []cmd.Cmd{cmd.NewCmd("ip community-filter basic TEST index 10 permit 10000:999"), cmd.NewCmd("quit")}, logger)

	require.NoError(t, resErr)
	require.Equal(t, cmdRes, []cmd.CmdRes{cmd.NewCmdRes(nil), cmd.NewCmdRes(nil)})
	require.NoError(t, err)
	require.NoError(t, serverErr)
}

func TestLoginCallback(t *testing.T) {
	logger := zap.Must(zap.NewDevelopmentConfig().Build())
	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>*Mar  1 00:04:21.011: %Login: Someone logged in"),
			gmock.Expect("\n"),
			gmock.Send("<device>"),
			gmock.Expect("test\n"),
			gmock.SendEcho("test\r\n"),
			gmock.Send("test ok\r\n"),
			gmock.Send("<device>"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	cmds := []cmd.Cmd{cmd.NewCmd("test")}

	cmdRes, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		promptExpression := `(\r\n|^)(?P<prompt>(<\w+>))$`
		cli := MakeGenericCLI(
			expr.NewSimpleExprLast200().FromPattern(promptExpression),
			expr.NewSimpleExprLast200().FromPattern(``),
			WithLoginCallbacks([]cmd.ExprCallback{cmd.NewExprCallback(`/\*.+Login: Someone logged in/`, "\n")}),
		)
		dev := MakeGenericDevice(cli, connector, WithDevLogger(logger))
		return &dev
	}, actions, cmds, logger)
	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.NoError(t, resErr)
	require.Equal(t, cmdRes, []cmd.CmdRes{cmd.NewCmdRes([]byte("test ok"))})
}

func TestQuestionWithAnswerNotSendNL(t *testing.T) {
	logConfig := zap.NewDevelopmentConfig()
	logger := zap.Must(logConfig.Build())

	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("ack\n"),
			gmock.SendEcho("ack\r\n"),
			gmock.Send("Are you sure? [Y/N]:"),
			gmock.Expect("Y"),
			gmock.Send("<device>"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	cmds := []cmd.Cmd{
		cmd.NewCmd("ack", cmd.WithAddAnswers(cmd.NewAnswer("Are you sure? [Y/N]:", "Y", true))),
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
func TestPagerPreservesNewline(t *testing.T) {
	logger := zap.Must(zap.NewDevelopmentConfig().Build())
	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("show config\n"),
			gmock.SendEcho("show config\r\n"),
			gmock.Send(" description BG_W451-ObrenovacStocnjak\r\n"),
			gmock.Send(" --More-- "),
			gmock.Expect(" "),
			gmock.Send("\b\b\b\b\b\b\b\b\b\b         \b\b\b\b\b\b\b\b\b\b no switchport\r\n"),
			gmock.Send("<device>"),
			gmock.Close(),
		},
	}

	actions := gmock.ConcatMultipleSlices(dialog)
	cmdRes, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		promptExpression := `(\r\n|^)(?P<prompt>(<\w+>))$`
		pagerExpression := `\r\n --More-- $`
		cli := MakeGenericCLI(
			expr.NewSimpleExprLast200().FromPattern(promptExpression),
			expr.NewSimpleExprLast200().FromPattern(``),
			WithPager(expr.NewSimpleExprLast200().FromPattern(pagerExpression)),
		)
		dev := MakeGenericDevice(cli, connector, WithDevLogger(logger))
		return &dev
	}, actions, []cmd.Cmd{cmd.NewCmd("show config")}, logger)

	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.NoError(t, resErr)
	require.Len(t, cmdRes, 1)

	// Verify that the newline is preserved between lines
	// Note: \r\n is normalized to \n by the terminal parser
	output := string(cmdRes[0].Output())
	require.Contains(t, output, "description BG_W451-ObrenovacStocnjak\n")
	require.Contains(t, output, " no switchport")
	// Ensure they're on separate lines, not merged
	require.NotContains(t, output, "ObrenovacStocnjak no switchport")
}

func TestStripPagerClearingSequence(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
	}{
		{
			name:     "Cisco pager clearing pattern",
			input:    []byte("\b\b\b\b\b\b\b\b\b         \b\b\b\b\b\b\b\b\b no switchport\r\n"),
			expected: []byte(" no switchport\r\n"),
		},
		{
			name:     "No clearing pattern",
			input:    []byte(" no switchport\r\n"),
			expected: []byte(" no switchport\r\n"),
		},
		{
			name:     "Only backspaces (no spaces)",
			input:    []byte("\b\b\b\b\btext"),
			expected: []byte("\b\b\b\b\btext"), // Not a clearing pattern
		},
		{
			name:     "Empty input",
			input:    []byte(""),
			expected: []byte(""),
		},
		{
			name:     "Backspaces and spaces but no trailing backspaces",
			input:    []byte("\b\b\b   text"),
			expected: []byte("\b\b\b   text"), // Not a complete clearing pattern
		},
		{
			name:     "Multiple lines after clearing",
			input:    []byte("\b\b\b\b\b    \b\b\b\b\binterface GigabitEthernet1/38\r\n!\r\n"),
			expected: []byte("interface GigabitEthernet1/38\r\n!\r\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := stripPagerClearingSequence(tt.input)
			require.Equal(t, tt.expected, result, "stripPagerClearingSequence(%q) = %q, want %q", tt.input, result, tt.expected)
		})
	}
}
