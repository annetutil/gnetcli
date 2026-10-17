package genericcli

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	gmock "github.com/annetutil/gnetcli/pkg/testutils/mock"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/annetutil/gnetcli/pkg/streamer/ssh"
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
			WithLoginCallbacks([]cmd.ExprCallback{
				// both not valid regex * added here to check that we make callback for an expected regex
				cmd.NewExprCallback("/not valid regex 1/", "\r\n"),
				cmd.NewExprCallback(`/\*.+Login: Someone logged in/`, "\n"),
				cmd.NewExprCallback("/not valid regex 2/", "\r"),
			}),
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

func TestCommandCallbackWithAdditionalQuestionExpression(t *testing.T) {
	logger := zap.Must(zap.NewDevelopmentConfig().Build())
	dialog := [][]gmock.Action{
		{
			gmock.Send("<device>"),
			gmock.Expect("test\n"),
			gmock.SendEcho("test\r\n"),
			gmock.Send("callback"),
			gmock.Expect("answer"),
			gmock.Send("done\r\n<device>"),
			gmock.Close(),
		},
	}

	command := cmd.NewCmd(
		"test",
		cmd.WithAddAnswers(cmd.NewAnswer("unused-question", "unused", true)),
		cmd.WithExprCallback(cmd.NewExprCallback("callback", "answer")),
	)
	cmdRes, resErr, serverErr, err := gmock.RunCmd(func(connector streamer.Connector) device.Device {
		dev := newDevice(fullQuestion, connector, logger)
		return &dev
	}, gmock.ConcatMultipleSlices(dialog), []cmd.Cmd{command}, logger)

	require.NoError(t, err)
	require.NoError(t, serverErr)
	require.NoError(t, resErr)
	require.Equal(t, []cmd.CmdRes{cmd.NewCmdRes([]byte("done"))}, cmdRes)
}

// Observe transport-read deadlines without slow commands or wall-clock sleeps.
type timeoutRecordingConnector struct {
	streamer.Connector
	readContexts []context.Context
	beforeRead   func(context.Context) error
	lastCommand  string
}

func (c *timeoutRecordingConnector) ReadTo(ctx context.Context, expression expr.Expr) (streamer.ReadRes, error) {
	c.readContexts = append(c.readContexts, ctx)
	if c.beforeRead != nil {
		if err := c.beforeRead(ctx); err != nil {
			return nil, err
		}
	}
	return c.Connector.ReadTo(ctx, expression)
}

func (c *timeoutRecordingConnector) Write(data []byte) error {
	if string(data) != "\n" {
		c.lastCommand = string(data)
	}
	return c.Connector.Write(data)
}

func newTimeoutTestDevice(t *testing.T, autoCommands ...cmd.Cmd) (*GenericDevice, *timeoutRecordingConnector) {
	t.Helper()
	dialog := []gmock.Action{gmock.Send("<device>")}
	for _, command := range []string{"first", "second"} {
		dialog = append(dialog, gmock.Expect(command+"\n"), gmock.SendEcho(command+"\r\n"), gmock.Send("ok\r\n<device>"))
	}
	// Keep the transport open until client cleanup, avoiding an EOF/prompt race.
	dialog = append(dialog, gmock.Expect("client cleanup\n"))
	server, err := gmock.NewMockSSHServer(dialog)
	require.NoError(t, err)
	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Run(context.Background()) }()
	host, port := server.GetAddress()
	connector := &timeoutRecordingConnector{
		Connector: ssh.NewStreamer(host, credentials.NewSimpleCredentials(), ssh.WithPort(port)),
	}
	cli := MakeGenericCLI(
		expr.NewSimpleExprLast200().FromPattern(loginPromptExpression),
		expr.NewSimpleExprLast200().FromPattern(loginErrorExpression),
		WithAutoCommands(autoCommands),
	)
	dev := MakeGenericDevice(cli, connector, WithDevLogger(zap.NewNop()))
	t.Cleanup(func() {
		dev.Close()
		if err := <-serverErr; err != nil && err != io.EOF {
			require.ErrorIs(t, err, gmock.ErrReadFailed)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, dev.Connect(ctx))
	return &dev, connector
}

func TestExecuteCtxCommandDeadline(t *testing.T) {
	for _, tc := range []struct {
		name          string
		parentTimeout time.Duration
		cmdTimeout    time.Duration
	}{
		{name: "no deadline"},
		{name: "parent deadline", parentTimeout: 3 * time.Hour},
		{name: "command deadline", parentTimeout: 3 * time.Hour, cmdTimeout: 2 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev, connector := newTimeoutTestDevice(t)
			dev.SetCLIConnectTimeout(time.Minute)
			ctx := context.Background()
			if tc.parentTimeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.parentTimeout)
				defer cancel()
			}
			parentDeadline, hasParentDeadline := ctx.Deadline()
			for i, command := range []string{"first", "second"} {
				startRead := len(connector.readContexts)
				before := time.Now()
				res, err := dev.ExecuteCtx(ctx, cmd.NewCmd(command, cmd.WithCmdTimeout(tc.cmdTimeout)))
				after := time.Now()
				require.NoError(t, err)
				require.Equal(t, "ok", string(res.Output()))
				reads := connector.readContexts[startRead:]
				if i == 0 {
					require.NotEmpty(t, reads)
					deadline, ok := reads[0].Deadline()
					require.True(t, ok, "initial CLI login must have a deadline")
					require.False(t, deadline.Before(before.Add(time.Minute)))
					require.False(t, deadline.After(after.Add(time.Minute)))
					reads = reads[1:]
				}
				require.NotEmpty(t, reads)
				for _, readCtx := range reads {
					deadline, ok := readCtx.Deadline()
					if tc.cmdTimeout > 0 {
						require.True(t, ok)
						require.False(t, deadline.Before(before.Add(tc.cmdTimeout)), "command inherited CLI connect deadline")
						require.False(t, deadline.After(after.Add(tc.cmdTimeout)))
					} else {
						require.Equal(t, hasParentDeadline, ok, "command inherited CLI connect deadline")
						require.Equal(t, parentDeadline, deadline)
					}
				}
			}
		})
	}
}

func TestExecuteCtxTimeouts(t *testing.T) {
	for _, name := range []string{"login timeout", "command timeout", "parent deadline", "parent cancellation"} {
		t.Run(name, func(t *testing.T) {
			dev, connector := newTimeoutTestDevice(t)
			dev.SetCLIConnectTimeout(time.Minute)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := "first"
			cmdTimeout := time.Hour
			if name == "login timeout" {
				dev.SetCLIConnectTimeout(20 * time.Millisecond)
			} else {
				_, err := dev.ExecuteCtx(ctx, cmd.NewCmd("first"))
				require.NoError(t, err)
				command = "second"
			}
			if name == "command timeout" {
				cmdTimeout = 20 * time.Millisecond
			}
			if name == "parent deadline" {
				var deadlineCancel context.CancelFunc
				ctx, deadlineCancel = context.WithTimeout(ctx, 20*time.Millisecond)
				defer deadlineCancel()
			}
			connector.beforeRead = func(readCtx context.Context) error {
				if name == "parent cancellation" {
					cancel()
				}
				<-readCtx.Done()
				return readCtx.Err()
			}
			_, err := dev.ExecuteCtx(ctx, cmd.NewCmd(command, cmd.WithCmdTimeout(cmdTimeout)))
			if name == "parent cancellation" {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.ErrorIs(t, err, context.DeadlineExceeded)
			}
			if name == "login timeout" || name == "command timeout" {
				require.NoError(t, ctx.Err(), "the parent context must remain usable")
			}
		})
	}
}

func TestExecuteCtxInitializationDeadline(t *testing.T) {
	dev, connector := newTimeoutTestDevice(t, cmd.NewCmd("first", cmd.WithCmdTimeout(time.Hour)))
	dev.SetCLIConnectTimeout(time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	parentDeadline, _ := ctx.Deadline()
	var loginDeadline time.Time
	seenAutoCommand, seenUserCommand := false, false
	connector.beforeRead = func(readCtx context.Context) error {
		deadline, ok := readCtx.Deadline()
		require.True(t, ok)
		switch connector.lastCommand {
		case "":
			loginDeadline = deadline
		case "first":
			seenAutoCommand = true
			require.Equal(t, loginDeadline, deadline, "auto commands must share the CLI login deadline")
		case "second":
			seenUserCommand = true
			require.Equal(t, parentDeadline, deadline, "user command must not inherit the CLI login deadline")
		}
		return nil
	}
	res, err := dev.ExecuteCtx(ctx, cmd.NewCmd("second"))
	require.NoError(t, err)
	require.Equal(t, "ok", string(res.Output()))
	require.True(t, seenAutoCommand)
	require.True(t, seenUserCommand)
}
