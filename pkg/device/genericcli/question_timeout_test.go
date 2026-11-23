package genericcli_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/device/genericcli"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

func TestGenericExecuteDefersDefaultQuestionWithCommandAnswers(t *testing.T) {
	const question = "Continue? [Y/N]"
	explicitQA := []cmd.CmdOption{cmd.WithAnswers(cmd.NewAnswerWithNL(question+":", "Y"))}

	for _, tc := range []struct {
		name                string
		options             []cmd.CmdOption
		chunks              []string
		duringTimeout       string
		eof                 bool
		cancel              bool
		readCause           error
		wantErr             error
		wantTerminalReadErr bool
	}{
		{
			name:    "explicit question split before colon",
			options: explicitQA,
			chunks:  []string{question, ":", "done\r\nlab#"},
		},
		{
			name:                "unanswered question diagnosed at read timeout",
			options:             explicitQA,
			chunks:              []string{question},
			wantErr:             &device.QuestionException{Question: []byte(question)},
			wantTerminalReadErr: true,
		},
		{
			name:                "output without a question preserves the read timeout",
			options:             explicitQA,
			chunks:              []string{"still working"},
			wantErr:             &streamer.ReadTimeoutException{},
			wantTerminalReadErr: true,
		},
		{
			name:                "question followed by other output is not a pending question",
			options:             explicitQA,
			chunks:              []string{question, "\r\nstill working"},
			wantErr:             &streamer.ReadTimeoutException{},
			wantTerminalReadErr: true,
		},
		{
			name:                "question completed during timeout is not a missing answer",
			options:             explicitQA,
			chunks:              []string{question},
			duringTimeout:       ":",
			wantErr:             &streamer.ReadTimeoutException{},
			wantTerminalReadErr: true,
		},
		{
			name:                "device error takes precedence",
			options:             explicitQA,
			chunks:              []string{"Error: failed\r\n", question},
			wantErr:             &device.ExecException{Data: "Error: failed"},
			wantTerminalReadErr: true,
		},
		{
			name:                "EOF is not a missing answer",
			options:             explicitQA,
			chunks:              []string{question},
			eof:                 true,
			wantErr:             &streamer.EOFException{},
			wantTerminalReadErr: true,
		},
		{
			name:                "context cancellation is not a missing answer",
			options:             explicitQA,
			chunks:              []string{question},
			cancel:              true,
			wantErr:             context.Canceled,
			wantTerminalReadErr: true,
		},
		{
			name:                "connector cancellation wrapped in read timeout is preserved",
			options:             explicitQA,
			chunks:              []string{question},
			readCause:           context.Canceled,
			wantErr:             context.Canceled,
			wantTerminalReadErr: true,
		},
		{
			name:    "default question fails immediately without command answers",
			chunks:  []string{question},
			wantErr: &device.QuestionException{Question: []byte(question)},
		},
		{
			name:    "an empty QA is not a command question",
			options: []cmd.CmdOption{cmd.WithAnswers(cmd.NewAnswerWithNL("", "Y"))},
			chunks:  []string{question},
			wantErr: &device.QuestionException{Question: []byte(question)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			// Match after each chunk, rather than relying on network packet
			// boundaries or wall-clock delays to split the question.
			chunks := append([]string{"show\r\n"}, tc.chunks...)
			var buffer []byte
			var terminalReadErr bool
			conn := &contextConnector{reads: 1, read: func(_ context.Context, pattern expr.Expr) (streamer.ReadRes, error) {
				for len(chunks) > 0 {
					buffer = append(buffer, chunks[0]...)
					chunks = chunks[1:]
					if match, ok := pattern.Match(buffer); ok {
						res := streamer.NewReadResImpl(buffer[:match.Start], buffer[match.End:], match.GroupDict, buffer[match.Start:match.End], match.PatternNo)
						buffer = buffer[match.End:]
						return res, nil
					}
				}
				terminalReadErr = true
				buffer = append(buffer, tc.duringTimeout...)
				if tc.eof {
					return nil, streamer.ThrowEOFException(buffer)
				}
				if tc.cancel {
					cancel()
					return nil, streamer.ThrowReadTimeoutException(buffer, context.Canceled)
				}
				return nil, streamer.ThrowReadTimeoutException(buffer, tc.readCause)
			}}
			cli := genericcli.MakeGenericCLI(
				expr.NewSimpleExpr().FromPattern(`(?:^|\r\n)lab#$`),
				expr.NewSimpleExpr().FromPattern(`Error: [^\r\n]+`),
				genericcli.WithQuestion(expr.NewSimpleExpr().FromPattern(`Continue\? \[Y/N\]:?`)),
			)
			res, err := genericcli.GenericExecute(ctx, cmd.NewCmd("show", tc.options...), conn, cli, zap.NewNop())
			if tc.wantErr == nil {
				require.NoError(t, err)
				require.Equal(t, "done", string(res.Output()))
				require.Equal(t, []string{"show", "\n", "Y\n"}, conn.writes)
			} else {
				switch tc.wantErr.(type) {
				case *device.QuestionException, *device.ExecException:
					require.Equal(t, tc.wantErr, err)
				default:
					require.ErrorIs(t, err, tc.wantErr)
				}
				require.Nil(t, res)
				require.Equal(t, []string{"show", "\n"}, conn.writes)
			}
			require.Equal(t, tc.wantTerminalReadErr, terminalReadErr)
		})
	}
}
