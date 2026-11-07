package emulator_test

import (
	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestCursorInsertionDeleteHomeEndHistoryAndCompletion(t *testing.T) {
	d := device(t, emulator.Options{})
	s := attach(t, d)
	input(t, s, "configure terminal\ndescription ac")
	require.Equal(t, "\x1b[1D", input(t, s, "\x1b[D"))
	require.Contains(t, input(t, s, "b"), "description abc")
	input(t, s, "\x1b[3~\x1bOFc\x1bOH\x1b[3~d\x1b[F\n")
	require.Equal(t, "abc", d.Snapshot().Running["description"])
	input(t, s, "description xy\x1b[D"+historyUp+historyDown+"z\n")
	require.Equal(t, "xzy", d.Snapshot().Running["description"])
	input(t, s, "description xy\x1b[D")
	require.NoError(t, d.Inject(emulator.Event{Kind: "log", Route: "all", Policy: "redraw", Text: "noise"}))
	require.True(t, strings.HasSuffix(drain(s), "description xy\x1b[1D"))
	input(t, s, "z\n")
	require.Equal(t, "xzy", d.Snapshot().Running["description"])
	input(t, s, "des old\x1b[H\x1b[3C\tnew-\x1b[F\n")
	require.Equal(t, "new-old", d.Snapshot().Running["description"])
	input(t, s, "show rn\x1b[D\t")
	require.Contains(t, input(t, s, "\n"), "new-old\r\n")
}

func TestCursorEditingFragmentationAndSecretGuards(t *testing.T) {
	var outputs []string
	text := "configure terminal\ndescription ac\x1b[Db\x1b[3~\x1bOFc\x1bOH\x1b[3~d\x1b[F\n"
	for _, size := range []int{1, 2, 7, 4096} {
		d := device(t, emulator.Options{})
		s := attach(t, d)
		var out strings.Builder
		for i := 0; i < len(text); i += size {
			out.WriteString(input(t, s, text[i:min(len(text), i+size)]))
		}
		require.Equal(t, "abc", d.Snapshot().Running["description"])
		outputs = append(outputs, out.String())
	}
	for _, out := range outputs[1:] {
		require.Equal(t, outputs[0], out)
	}
	d := device(t, emulator.Options{})
	s, err := d.Attach(emulator.AttachOptions{Console: "tty0"})
	require.NoError(t, err)
	drain(s)
	input(t, s, "test\n")
	require.Empty(t, input(t, s, "sec\x1b[D\x1b[H\x1b[3~ret"))
	require.Equal(t, "\r\nsw#", input(t, s, "\n"))
}

func TestTerminalGeometryResizeWrappingAndPager(t *testing.T) {
	text := strings.Replace(profileYAML, "terminal: {logPolicy: redraw}", "terminal: {logPolicy: redraw, pageLines: 10}", 1)
	text += `  # placeholder
`
	text = strings.Replace(text, "dialogs:\n", `  - id: long
    modes: [exec]
    syntax: long
    actions: [{op: output, text: "0123456789ABCDEFGHIJ\n"}]
`+"dialogs:\n", 1)
	d := validationDevice(t, load(t, text))
	s, err := d.Attach(emulator.AttachOptions{Authenticated: true, Columns: 8, Rows: 3})
	require.NoError(t, err)
	drain(s)
	require.Equal(t, "long\r\n0123456789ABCDEF--More--", input(t, s, "long\n"))
	require.Equal(t, "\r\x1b[2KGHIJ\r\nsw#", input(t, s, " "))
	input(t, s, "abcdef\x1b[3D")
	out := input(t, s, "X")
	require.Contains(t, out, "\x1b[1B")
	require.Contains(t, out, "sw#abcXdef")
	require.NoError(t, s.Resize(12, 4))
	require.Contains(t, drain(s), "sw#abcXdef")
	snapshot := d.Snapshot()
	require.Equal(t, 12, snapshot.Sessions[0].Columns)
	require.Equal(t, 4, snapshot.Sessions[0].Rows)
	require.Error(t, s.Resize(-1, 3))
	require.Error(t, s.Resize(5000, 3))
	require.NoError(t, s.Resize(0, 0))
	require.Equal(t, 12, d.Snapshot().Sessions[0].Columns)
}

func TestLiveHelpUsesPTYWidth(t *testing.T) {
	d := validationDevice(t, loadHuaweiHelpProfile(t))
	s, err := d.Attach(emulator.AttachOptions{Authenticated: true, Columns: 35, Rows: 24})
	require.NoError(t, err)
	drain(s)
	out := input(t, s, "display interface ?")
	require.Contains(t, out, "  brief            Summary\r\n                   information")
	for _, line := range strings.Split(out, "\r\n") {
		if strings.HasPrefix(line, "  ") {
			require.LessOrEqual(t, len(line), 35)
		}
	}
}
