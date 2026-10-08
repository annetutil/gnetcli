package emulator_test

import (
	"strings"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
)

func TestKeywordCompletion(t *testing.T) {
	p := load(t, profileYAML)
	for _, tc := range []struct {
		name, mode, input, line string
		candidates              []string
	}{
		{"first word", "exec", "sh", "show ", []string{"show"}},
		{"next word", "exec", "show ru", "show running ", []string{"running"}},
		{"abbreviated parent", "exec", "sh ru", "sh running ", []string{"running"}},
		{"common prefix", "exec", "co", "con", []string{"configure", "connect"}},
		{"ambiguous", "exec", "con", "con", []string{"configure", "connect"}},
		{"choices", "exec", "show ", "show ", []string{"running", "slow"}},
		{"finished", "exec", "show running ", "show running ", []string{"<cr>"}},
		{"exact current word", "exec", "show", "show ", []string{"show"}},
		{"whitespace", "exec", "  sh   ru", "  sh   running ", []string{"running"}},
		{"case", "exec", "SH RU", "SH running ", []string{"running"}},
		{"mode", "config", "des", "description ", []string{"description"}},
		{"free text", "config", `description hello  "world"`, `description hello  "world"`, []string{"<text:rest>"}},
		{"missing argument", "config", "description ", "description ", []string{"<text:rest>"}},
		{"wrong mode", "config", "conf", "conf", nil},
		{"unknown mode", "absent", "sh", "sh", nil},
		{"unknown command", "exec", "wat", "wat", nil},
		{"invalid parent", "exec", "show absent next", "show absent next", nil},
		{"ambiguous parent", "exec", "con t", "con t", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := p.Complete(tc.mode, tc.input)
			require.Equal(t, tc.line, result.Line)
			require.Equal(t, tc.candidates, result.Candidates)
		})
	}
}

func TestCompletionRespectsParserPrecedenceAndArgumentTypes(t *testing.T) {
	extra := `  - id: showing
    modes: [exec]
    syntax: showing status
    actions: []
  - id: screen-length
    modes: [exec]
    syntax: "screen-length <lines:uint> temporary"
    actions: []
  - id: interface-action
    modes: [exec]
    syntax: "interface <name:word> description"
    actions: []
  - id: show-target
    modes: [exec]
    syntax: "show <target:word>"
    actions: []
`
	p := load(t, strings.Replace(profileYAML, "dialogs:\n", extra+"dialogs:\n", 1))
	require.Equal(t, "show ", p.Complete("exec", "show").Line)
	require.Equal(t, []string{"show", "showing"}, p.Help("exec", "show"))
	require.Equal(t, "show running ", p.Complete("exec", "show running").Line)
	// A free-form argument must not be silently changed to a keyword prefix.
	require.Equal(t, "show ru", p.Complete("exec", "show ru").Line)
	require.Equal(t, []string{"<target:word>", "running"}, p.Complete("exec", "show ru").Candidates)
	require.Equal(t, "screen-l 24 temporary ", p.Complete("exec", "screen-l 24 tem").Line)
	require.Empty(t, p.Complete("exec", "screen-l bad tem").Candidates)
	require.Empty(t, p.Help("exec", "screen-l bad "))
	require.Empty(t, p.Complete("exec", "screen-l -1 ").Candidates)
	require.Equal(t, "interface Eth1 description ", p.Complete("exec", "interface Eth1 des").Line)
	strict := load(t, strings.Replace(profileYAML, "abbreviations: true", "abbreviations: false", 1))
	require.Equal(t, "show ", strict.Complete("exec", "sh").Line)
	require.Empty(t, strict.Complete("exec", "sh ru").Candidates)
	require.Empty(t, strict.Help("exec", "sh "))
	require.Equal(t, "show running ", strict.Complete("exec", "show ru").Line)
}

func TestTabEditsWithoutExecutingAndHandlesAmbiguity(t *testing.T) {
	d := device(t, emulator.Options{})
	s := attach(t, d)
	before := d.Snapshot()
	require.Equal(t, "show ", input(t, s, "sh\t"))
	require.Equal(t, "\r\nrunning\r\nslow\r\nsw#show ", input(t, s, "\t"))
	require.Equal(t, "running ", input(t, s, "ru\t"))
	require.Equal(t, before, d.Snapshot())
	require.Equal(t, "\r\ninitial\r\nsw#", input(t, s, "\r\n"))
	require.Equal(t, "con\r\nconfigure\r\nconnect\r\nsw#con", input(t, s, "co\t"))
	require.Equal(t, "\r\nconfigure\r\nconnect\r\nsw#con", input(t, s, "\t"))
	input(t, s, "\x03")
	require.Equal(t, "configure terminal ", input(t, s, "conf\tt\t"))
	require.Equal(t, "exec", d.Snapshot().Sessions[0].Mode)
	require.Equal(t, "\r\nsw(config)#", input(t, s, "\n"))
	require.Equal(t, "description ", input(t, s, "des\t"))
	input(t, s, "untouched  value")
	require.Contains(t, input(t, s, "\t"), "<text:rest>")
	input(t, s, "\n")
	require.Equal(t, "untouched  value", d.Snapshot().Running["description"])
}

func TestTabRedrawBackspaceAndUnknownInput(t *testing.T) {
	d := device(t, emulator.Options{})
	s := attach(t, d)
	require.Equal(t, "SH\r\x1b[2Ksw#show ", input(t, s, "SH\t"))
	require.NoError(t, d.Inject(emulator.Event{Kind: "log", Route: "all", Text: "noise", Policy: "redraw"}))
	require.Equal(t, "\r\x1b[2Knoise\r\nsw#show ", drain(s))
	require.Equal(t, "running ", input(t, s, "r\t"))
	require.Equal(t, "\b \b", input(t, s, "\x7f"))
	require.Contains(t, input(t, s, "\n"), "initial\r\nsw#")
	require.Equal(t, "unknown\a", input(t, s, "unknown\t"))
	require.Contains(t, input(t, s, "\n"), "Invalid input")
}

func TestTabRespectsInputLimitAndEchoMode(t *testing.T) {
	p := load(t, strings.Replace(profileYAML, "terminal: {logPolicy: redraw}", "terminal: {logPolicy: redraw, maxInput: 4}", 1))
	d := validationDevice(t, p)
	s := attach(t, d)
	require.Equal(t, "sh\a", input(t, s, "sh\t"))
	require.NoError(t, d.Inject(emulator.Event{Kind: "log", Route: "all", Text: "noise", Policy: "redraw"}))
	require.Equal(t, "\r\x1b[2Knoise\r\nsw#sh", drain(s))
	for _, echo := range []string{"line", "none"} {
		t.Run(echo, func(t *testing.T) {
			p := load(t, strings.Replace(profileYAML, "terminal: {logPolicy: redraw}", "terminal: {echo: "+echo+"}", 1))
			s := attach(t, validationDevice(t, p))
			require.Empty(t, input(t, s, "sh\tru\t"))
			out := input(t, s, "\n")
			if echo == "line" {
				require.Equal(t, "show running \r\ninitial\r\nsw#", out)
			} else {
				require.Equal(t, "\r\ninitial\r\nsw#", out)
			}
		})
	}
}

func TestTabIgnoredOutsideCommandEditing(t *testing.T) {
	d := device(t, emulator.Options{})
	s, err := d.Attach(emulator.AttachOptions{Console: "tty0"})
	require.NoError(t, err)
	require.Equal(t, "Username: ", drain(s))
	require.Equal(t, "test", input(t, s, "test\t"))
	require.Equal(t, "\r\nPassword: ", input(t, s, "\n"))
	require.Empty(t, input(t, s, "sec\tret\t"))
	require.Equal(t, "\r\nsw#", input(t, s, "\n"))
	input(t, s, "ask\n")
	require.Empty(t, input(t, s, "\t"))
	input(t, s, "n\npage\n")
	require.Empty(t, input(t, s, "\t"))
	require.Equal(t, "paging", d.Snapshot().Sessions[0].Interaction)
	input(t, s, "qshow slow\n")
	require.Empty(t, input(t, s, "\t"))
	require.NoError(t, d.Advance(time.Second))
	require.Equal(t, "Body\r\nsw#", drain(s))
	input(t, s, "sh\t")
	require.NoError(t, s.Close())
	s, err = d.Attach(emulator.AttachOptions{Console: "tty0"})
	require.NoError(t, err)
	require.Equal(t, "sw#show ", drain(s))
}

func TestTabInputFragmentation(t *testing.T) {
	var outputs []string
	for _, size := range []int{1, 2, 7, 4096} {
		d := device(t, emulator.Options{})
		s := attach(t, d)
		text := "co\t\x03conf\tt\t\r\ndes\tuplink\r\nex\t\r\nsh\tru\t\r\n"
		var output strings.Builder
		for i := 0; i < len(text); i += size {
			output.WriteString(input(t, s, text[i:min(i+size, len(text))]))
		}
		require.Equal(t, "uplink", d.Snapshot().Running["description"])
		outputs = append(outputs, output.String())
	}
	for _, output := range outputs[1:] {
		require.Equal(t, outputs[0], output)
	}
}
