package emulator_test

import (
	"os"
	"strings"
	"testing"

	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
)

const helpProfile = `
apiVersion: cli-emulator/v1
name: help-example
initialMode: user
abbreviations: true
initialState: {hostname: sw}
terminal:
  help:
    rootHeader: "Current view commands:"
    indent: 2
    keywordWidth: 18
    echoQuestion: true
modes:
  user: {prompt: "<{{ .Running.hostname }}>"}
  config: {prompt: "[{{ .Running.hostname }}]"}
commands:
  - id: display-version
    modes: [user]
    syntax: display version
    help: [Display current system information, Display system version]
    actions: [{op: output, text: "VERSION-RESULT\n"}]
  - id: display-config
    modes: [user]
    syntax: display current-configuration
    help: [Display current system information, Display current configuration]
    actions: []
  - id: enter-config
    modes: [user]
    syntax: system-view
    help: [Enter system view]
    actions: [{op: push, mode: config}]
  - id: interface
    modes: [config]
    syntax: "interface <name:word>"
    help: [Enter interface view, Interface name]
    actions: []
  - id: quit
    modes: [config]
    syntax: quit
    help: [Exit the current view]
    actions: [{op: pop}]
`

func TestHelpShowsOnlyOneGrammarLevel(t *testing.T) {
	p := load(t, helpProfile)
	require.Equal(t, []emulator.HelpEntry{
		{Token: "display", Description: "Display current system information", Kind: "keyword"},
		{Token: "system-view", Description: "Enter system view", Kind: "keyword"},
	}, p.HelpEntries("user", ""))
	require.Equal(t, []emulator.HelpEntry{
		{Token: "current-configuration", Description: "Display current configuration", Kind: "keyword"},
		{Token: "version", Description: "Display system version", Kind: "keyword"},
	}, p.HelpEntries("user", "display "))
	require.Equal(t, p.HelpEntries("user", "display "), p.HelpEntries("user", "dis "))
	require.Equal(t, []string{"display"}, p.Help("user", "disp"))
	require.Equal(t, []string{"display"}, p.Help("user", "display"))
	require.Equal(t, []string{"version"}, p.Help("user", "display v"))
	require.Equal(t, []emulator.HelpEntry{{Token: "<cr>", Kind: "end"}}, p.HelpEntries("user", "display version "))
	require.Equal(t, []emulator.HelpEntry{{Token: "<name:word>", Description: "Interface name", Kind: "argument"}}, p.HelpEntries("config", "interface "))
	require.Equal(t, []string{"interface", "quit"}, p.Help("config", ""))
	require.Empty(t, p.HelpEntries("user", "display nonexistent "))
	require.Empty(t, p.HelpEntries("absent", ""))
	require.Equal(t, "Current view commands:\n  display           Display current system information\n  system-view       Enter system view\n", p.RenderHelp("user", ""))
	require.Equal(t, "  current-configuration  Display current configuration\n  version                Display system version\n", p.RenderHelp("user", "display "))
}

func TestHelpQuestionEchoAndInputPreservation(t *testing.T) {
	d := validationDevice(t, load(t, helpProfile))
	s, err := d.Attach(emulator.AttachOptions{Authenticated: true, Username: "test"})
	require.NoError(t, err)
	require.Equal(t, "<sw>", drain(s))
	before := d.Snapshot()
	root := input(t, s, "?")
	require.Equal(t, "?\r\nCurrent view commands:\r\n  display           Display current system information\r\n  system-view       Enter system view\r\n<sw>", root)
	require.NotContains(t, root, "version")
	require.NotContains(t, root, "current-configuration")
	require.Equal(t, before, d.Snapshot())
	sub := input(t, s, "display ?")
	require.Equal(t, "display ?\r\n  current-configuration  Display current configuration\r\n  version                Display system version\r\n<sw>display ", sub)
	require.NotContains(t, sub, "Current view commands:")
	require.NotContains(t, sub, "VERSION-RESULT")
	require.Equal(t, before, d.Snapshot())
	require.Equal(t, "version\r\nVERSION-RESULT\r\n<sw>", input(t, s, "version\n"))
	require.Equal(t, "display ", input(t, s, "dis\t"))
	require.Equal(t, "\r\ncurrent-configuration\r\nversion\r\n<sw>display ", input(t, s, "\t"))
	input(t, s, "\x03system-view\n")
	view := input(t, s, "?")
	require.Contains(t, view, "  interface         Enter interface view")
	require.NotContains(t, view, "display")
	require.NotContains(t, view, "Interface name")
}

func TestHelpDescriptionsAreSharedByPrefixAndScopedByMode(t *testing.T) {
	// A description provided on only one leaf still belongs to their shared node.
	text := strings.Replace(helpProfile, "help: [Display current system information, Display system version]", "help: [\"\", Display system version]", 1)
	p := load(t, text)
	require.Equal(t, "Display current system information", p.HelpEntries("user", "")[0].Description)
	// Different descriptions for the same keyword in different views are allowed.
	text += `  - id: display-config-view
    modes: [config]
    syntax: display candidate
    help: [Display candidate data, Display candidate configuration]
    actions: []
`
	p = load(t, text)
	require.Equal(t, "Display candidate data", p.HelpEntries("config", "")[0].Description)
	require.Equal(t, "Display current system information", p.HelpEntries("user", "")[0].Description)
}

func TestHelpMetadataValidation(t *testing.T) {
	for _, tc := range []struct{ name, text, want string }{
		{"conflict", strings.Replace(helpProfile, "help: [Display current system information, Display current configuration]", "help: [Conflicting parent description, Display current configuration]", 1), "conflicting help for \"display\""},
		{"wrong length", strings.Replace(helpProfile, "help: [Display current system information, Display system version]", "help: [Only one description]", 1), "one entry per syntax token"},
		{"unknown field", strings.Replace(helpProfile, "keywordWidth: 18", "keywordWidth: 18\n    typo: true", 1), "field typo"},
		{"negative indent", strings.Replace(helpProfile, "indent: 2", "indent: -1", 1), "help indent"},
		{"large width", strings.Replace(helpProfile, "keywordWidth: 18", "keywordWidth: 257", 1), "keywordWidth"},
		{"multiline description", strings.Replace(helpProfile, "help: [Enter system view]", `help: ["bad\ntext"]`, 1), "single line"},
		{"control header", strings.Replace(helpProfile, `rootHeader: "Current view commands:"`, `rootHeader: "bad\ttext"`, 1), "single line"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := emulator.LoadProfile(strings.NewReader(tc.text), nil)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestHelpWithoutMetadataRemainsCompatible(t *testing.T) {
	p := load(t, profileYAML)
	require.Equal(t, "running\nslow\n", p.RenderHelp("exec", "show "))
	d := validationDevice(t, p)
	s := attach(t, d)
	require.Equal(t, "show \r\nrunning\r\nslow\r\nsw#show ", input(t, s, "show ?"))
	require.Equal(t, "^C\r\nsw#", input(t, s, "\x03"))
	for _, echo := range []string{"line", "none"} {
		t.Run(echo, func(t *testing.T) {
			text := strings.Replace(helpProfile, "terminal:\n", "terminal:\n  echo: "+echo+"\n", 1)
			d := validationDevice(t, load(t, text))
			s, err := d.Attach(emulator.AttachOptions{Authenticated: true})
			require.NoError(t, err)
			drain(s)
			out := input(t, s, "display ?")
			require.NotContains(t, out, "?")
			require.NotContains(t, out, "<sw>display ")
			require.Contains(t, out, "Display system version")
			out = input(t, s, "version\n")
			require.Contains(t, out, "VERSION-RESULT")
		})
	}
}

func TestHuaweiExampleUsesDescribedSingleLevelHelp(t *testing.T) {
	root, err := os.OpenRoot("../../../examples/gswitch")
	require.NoError(t, err)
	defer root.Close()
	f, err := root.Open("huawei.yaml")
	require.NoError(t, err)
	defer f.Close()
	p, err := emulator.LoadProfile(f, root.FS())
	require.NoError(t, err)
	top := p.RenderHelp("user", "")
	require.Equal(t, 1, strings.Count(top, "  display "))
	require.Contains(t, top, "  display           Display current system information")
	require.NotContains(t, top, "current-configuration")
	require.NotContains(t, top, "version")
	next := p.RenderHelp("user", "display ")
	require.Contains(t, next, "  current-configuration  Display current configuration")
	require.Contains(t, next, "  version                Display system version")
	require.Contains(t, next, "  slow                   Demonstrate delayed output (emulator)")
	require.NotContains(t, next, "  display ")
}
