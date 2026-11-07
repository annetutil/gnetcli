package emulator_test

import (
	"strings"
	"testing"

	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
)

const argumentProfile = `apiVersion: cli-emulator/v1
name: argument-completion
initialMode: config
abbreviations: true
initialState:
  inventory:
    interfaces:
      Ethernet1: {}
      Ethernet2: {}
      LoopBack0: {}
terminal: {}
modes:
  config: {prompt: "sw#"}
commands:
  - id: interface
    modes: [config]
    syntax: "interface <name:word>"
    help: [Interface, Interface name]
    completions:
      name: {statePath: [inventory, interfaces]}
    actions: []
  - id: loopback
    modes: [config]
    syntax: "interface LoopBack <number:word>"
    help: [Interface, LoopBack interface, Interface number]
    completions:
      number: {statePath: [inventory, interfaces], prefix: LoopBack, stripPrefix: true}
    actions: []
  - id: description
    modes: [config]
    syntax: "description <text:rest>"
    actions: []
`

func TestStateBackedArgumentHelpAndCompletion(t *testing.T) {
	p := load(t, argumentProfile)
	require.Equal(t, []string{"Ethernet1", "Ethernet2", "LoopBack", "LoopBack0"}, p.Help("config", "interface "))
	for _, tc := range []struct{ input, want string }{
		{"interface eth", "interface Ethernet"},
		{"interface ethernet1", "interface Ethernet1 "},
		{"interface LoopBack", "interface LoopBack "},
		{"interface loopback ", "interface loopback 0 "},
		{"interface LoopBack0", "interface LoopBack0 "},
		{"description Ethernet", "description Ethernet"},
		{"interface absent", "interface absent"},
	} {
		require.Equal(t, tc.want, p.Complete("config", tc.input).Line, tc.input)
	}
	require.Empty(t, p.Help("config", "interface absent"))
	// Completion is advisory: new values are accepted, not an enum constraint.
	_, err := p.Parse("config", "interface NewPort123")
	require.NoError(t, err)
	match, err := p.Parse("config", "INTERFACE loopback 42")
	require.NoError(t, err)
	require.Equal(t, "loopback", match.Command)
	require.Equal(t, "42", match.Args["number"])

	state := map[string]any{"inventory": map[string]any{"interfaces": map[string]any{"LoopBack99": nil}}}
	require.Equal(t, []string{"LoopBack", "LoopBack99"}, p.HelpWithState("config", "interface ", state))
	require.Equal(t, "interface LoopBack 99 ", p.CompleteWithState("config", "interface LoopBack ", state).Line)
	require.Equal(t, "LoopBack\nLoopBack99\n", p.RenderHelpWithState("config", "interface ", state))
	require.Equal(t, []emulator.HelpEntry{{Token: "99", Description: "Interface number", Kind: "value"}}, p.HelpEntriesWithState("config", "interface LoopBack ", state))
	require.Equal(t, map[string]any{"inventory": map[string]any{"interfaces": map[string]any{"LoopBack99": nil}}}, state)
	// Per-query state never replaces the profile's initial state.
	require.Equal(t, []string{"0"}, p.Help("config", "interface LoopBack "))

	// Even if a state key collides with a keyword, the parser/help prefer the keyword.
	state["inventory"].(map[string]any)["interfaces"] = map[string]any{"loopback": nil, "LoopBack0": nil}
	require.Equal(t, []string{"LoopBack", "LoopBack0"}, p.HelpWithState("config", "interface ", state))
	require.Equal(t, "interface LoopBack ", p.CompleteWithState("config", "interface loopback", state).Line)
}

func TestArgumentCompletionEmptyAndUnsafeValues(t *testing.T) {
	p := load(t, argumentProfile)
	for _, interfaces := range []any{nil, "not a map", map[string]any{}, map[string]any{
		"": nil, "bad name": nil, "bad\tname": nil, "\x1b[2J": nil, "порт": nil, strings.Repeat("X", 10000): nil,
	}} {
		state := map[string]any{"inventory": map[string]any{"interfaces": interfaces}}
		require.Equal(t, []string{"<name:word>", "LoopBack"}, p.HelpWithState("config", "interface ", state))
	}
	require.Equal(t, []string{"<name:word>", "LoopBack"}, p.HelpWithState("config", "interface ", nil))
	state := map[string]any{"inventory": map[string]any{"interfaces": map[string]any{
		"Good1": nil, "bad\nname": nil, "LoopBack": nil, "LoopBack12": nil,
	}}}
	require.Equal(t, []string{"Good1", "LoopBack", "LoopBack12"}, p.HelpWithState("config", "interface ", state))
	require.Equal(t, []string{"12"}, p.HelpWithState("config", "interface LoopBack ", state))
	unstripped := load(t, strings.Replace(argumentProfile, "stripPrefix: true", "stripPrefix: false", 1))
	require.Equal(t, []string{"LoopBack0"}, unstripped.Help("config", "interface LoopBack "))
}

func TestArgumentCompletionProfileValidation(t *testing.T) {
	for _, tc := range []struct{ old, replacement, message string }{
		{"name: {statePath:", "missing: {statePath:", "word argument"},
		{"<name:word>", "<name:uint>", "word argument"},
		{"<name:word>", "<name:rest>", "word argument"},
		{"statePath: [inventory, interfaces]", "statePath: []", "statePath"},
		{"statePath: [inventory, interfaces]", `statePath: [""]`, "statePath"},
		{"prefix: LoopBack, ", "", "stripPrefix requires prefix"},
		{"prefix: LoopBack", `prefix: "bad\n"`, "invalid completion prefix"},
		{"stripPrefix: true", "unknownField: true", "unknownField"},
		{"terminal: {}", "terminal: {help: {lineWidth: -1}}", "lineWidth"},
		{"terminal: {}", "terminal: {help: {lineWidth: 4097}}", "lineWidth"},
	} {
		_, err := emulator.LoadProfile(strings.NewReader(strings.Replace(argumentProfile, tc.old, tc.replacement, 1)), nil)
		require.ErrorContains(t, err, tc.message, tc.replacement)
	}
	// The same argument prefix shares its source across longer command leaves.
	extra := `  - id: detail
    modes: [config]
    syntax: "interface <port:word> detail"
    actions: []
`
	p := load(t, argumentProfile+extra)
	require.Equal(t, []string{"Ethernet1", "Ethernet2", "LoopBack", "LoopBack0"}, p.Help("config", "interface "))
	extra = strings.Replace(extra, "    actions: []", "    completions:\n      port: {statePath: [other]}\n    actions: []", 1)
	_, err := emulator.LoadProfile(strings.NewReader(argumentProfile+extra), nil)
	require.ErrorContains(t, err, "conflicting completion source")
}

const displayInterfaceHelp = "  100GE            100GE interface\n" +
	"  25GE             25GE interface\n" +
	"  Ethernet         Ethernet interface\n" +
	"  LoopBack         LoopBack interface\n" +
	"  MEth             MEth interface\n" +
	"  NULL             NULL interface\n" +
	"  Vlanif           VLAN interface\n" +
	"  brief            Summary information about the interface status and\n" +
	"                   configuration\n" +
	"  counters         Statistics information about the interface\n" +
	"  description      Interface description\n" +
	"  main             Main interface\n" +
	"  slot             Specify slot number\n" +
	"  transceiver      Transceiver information\n" +
	"  troubleshooting  Troubleshooting information\n" +
	"  |                Matching output\n" +
	"  >                Redirect the output to a file\n" +
	"  >>               Redirect the output to a file in append mode\n" +
	"  <cr>\n"

func TestHuaweiInterfaceHelpTranscript(t *testing.T) {
	p := loadHuaweiHelpProfile(t)
	require.Equal(t, displayInterfaceHelp, p.RenderHelp("user", "display interface "))
	require.Equal(t, []string{"100GE", "25GE", "Ethernet", "GE0/0/1", "LoopBack", "MEth", "NULL", "Vlanif"}, p.Help("system", "interface "))
	d := validationDevice(t, p)
	s, err := d.Attach(emulator.AttachOptions{Authenticated: true})
	require.NoError(t, err)
	drain(s)
	before := d.Snapshot()
	require.Equal(t, "display interface ?\r\n"+strings.ReplaceAll(displayInterfaceHelp, "\n", "\r\n")+"\r\n<sw1>display interface ", input(t, s, "display interface ?"))
	require.Equal(t, before, d.Snapshot())
	require.Contains(t, input(t, s, "\n"), "not implemented in this emulator profile")
	input(t, s, "system-view\n")
	before = d.Snapshot()
	require.Equal(t, "interface GE0/0/1 ", input(t, s, "interface GE\t"))
	require.Equal(t, before, d.Snapshot())
	require.Contains(t, input(t, s, "\n"), "[~sw1-GE0/0/1]")
}

func TestHuaweiArgumentCompletionUsesSessionCandidate(t *testing.T) {
	d := validationDevice(t, loadHuaweiHelpProfile(t))
	attachHuawei := func() *emulator.Session {
		s, err := d.Attach(emulator.AttachOptions{Authenticated: true})
		require.NoError(t, err)
		drain(s)
		require.Contains(t, input(t, s, "system-view\n"), "[~sw1]")
		return s
	}
	a, b := attachHuawei(), attachHuawei()
	require.Contains(t, input(t, a, "interface loopback 123\n"), "[~sw1-LoopBack123]")
	require.Contains(t, input(t, a, "description loopback-test\nquit\n"), "[*sw1]")
	require.Contains(t, input(t, a, "interface ?"), "LoopBack123")
	require.NotContains(t, input(t, b, "interface ?"), "LoopBack123")
	require.NotContains(t, d.Snapshot().Running["interfaces"], "LoopBack123")
	require.Contains(t, input(t, a, "\x03interface LoopBack ?"), "  123  Interface number")
	require.Equal(t, "123 ", input(t, a, "\t"))
	require.Contains(t, input(t, a, "\n"), "[*sw1-LoopBack123]")
	require.NotContains(t, input(t, a, "commit\n"), "Error:")
	require.Equal(t, "loopback-test", description(d.Snapshot().Running, "LoopBack123"))
	// An already-open candidate keeps its snapshot until that view is restarted.
	require.NotContains(t, input(t, b, "?"), "LoopBack123")
	input(t, b, "\x03return\nsystem-view\n")
	require.Contains(t, input(t, b, "interface ?"), "LoopBack123")
}
