package emulator_test

import (
	"strings"
	"testing"

	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
)

const boundedWordProfile = `apiVersion: cli-emulator/v1
name: bounded-word
initialMode: config
modes:
  config: {prompt: "sw#"}
  other: {prompt: "other#"}
commands:
  - id: set
    modes: [config]
    syntax: "set <name:word>"
    help: [Set value, Value]
    arguments:
      name: {hint: "TEXT<2-4>", minLength: 2, maxLength: 4}
    actions: []
`

func TestBoundedWordArgumentsShareParsingAndHelp(t *testing.T) {
	p := load(t, boundedWordProfile)
	for _, value := range []string{"ab", "ABCD", "абвг"} {
		m, err := p.Parse("config", "set "+value)
		require.NoError(t, err)
		require.Equal(t, value, m.Args["name"])
		require.Equal(t, []string{"<cr>"}, p.Help("config", "set "+value+" "))
	}
	for _, value := range []string{"a", "abcde", "абвгд"} {
		_, err := p.Parse("config", "set "+value)
		var pe *emulator.ParseError
		require.ErrorAs(t, err, &pe)
		require.Equal(t, "invalid", pe.Kind)
		require.Equal(t, 4, pe.Offset)
		require.Empty(t, p.Help("config", "set "+value+" "))
	}
	for _, value := range []string{"", "a", "ab", "ABCD"} {
		require.Equal(t, []emulator.HelpEntry{{Token: "TEXT<2-4>", Description: "Value", Kind: "argument"}}, p.HelpEntries("config", "set "+value))
		require.Equal(t, "set "+value, p.Complete("config", "set "+value).Line)
	}
	require.Empty(t, p.Help("config", "set abcde"))
	require.Equal(t, "set ", p.Complete("config", "se").Line)
	_, err := p.Parse("config", "set")
	require.Error(t, err)

	// Equivalent argument prefixes inherit specifications, not just help text.
	extra := `  - id: detailed
    modes: [config]
    syntax: "set <value:word> detail"
    actions: []
  - id: other-mode
    modes: [other]
    syntax: "set <name:word>"
    actions: []
`
	p = load(t, boundedWordProfile+extra)
	_, err = p.Parse("config", "set abcde detail")
	require.Error(t, err)
	_, err = p.Parse("config", "set ab detail")
	require.NoError(t, err)
	require.Equal(t, []string{"TEXT<2-4>"}, p.Help("config", "set "))
	_, err = p.Parse("other", "set abcde")
	require.NoError(t, err)
	require.Equal(t, []string{"<name:word>"}, p.Help("other", "set "))
	extra = strings.Replace(extra, "    actions: []", "    arguments:\n      value: {maxLength: 8}\n    actions: []", 1)
	_, err = emulator.LoadProfile(strings.NewReader(boundedWordProfile+extra), nil)
	require.ErrorContains(t, err, "conflicting argument specification")
}

func TestArgumentSpecificationsFilterStateBackedValues(t *testing.T) {
	text := strings.Replace(argumentProfile, "    help: [Interface, Interface name]", "    help: [Interface, Interface name]\n    arguments:\n      name: {minLength: 2, maxLength: 4}", 1)
	p := load(t, text)
	state := map[string]any{"inventory": map[string]any{"interfaces": map[string]any{"A": nil, "Good": nil, "TooLong": nil}}}
	require.Equal(t, []string{"Good", "LoopBack"}, p.HelpWithState("config", "interface ", state))
	require.Equal(t, "interface Good ", p.CompleteWithState("config", "interface Go", state).Line)
	// A named family keyword isn't subject to the sibling word's length bound.
	_, err := p.Parse("config", "interface LoopBack 1")
	require.NoError(t, err)
}

func TestArgumentSpecificationValidation(t *testing.T) {
	for _, tc := range []struct{ old, value, want string }{
		{"name: {hint:", "missing: {hint:", "word argument"},
		{"<name:word>", "<name:uint>", "word argument"},
		{"<name:word>", "<name:rest>", "word argument"},
		{"minLength: 2", "minLength: -1", "length bounds"},
		{"maxLength: 4", "maxLength: -1", "length bounds"},
		{"minLength: 2", "minLength: 5", "length bounds"},
		{"TEXT<2-4>", "bad hint", "argument hint"},
		{"TEXT<2-4>", `bad\n`, "argument hint"},
		{"TEXT<2-4>", "<cr>", "argument hint"},
		{"TEXT<2-4>", strings.Repeat("X", 257), "argument hint"},
		{"minLength: 2", "minLenght: 2", "minLenght"},
	} {
		_, err := emulator.LoadProfile(strings.NewReader(strings.Replace(boundedWordProfile, tc.old, tc.value, 1)), nil)
		require.ErrorContains(t, err, tc.want, tc.value)
	}
	p := load(t, strings.Replace(boundedWordProfile, `hint: "TEXT<2-4>", minLength: 2, maxLength: 4`, `hint: "", minLength: 0, maxLength: 0`, 1))
	require.Equal(t, []string{"<name:word>"}, p.Help("config", "set "))
	_, err := p.Parse("config", "set "+strings.Repeat("x", 100))
	require.NoError(t, err)
}

func TestArgumentHintDoesNotCollideWithSuggestionKeys(t *testing.T) {
	text := strings.Replace(boundedWordProfile, "TEXT<2-4>", "keyword:child", 1)
	text += `  - id: child
    modes: [config]
    syntax: set child
    actions: []
`
	p := load(t, text)
	require.Equal(t, []string{"child", "keyword:child"}, p.Help("config", "set "))
	require.Equal(t, "set child ", p.Complete("config", "set child").Line)
}
