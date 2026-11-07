package emulator_test

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
)

func inlineValidator(source string) string {
	return "\nvalidation:\n  starlark: |\n    " + strings.ReplaceAll(strings.TrimSpace(source), "\n", "\n    ") + "\n"
}

func uniqueProfile(t *testing.T) *emulator.Profile {
	t.Helper()
	source, err := os.ReadFile("../../../examples/gswitch/validators/unique-descriptions.star")
	require.NoError(t, err)
	base := strings.Replace(profileYAML, "initialState: {hostname: sw, description: initial}", `initialState:
  hostname: sw
  interfaces:
    Ethernet1: {description: uplink}
    Ethernet2: {description: spare}`, 1)
	base = strings.Replace(base, "path: [description]", "path: [interfaces, Ethernet2, description]", 1)
	return load(t, base+inlineValidator(string(source)))
}

func validationDevice(t *testing.T, p *emulator.Profile) *emulator.Device {
	t.Helper()
	d, err := emulator.New(p, emulator.Options{})
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	return d
}

func description(config map[string]any, name string) any {
	return config["interfaces"].(map[string]any)[name].(map[string]any)["description"]
}

func TestStarlarkUniqueDescriptionsRejectImmediateChange(t *testing.T) {
	d := validationDevice(t, uniqueProfile(t))
	s := attach(t, d)
	// A rejected immediate action must not increment the running revision either.
	candidate := attach(t, d)
	input(t, candidate, "begin\n")
	input(t, s, "configure terminal\n")
	before := d.Snapshot()
	output := input(t, s, "description uplink\n")
	require.Contains(t, output, "% Invalid input: description")
	require.Contains(t, output, "Ethernet1 and Ethernet2")
	require.True(t, strings.HasSuffix(output, "sw(config)#"))
	require.NoError(t, s.Err())
	require.Equal(t, before.Running, d.Snapshot().Running)
	require.Equal(t, before.Startup, d.Snapshot().Startup)
	require.NotContains(t, input(t, candidate, "commit\n"), "Candidate conflicts")
	require.NotContains(t, input(t, s, "description access\n"), "Invalid input")
	require.Equal(t, "access", description(d.Snapshot().Running, "Ethernet2"))
}

func TestStarlarkCandidateValidationAtCommit(t *testing.T) {
	d := validationDevice(t, uniqueProfile(t))
	s := attach(t, d)
	require.NotContains(t, input(t, s, "begin\ndescription uplink\n"), "Invalid input")
	require.Equal(t, "spare", description(d.Snapshot().Running, "Ethernet2"))
	require.Equal(t, "uplink", description(d.Snapshot().Sessions[0].Candidate, "Ethernet2"))
	output := input(t, s, "commit\n")
	require.Contains(t, output, "Ethernet1 and Ethernet2")
	require.Equal(t, "spare", description(d.Snapshot().Running, "Ethernet2"))
	require.Equal(t, "uplink", description(d.Snapshot().Sessions[0].Candidate, "Ethernet2"))
	require.NotContains(t, input(t, s, "description access\ncommit\nexit\nsave\n"), "Invalid input")
	require.Equal(t, "access", description(d.Snapshot().Startup, "Ethernet2"))
	require.NoError(t, d.Reboot())
	require.Equal(t, "access", description(d.Snapshot().Running, "Ethernet2"))
}

func TestStarlarkRejectionSkipsRemainingActions(t *testing.T) {
	p := load(t, strings.Replace(profileYAML, `actions: [{op: set, path: [description], value: "{{ .Args.text }}"}]`, `actions: [{op: set, path: [description], value: "{{ .Args.text }}"}, {op: set, path: [hostname], value: corrupted}, {op: save}, {op: output, text: "success\n"}]`, 1)+inlineValidator(`def validate(config):
    if config.get("description") == "bad":
        return "description rejected"
    return None`))
	d := validationDevice(t, p)
	s := attach(t, d)
	input(t, s, "configure terminal\n")
	before := d.Snapshot()
	out := input(t, s, "description bad\n")
	require.Contains(t, out, "description rejected")
	require.NotContains(t, out, "success")
	require.Equal(t, before.Running, d.Snapshot().Running)
	require.Equal(t, before.Startup, d.Snapshot().Startup)
}

func TestStarlarkChecksDeleteAndDelayedActions(t *testing.T) {
	base := strings.Replace(profileYAML, "op: set, path: [description], value:", "op: set, after: 1s, path: [description], value:", 1)
	base = strings.Replace(base, "syntax: save\n    actions: [{op: save}]", "syntax: save\n    actions: [{op: delete, path: [description]}]", 1)
	p := load(t, base+inlineValidator(`def validate(config):
    if config.get("description") != "initial":
        return "description is required and immutable"
    return None`))
	d := validationDevice(t, p)
	s := attach(t, d)
	require.Contains(t, input(t, s, "save\n"), "description is required")
	input(t, s, "configure terminal\ndescription bad\n")
	require.Equal(t, "initial", d.Snapshot().Running["description"])
	require.NoError(t, d.Advance(time.Second))
	require.Contains(t, drain(s), "description is required")
	require.Equal(t, "initial", d.Snapshot().Running["description"])
}

func TestStarlarkFileAndInitialStateValidation(t *testing.T) {
	fsys := fstest.MapFS{"check.star": {Data: []byte("def validate(config):\n    return None\n")}}
	_, err := emulator.LoadProfile(strings.NewReader(profileYAML+"\nvalidation:\n  file: check.star\n"), fsys)
	require.NoError(t, err)
	cases := []struct{ section, want string }{
		{"validation: {}", "exactly one"},
		{"validation: {file: check.star, starlark: inline}", "exactly one"},
		{"validation: {file: ../check.star}", "invalid fixture path"},
		{"validation: {file: missing.star}", "validation file"},
		{"validation: {file: check.star, maxSteps: 1000001}", "maxSteps"},
		{"validation: {file: check.star, typo: true}", "field typo"},
		{strings.TrimSpace(inlineValidator("def broken(")), "compile validation"},
		{strings.TrimSpace(inlineValidator("value = 1")), "must define validate"},
		{strings.TrimSpace(inlineValidator("def validate(config, other):\n    return None")), "one positional"},
		{strings.TrimSpace(inlineValidator("def validate(config):\n    return 'invalid initial config'")), "initialState validation: invalid initial config"},
		{strings.TrimSpace(inlineValidator("load('forbidden.star', 'x')\ndef validate(config):\n    return None")), "load() is disabled"},
	}
	for _, tc := range cases {
		t.Run(tc.want, func(t *testing.T) {
			_, err := emulator.LoadProfile(strings.NewReader(profileYAML+"\n"+tc.section+"\n"), fsys)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestStarlarkInputGlobalsAndReturnContract(t *testing.T) {
	cases := []struct{ name, source, want string }{
		{"immutable input", `def validate(config):
    if config.get("description") == "bad":
        config["description"] = "corrupted"
    return None`, "frozen"},
		{"immutable nested input", `def validate(config):
    if config.get("description") == "bad":
        config["nested"].append("corrupted")
    return None`, "frozen"},
		{"immutable globals", `seen = []
def validate(config):
    if config.get("description") == "bad":
        seen.append("corrupted")
    return None`, "frozen"},
		{"wrong result", `def validate(config):
    if config.get("description") == "bad":
        return False
    return None`, "must return None"},
		{"empty rejection", `def validate(config):
    if config.get("description") == "bad":
        return ""
    return None`, "non-empty string"},
		{"execution error", `def validate(config):
    if config.get("description") == "bad":
        fail("rule failure")
    return None`, "rule failure"},
		{"bounded message", `def validate(config):
    if config.get("description") == "bad":
        return "x" * 4097
    return None`, "4096 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := load(t, profileYAML+inlineValidator(tc.source))
			cfg := map[string]any{"description": "bad", "nested": []any{"initial"}}
			err := p.ValidateConfiguration(cfg)
			require.ErrorContains(t, err, tc.want)
			var rejection *emulator.ValidationError
			require.False(t, errors.As(err, &rejection))
			require.Equal(t, "bad", cfg["description"])
			require.Equal(t, []any{"initial"}, cfg["nested"])
			d := validationDevice(t, p)
			s := attach(t, d)
			input(t, s, "configure terminal\n")
			require.Contains(t, input(t, s, "description bad\n"), "% Invalid input:")
			require.NoError(t, s.Err())
			require.Equal(t, "initial", d.Snapshot().Running["description"])
		})
	}
}

func TestStarlarkStepBudgetAndRecovery(t *testing.T) {
	source := `def validate(config):
    if config.get("description") == "slow":
        total = 0
        for i in range(1000000):
            total += i
    return None`
	p := load(t, profileYAML+strings.Replace(inlineValidator(source), "validation:\n", "validation:\n  maxSteps: 100\n", 1))
	err := p.ValidateConfiguration(map[string]any{"description": "slow"})
	require.ErrorContains(t, err, "too many steps")
	require.NoError(t, p.ValidateConfiguration(map[string]any{"description": "fast"}))
	_, err = emulator.LoadProfile(strings.NewReader(profileYAML+inlineValidator(`def expensive():
    total = 0
    for i in range(1000000):
        total += i
    return total
value = expensive()
def validate(config):
    return None`)), nil)
	require.ErrorContains(t, err, "initialize validation")
}

func TestStarlarkConfigurationTypesAndDeterminism(t *testing.T) {
	p := load(t, profileYAML+inlineValidator(`def validate(config):
    if "types" not in config:
        return None
    v = config["types"]
    if v != [None, True, 42, 1.5, "text", {"nested": []}]:
        return "types changed"
    if list(config.keys()) != ["a", "types", "z"]:
        return "nondeterministic key order"
    return None`))
	for i := 0; i < 10; i++ {
		require.NoError(t, p.ValidateConfiguration(map[string]any{"z": 1, "types": []any{nil, true, 42, 1.5, "text", map[string]any{"nested": []any{}}}, "a": 1}))
	}
	require.Error(t, p.ValidateConfiguration(map[string]any{"unsupported": make(chan int)}))
}

func TestStarlarkUniquenessEmptyDescriptionsAndSharedProfile(t *testing.T) {
	p := uniqueProfile(t)
	good := map[string]any{"interfaces": map[string]any{"Ethernet2": map[string]any{}, "Ethernet1": map[string]any{"description": ""}}}
	require.NoError(t, p.ValidateConfiguration(good))
	bad := map[string]any{"interfaces": map[string]any{"Ethernet2": map[string]any{"description": "dup"}, "Ethernet1": map[string]any{"description": "dup"}}}
	err := p.ValidateConfiguration(bad)
	var rejection *emulator.ValidationError
	require.ErrorAs(t, err, &rejection)
	require.Contains(t, rejection.Message, "Ethernet1 and Ethernet2")
	var wg sync.WaitGroup
	results := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if err := p.ValidateConfiguration(good); err != nil {
					results <- err
					return
				}
				if err := p.ValidateConfiguration(bad); err == nil {
					results <- fmt.Errorf("accepted duplicate")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		require.NoError(t, err)
	}
}
