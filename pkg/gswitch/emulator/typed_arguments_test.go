package emulator_test

import (
	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

const typedProfile = `apiVersion: cli-emulator/v1
name: typed
initialMode: exec
abbreviations: true
modes:
  exec: {prompt: "sw#"}
commands:
  - id: mode
    modes: [exec]
    syntax: "mode <value:word>"
    arguments:
      value: {enum: [up, down]}
    actions: []
  - id: number
    modes: [exec]
    syntax: "number <value:uint>"
    arguments:
      value: {minValue: 10, maxValue: 20}
    actions: []
  - id: addr
    modes: [exec]
    syntax: "addr <value:ip>"
    actions: []
  - id: addr4
    modes: [exec]
    syntax: "addr4 <value:ipv4>"
    actions: []
  - id: addr6
    modes: [exec]
    syntax: "addr6 <value:ipv6>"
    actions: []
  - id: mac
    modes: [exec]
    syntax: "mac <value:mac>"
    actions: []
  - id: exit
    modes: [exec]
    syntax: exit
    abbreviations: false
    actions: []
`

func TestTypedArgumentsAndCommandAbbreviations(t *testing.T) {
	p := load(t, typedProfile)
	for _, line := range []string{"mode up", "mode down", "number 10", "number 20", "addr 192.0.2.1", "addr 2001:db8::1", "addr4 192.0.2.1", "addr6 2001:db8::1", "mac 02:00:00:00:00:01", "mac 0200.0000.0001", "exit", "n 15"} {
		_, err := p.Parse("exec", line)
		require.NoError(t, err, line)
	}
	for _, line := range []string{"mode u", "mode UP", "number 9", "number 21", "number 4294967296", "addr hostname", "addr4 2001:db8::1", "addr6 192.0.2.1", "addr fe80::1%eth0", "mac 02:00:00:00:00:01:02:03", "mac nope", "ex"} {
		_, err := p.Parse("exec", line)
		require.Error(t, err, line)
		require.Empty(t, p.Help("exec", line+" "), line)
	}
	require.Equal(t, []string{"down", "up"}, p.Help("exec", "mode "))
	require.Equal(t, "mode up ", p.Complete("exec", "mode U").Line)
	require.Equal(t, "exit ", p.Complete("exec", "ex").Line)
	require.Equal(t, []string{"<value:ipv4>"}, p.Help("exec", "addr4 192."))
	for _, tc := range []struct{ old, value string }{
		{"maxValue: 20", "maxValue: 5"}, {"minValue: 10", "minValue: -1"}, {"maxValue: 20", "maxValue: 4294967296"},
		{"enum: [up, down]", "enum: [up, up]"}, {"enum: [up, down]", `enum: ["bad word"]`},
		{"<value:word>", "<value:ip>"}, {"<value:uint>", "<value:word>"},
		{"enum: [up, down]", "enum: [up, down]\n    completions:\n      value: {statePath: [values]}"},
	} {
		_, err := emulator.LoadProfile(strings.NewReader(strings.Replace(typedProfile, tc.old, tc.value, 1)), nil)
		require.Error(t, err, tc)
	}
}
