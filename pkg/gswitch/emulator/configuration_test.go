package emulator_test

import (
	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

const sectionProfile = `apiVersion: cli-emulator/v1
name: sections
initialMode: exec
modes:
  exec: {prompt: "sw#"}
initialState:
  hostname: sw
  interfaces:
    Eth2: {description: two}
    Eth1: {description: one, addresses: {v4: 192.0.2.1}}
configuration:
  id: root
  children:
    - id: system
      lines: ['hostname {{ .Value.hostname }}']
      footer: '#'
    - id: interfaces
      path: [interfaces]
      each: true
      header: 'interface {{ .Key }}'
      lines: ['{{ if index .Value "description" }} description {{ .Value.description }}{{ end }}']
      children:
        - id: addresses
          path: [addresses]
          each: true
          lines: [' address {{ .Key }} {{ .Value }} on {{ index .Keys "interfaces" }}']
      footer: '#'
commands:
  - id: show
    modes: [exec]
    syntax: show running
    actions: [{op: render-config, name: root}]
`

func TestDeclarativeConfigurationTreeAndSelections(t *testing.T) {
	p := load(t, sectionProfile)
	state := map[string]any{"hostname": "changed", "interfaces": map[string]any{"Eth2": map[string]any{"description": "two"}, "Eth1": map[string]any{"description": "one", "addresses": map[string]any{"v4": "192.0.2.1"}}}}
	out, err := p.RenderConfiguration("root", nil, state)
	require.NoError(t, err)
	require.Equal(t, "hostname changed\n#\ninterface Eth1\n description one\n address v4 192.0.2.1 on Eth1\n#\ninterface Eth2\n description two\n#\n", out)
	out, err = p.RenderConfiguration("addresses", map[string]string{"interfaces": "Eth1"}, state)
	require.NoError(t, err)
	require.Equal(t, " address v4 192.0.2.1 on Eth1\n", out)
	out, err = p.RenderConfiguration("interfaces", map[string]string{"interfaces": "New"}, state)
	require.NoError(t, err)
	require.Equal(t, "interface New\n#\n", out)
	require.Equal(t, "changed", state["hostname"])
	for _, tc := range []struct {
		name string
		keys map[string]string
	}{{"absent", nil}, {"root", map[string]string{"system": "invalid"}}} {
		_, err = p.RenderConfiguration(tc.name, tc.keys, state)
		require.Error(t, err)
	}
	d := validationDevice(t, p)
	s := attach(t, d)
	before := d.Snapshot()
	out = input(t, s, "show running\n")
	require.Contains(t, out, "hostname sw\r\n")
	require.Equal(t, before, d.Snapshot())
	_, err = p.RenderConfiguration("root", nil, map[string]any{"hostname": "large", "interfaces": map[string]any{"Eth1": map[string]any{"description": strings.Repeat("x", 1<<20)}}})
	require.Error(t, err)
}

func TestConfigurationDeclarationValidation(t *testing.T) {
	for _, tc := range []struct{ old, value string }{
		{"id: interfaces", "id: root"}, {"path: [interfaces]", `path: [""]`}, {"name: root}", "name: missing}"}, {"name: root}", "name: root, config: unknown}"},
		{"name: root}", "name: root, context: {system: key}}"}, {"hostname {{ .Value.hostname }}", "{{ broken"},
	} {
		_, err := emulator.LoadProfile(strings.NewReader(strings.Replace(sectionProfile, tc.old, tc.value, 1)), nil)
		require.Error(t, err, tc)
	}
}
