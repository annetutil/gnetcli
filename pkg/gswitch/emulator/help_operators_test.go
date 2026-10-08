package emulator_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/annetutil/gnetcli/pkg/gswitch/emulator"
	"github.com/stretchr/testify/require"
)

const infoCenterHelp = "  channel     Set the name of information channel\n" +
	"  statistics  Information statistics data of all modules\n" +
	"  |           Matching output\n" +
	"  >           Redirect the output to a file\n" +
	"  >>          Redirect the output to a file in append mode\n" +
	"  <cr>\n"

func loadHuaweiHelpProfile(t *testing.T) *emulator.Profile {
	t.Helper()
	root, err := os.OpenRoot("../../../examples/gswitch")
	require.NoError(t, err)
	defer root.Close()
	f, err := root.Open("huawei.yaml")
	require.NoError(t, err)
	defer f.Close()
	p, err := emulator.LoadProfile(f, root.FS())
	require.NoError(t, err)
	return p
}

func TestHuaweiInfoCenterHelpTranscript(t *testing.T) {
	p := loadHuaweiHelpProfile(t)
	require.Equal(t, infoCenterHelp, p.RenderHelp("user", "display info-center "))
	require.NotContains(t, p.Help("user", "display "), "<cr>")
	require.NotContains(t, p.Help("user", "display "), ">")
	require.Equal(t, []string{"info-center"}, p.Help("user", "display info"))
	require.Equal(t, []string{"<file:word>"}, p.Help("user", "display info-center > "))
	require.Equal(t, []string{"<file:word>"}, p.Help("user", "display info-center >> "))
	require.Equal(t, []string{"<filter:rest>"}, p.Help("user", "display info-center | "))
	d := validationDevice(t, p)
	s, err := d.Attach(emulator.AttachOptions{Authenticated: true, Username: "test"})
	require.NoError(t, err)
	require.Equal(t, "<sw1>", drain(s))
	before := d.Snapshot()
	require.Equal(t, "display info-center ?\r\n"+strings.ReplaceAll(infoCenterHelp, "\n", "\r\n")+"\r\n<sw1>display info-center ", input(t, s, "display info-center ?"))
	require.Equal(t, before, d.Snapshot())
	// The space/input buffer is restored; '?' was not inserted into the command.
	require.Equal(t, "\r\nError: display info-center is not implemented in this emulator profile.\r\n<sw1>", input(t, s, "\n"))
	require.NoError(t, s.Err())
}

func TestHelpExecutableParentCanHaveChildren(t *testing.T) {
	text := strings.Replace(helpProfile, "    echoQuestion: true", "    echoQuestion: true\n    tailOrder: [\"<cr>\"]\n    blankLineAfter: true", 1)
	text += `  - id: display-parent
    modes: [user]
    syntax: display
    help: [Display current system information]
    actions: [{op: output, text: "PARENT-OUTPUT\n"}]
`
	p := load(t, text)
	require.True(t, strings.HasSuffix(p.RenderHelp("user", "display "), "  <cr>\n"))
	require.Contains(t, p.Help("user", "display "), "version")
	match, err := p.Parse("user", "display")
	require.NoError(t, err)
	require.Equal(t, "display-parent", match.Command)
	d := validationDevice(t, p)
	s, err := d.Attach(emulator.AttachOptions{Authenticated: true})
	require.NoError(t, err)
	drain(s)
	out := input(t, s, "display ?")
	require.Contains(t, out, "  <cr>\r\n\r\n<sw>display ")
	require.NotContains(t, out, "PARENT-OUTPUT")
	require.Equal(t, "\r\nPARENT-OUTPUT\r\n<sw>", input(t, s, "\n"))
	require.Contains(t, input(t, s, "display version\n"), "VERSION-RESULT")
}

func TestHelpNestedWidthAndTailValidation(t *testing.T) {
	text := strings.Replace(helpProfile, "    keywordWidth: 18", "    keywordWidth: 18\n    nestedKeywordWidth: 0", 1)
	p := load(t, text)
	require.Equal(t, "  display           Display current system information\n", p.RenderHelp("user", "disp"))
	require.Equal(t, "  version  Display system version\n", p.RenderHelp("user", "display v"))
	for _, setting := range []string{
		"nestedKeywordWidth: -1", "nestedKeywordWidth: 257",
		"tailOrder: [\"|\", \"|\"]", "tailOrder: [\"bad token\"]", "tailOrder: [\"\"]",
	} {
		_, err := emulator.LoadProfile(strings.NewReader(strings.Replace(helpProfile, "    keywordWidth: 18", "    keywordWidth: 18\n    "+setting, 1)), nil)
		require.Error(t, err, setting)
	}
}

func TestHuaweiInfoCenterOperatorsAreExplicitUnsupportedFixtures(t *testing.T) {
	p := loadHuaweiHelpProfile(t)
	d := validationDevice(t, p)
	s, err := d.Attach(emulator.AttachOptions{Authenticated: true})
	require.NoError(t, err)
	drain(s)
	before := d.Snapshot().Running
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.txt")
	missing := filepath.Join(dir, "missing.txt")
	require.NoError(t, os.WriteFile(existing, []byte("unchanged"), 0600))
	for _, tc := range []struct{ command, id string }{
		{"display info-center > " + existing, "display-info-center-redirect"},
		{"display info-center >> " + existing, "display-info-center-append"},
		{"display info-center > " + missing, "display-info-center-redirect"},
		{"display info-center | include something", "display-info-center-filter"},
	} {
		match, err := p.Parse("user", tc.command)
		require.NoError(t, err)
		require.Equal(t, tc.id, match.Command)
		require.Contains(t, input(t, s, tc.command+"\n"), "not implemented in this emulator profile")
		require.NoError(t, s.Err())
	}
	require.Equal(t, before, d.Snapshot().Running)
	data, err := os.ReadFile(existing)
	require.NoError(t, err)
	require.Equal(t, "unchanged", string(data))
	_, err = os.Stat(missing)
	require.True(t, os.IsNotExist(err))
	for _, incomplete := range []string{"display info-center >", "display info-center >>", "display info-center |"} {
		_, err := p.Parse("user", incomplete)
		var pe *emulator.ParseError
		require.ErrorAs(t, err, &pe)
		require.Equal(t, "incomplete", pe.Kind)
	}
}
