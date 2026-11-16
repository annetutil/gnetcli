package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func writeSetEnvConfig(t *testing.T, path, source string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0700))
	require.NoError(t, os.WriteFile(path, []byte(source), 0600))
}

func TestFileSetEnvQuotedHashAndIncludes(t *testing.T) {
	dir := t.TempDir()
	userPath := filepath.Join(dir, "user", "config")
	systemPath := filepath.Join(dir, "system", "ssh_config")
	writeSetEnvConfig(t, userPath, "Host switch.example.net\n Include conf.d/*.conf\n SetEnv NOTE=fallback\nHost ignored\n Include [\n")
	writeSetEnvConfig(t, filepath.Join(dir, "user", "conf.d", "10-first.conf"), "Host *.example.net\n SetEnv NOTE=\"a # b\" SWITCH=%n # actual comment\n")
	writeSetEnvConfig(t, filepath.Join(dir, "user", "conf.d", "20-later.conf"), "SetEnv NOTE=later\n")
	writeSetEnvConfig(t, systemPath, "Include conf.d/*.conf\n")
	writeSetEnvConfig(t, filepath.Join(dir, "system", "conf.d", "settings.conf"), "SetEnv NOTE='system # value'\n")
	app := authApp{config: authAppConfig{SshConfig: true}, sshConfig: realSSHConfigReader{userConfigPath: userPath, systemConfigPath: systemPath}}
	values, err := app.getSetEnv("switch.example.net")
	require.NoError(t, err)
	require.Equal(t, map[string]string{"NOTE": "a # b", "SWITCH": "switch.example.net"}, values)
	values, err = app.getSetEnv("system.example.net")
	require.NoError(t, err)
	require.Equal(t, map[string]string{"NOTE": "system # value"}, values)
}

func TestParsedSetEnvQuotedHashInInclude(t *testing.T) {
	path := filepath.Join(t.TempDir(), "included.conf")
	writeSetEnvConfig(t, path, "Host *.example.net\n SetEnv NOTE=\"a#b\" SWITCH=%n # actual comment\n")
	app, err := NewAuthAppWithSSHConfig(authAppConfig{SshConfig: true}, zap.NewNop(), "Host switch.example.net\n Include "+path+"\n SetEnv NOTE=later\n")
	require.NoError(t, err)
	params, err := app.GetHostParams("switch.example.net", nil)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"NOTE": "a#b", "SWITCH": "switch.example.net"}, params.environment)
}

func TestFileSetEnvIncludeErrors(t *testing.T) {
	for _, tc := range []struct{ name, source, want string }{
		{"cycle", "Include config\n", "max recurse depth"},
		{"bad_glob", "Include [\n", "syntax error"},
		{"unreadable_include", "Include .\n", "directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config")
			writeSetEnvConfig(t, path, tc.source)
			app := authApp{config: authAppConfig{SshConfig: true}, sshConfig: realSSHConfigReader{userConfigPath: path, systemConfigPath: filepath.Join(t.TempDir(), "absent")}}
			_, err := app.getSetEnv("switch.example.net")
			require.ErrorContains(t, err, tc.want)
		})
	}
}
