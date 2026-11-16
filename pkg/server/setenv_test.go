package server

import (
	pb "github.com/annetutil/gnetcli/pkg/server/proto"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"testing"
)

func TestSetEnvInvalid(t *testing.T) {
	for _, directive := range []string{"", "SWITCH", "=value", `SWITCH="unterminated`, "SWITCH=%h", "SWITCH=%"} {
		t.Run(directive, func(t *testing.T) {
			app, err := NewAuthAppWithSSHConfig(authAppConfig{SshConfig: true}, zap.NewNop(), "Host *\n SetEnv "+directive+"\n")
			require.NoError(t, err)
			_, err = app.GetHostParams("switch.example.net", nil)
			require.ErrorContains(t, err, "SetEnv")
		})
	}
}

func TestSetEnvIgnored(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		app, err := NewAuthAppWithSSHConfig(authAppConfig{SshConfig: enabled}, zap.NewNop(), "Host *\n SetEnv SWITCH=%unsupported\n")
		require.NoError(t, err)
		params := &pb.HostParams{}
		if enabled {
			params.StreamerType = pb.StreamerType_StreamerType_telnet
		}
		_, err = app.GetHostParams("switch.example.net", params)
		require.NoError(t, err)
	}
}

func TestSetEnvValuesAndPrecedence(t *testing.T) {
	app, err := NewAuthAppWithSSHConfig(authAppConfig{SshConfig: true}, zap.NewNop(), `Host other.example.net
 SetEnv SWITCH=wrong
Host switch.example.net
 SetEnv SWITCH=%n SWITCH=ignored NOTE="two words" 'OTHER=more words' EMPTY= EQ=a=b PERCENT=%%n QUOTE="a\"b"
 SetEnv SECOND=ignored
Host *
 SetEnv SWITCH=wrong DEFAULT=ignored
`)
	require.NoError(t, err)
	params, err := app.GetHostParams("switch.example.net", nil)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"SWITCH": "switch.example.net", "NOTE": "two words", "OTHER": "more words", "EMPTY": "", "EQ": "a=b", "PERCENT": "%n", "QUOTE": `a"b`}, params.environment)
}

func TestSetEnvQuotedHash(t *testing.T) {
	for _, tc := range []struct{ name, assignment, want string }{
		{"spaces", `NOTE="a # b"`, "a # b"},
		{"single_quotes", `NOTE='a#b'`, "a#b"},
		{"escaped_quote", `NOTE="a\"#b"`, `a"#b`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, err := NewAuthAppWithSSHConfig(authAppConfig{SshConfig: true}, zap.NewNop(), "Host *\n SetEnv "+tc.assignment+" SWITCH=%n # real comment\n")
			require.NoError(t, err)
			params, err := app.GetHostParams("switch.example.net", nil)
			require.NoError(t, err)
			require.Equal(t, map[string]string{"NOTE": tc.want, "SWITCH": "switch.example.net"}, params.environment)
		})
	}
}
