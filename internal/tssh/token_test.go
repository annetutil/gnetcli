package tssh

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExpandTokensOriginalHost(t *testing.T) {
	param := NewSshParam("gateway.example.net", "8022", "tester", nil, WithOriginalHost("switch.example.net"))
	value, err := ExpandTokens("%n via %h:%p as %r %%", param, "%nhpr")
	require.NoError(t, err)
	require.Equal(t, "switch.example.net via gateway.example.net:8022 as tester %", value)
}

func TestExpandTokensOriginalHostBoundaries(t *testing.T) {
	for _, tc := range []struct{ name, input, host, tokens, want, wantError string }{
		{"literal_percent", "%%n %n", "switch%n", "%n", "%n switch%n", ""},
		{"not_allowed", "%n", "switch", "%h", "", "not supported"},
		{"unknown", "%x", "switch", "%n", "", "not supported"},
		{"trailing_percent", "%", "switch", "%n", "", "invalid"},
		{"unsafe_original", "%n", "switch;id", "%n", "", "invalid characters"},
		{"missing_original", "%n", "", "%n", "", "original hostname is not available"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			param := NewSshParam("gateway.example.net", "22", "tester", nil, WithOriginalHost(tc.host))
			value, err := ExpandTokens(tc.input, param, tc.tokens)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, value)
		})
	}
}

func TestExpandTokensWithoutOriginalHost(t *testing.T) {
	param := NewSshParam("gateway.example.net", "22", "tester", nil)
	value, err := ExpandTokens("%h-%p-%r-%%", param, "%hpr")
	require.NoError(t, err)
	require.Equal(t, "gateway.example.net-22-tester-%", value)
	_, err = ExpandTokens("%n", param, "%n")
	require.ErrorContains(t, err, "original hostname is not available")
}
