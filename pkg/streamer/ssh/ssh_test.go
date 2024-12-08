package ssh

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/annetutil/gnetcli/pkg/streamer"
)

func TestSSHInterface(t *testing.T) {
	val := Streamer{}

	_, ok := interface{}(&val).(streamer.Connector)
	assert.True(t, ok, "not a Connector interface")
}

func TestEndpoint_Addr(t *testing.T) {
	tests := []struct {
		name     string
		endpoint Endpoint
		expected string
	}{
		{
			name:     "default",
			endpoint: Endpoint{Host: "localhost", Port: 22},
			expected: "localhost:22",
		},
		{
			name:     "custom port",
			endpoint: Endpoint{Host: "example.com", Port: 2222},
			expected: "example.com:2222",
		},
		{
			name:     "IPv6",
			endpoint: Endpoint{Host: "2001:db8::1", Port: 22},
			expected: "[2001:db8::1]:22",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.endpoint.Addr())
		})
	}
}
