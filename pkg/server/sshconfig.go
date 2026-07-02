package server

import "github.com/kevinburke/ssh_config"

// sshConfigReader is an interface for reading SSH config values
type sshConfigReader interface {
	Get(host, key string) string
}

// realSSHConfigReader reads from actual SSH config file
type realSSHConfigReader struct{}

func (r realSSHConfigReader) Get(host, key string) string {
	return ssh_config.Get(host, key)
}

// mockSSHConfigReader for testing
type mockSSHConfigReader struct {
	configs map[string]map[string]string
}

func (m mockSSHConfigReader) Get(host, key string) string {
	if hostConfig, ok := m.configs[host]; ok {
		return hostConfig[key]
	}
	return ""
}
