package server

import "github.com/kevinburke/ssh_config"

// sshConfigReader is an interface for reading SSH config values.
type sshConfigReader interface {
	Get(host, key string) string
	GetAll(host, key string) []string
}

// realSSHConfigReader reads from actual SSH config file.
type realSSHConfigReader struct{}

func (r realSSHConfigReader) Get(host, key string) string {
	return ssh_config.Get(host, key)
}

func (r realSSHConfigReader) GetAll(host, key string) []string {
	return ssh_config.GetAll(host, key)
}

type parsedSSHConfigReader struct {
	config *ssh_config.Config
}

func (r parsedSSHConfigReader) Get(host, key string) string {
	value, err := r.config.Get(host, key)
	if err != nil {
		return ""
	}
	return value
}

func (r parsedSSHConfigReader) GetAll(host, key string) []string {
	value, err := r.config.GetAll(host, key)
	if err != nil {
		return nil
	}
	return value
}

// mockSSHConfigReader for testing.
type mockSSHConfigReader struct {
	configs map[string]map[string]string
}

func (m mockSSHConfigReader) Get(host, key string) string {
	if hostConfig, ok := m.configs[host]; ok {
		return hostConfig[key]
	}
	return ""
}

func (m mockSSHConfigReader) GetAll(host, key string) []string {
	value := m.Get(host, key)
	if len(value) == 0 {
		return nil
	}
	return []string{value}
}
