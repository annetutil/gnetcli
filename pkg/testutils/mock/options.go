package mock

import "go.uber.org/zap"

var defaultPrivateKey = []byte(`
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
`)

type MockSSHServerOption func(*MockSSHServer)

func WithUser(username string) MockSSHServerOption {
	return func(m *MockSSHServer) {
		m.username = username
	}
}

func WithLogger(logger *zap.Logger) MockSSHServerOption {
	return func(m *MockSSHServer) {
		m.log = logger
	}
}

func WithPassword(password string) MockSSHServerOption {
	return func(m *MockSSHServer) {
		m.password = password
	}
}

func WithPrivateKey(privateKey []byte) MockSSHServerOption {
	return func(m *MockSSHServer) {
		m.privateKey = privateKey
	}
}

func WithNetwork(network string) MockSSHServerOption {
	return func(m *MockSSHServer) {
		m.network = network
	}
}
