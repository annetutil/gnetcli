/*
Package credentials describes credentials.
*/
package credentials

import (
	"fmt"
	"os"
	"os/user"

	"go.uber.org/zap"
)

type Credentials interface {
	GetUsername() (string, error)
	GetPasswords() []Secret
	GetPrivateKey() []byte
	GetPassphrase() Secret
	AgentEnabled() bool
}

type SimpleCredentials struct {
	username   string
	passwords  []Secret
	privKey    []byte
	passphrase Secret
	agent      bool
	logger     *zap.Logger
}

type CredentialsOption func(*SimpleCredentials)

func NewSimpleCredentials(opts ...CredentialsOption) *SimpleCredentials {
	cred := &SimpleCredentials{
		username:   "",
		passwords:  []Secret{},
		passphrase: "",
		agent:      false,
		logger:     zap.NewNop(),
	}
	for _, opt := range opts {
		opt(cred)
	}
	return cred
}

func WithUsername(username string) CredentialsOption {
	return func(h *SimpleCredentials) {
		h.username = username
	}
}

func WithPassword(password Secret) CredentialsOption {
	return func(h *SimpleCredentials) {
		h.passwords = []Secret{password}
	}
}

func WithPasswords(password []Secret) CredentialsOption {
	return func(h *SimpleCredentials) {
		h.passwords = password
	}
}

func WithLogger(logger *zap.Logger) CredentialsOption {
	return func(h *SimpleCredentials) {
		h.logger = logger
	}
}

func WithPrivateKey(key []byte) CredentialsOption {
	return func(h *SimpleCredentials) {
		h.privKey = key
	}
}

func WithPassphrase(passphrase Secret) CredentialsOption {
	return func(h *SimpleCredentials) {
		h.passphrase = passphrase
	}
}

func WithSSHAgent() CredentialsOption {
	return func(h *SimpleCredentials) {
		h.agent = true
	}
}

func (m SimpleCredentials) GetUsername() (string, error) {
	if len(m.username) != 0 {
		return m.username, nil
	}
	currentUser, err := user.Current()
	if err == nil {
		return currentUser.Username, nil
	}
	return "", fmt.Errorf("unable to get username")
}

func (m SimpleCredentials) GetPasswords() []Secret {
	return m.passwords
}

func (m SimpleCredentials) GetPassphrase() Secret {
	return m.passphrase
}

func (m SimpleCredentials) GetPrivateKey() []byte {
	return m.privKey
}

func (m SimpleCredentials) AgentEnabled() bool {
	return m.agent
}

func GetLogin() string {
	login := os.Getenv("SUDO_USER")
	if login == "" {
		u, err := user.Current()
		if err != nil {
			return ""
		}
		return u.Username
	}
	return login
}

type Secret string

func (Secret) String() string {
	return "..."
}

func (Secret) MarshalText() ([]byte, error) {
	return []byte("..."), nil
}

func (m Secret) Value() string {
	return string(m)
}
