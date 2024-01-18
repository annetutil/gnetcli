/*
Package credentials describes credentials.
*/
package credentials

import (
	"fmt"
	"os"
	"os/user"

	"github.com/kevinburke/ssh_config"
	"go.uber.org/zap"
)

type Credentials interface {
	GetUsername() (string, error)
	GetPasswords() []Secret
	GetPrivateKeys() [][]byte
	GetPassphrase() Secret
	AgentEnabled() bool
}

type SimpleCredentials struct {
	username   string
	passwords  []Secret
	privKeys   [][]byte
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
		h.privKeys = [][]byte{key}
	}
}

func WithPrivateKeys(key [][]byte) CredentialsOption {
	return func(h *SimpleCredentials) {
		h.privKeys = key
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

func (m SimpleCredentials) GetPrivateKeys() [][]byte {
	return m.privKeys
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

func GetUsernameFromConfig(host string) string {
	return ssh_config.Get(host, "User")
}

func GetAgentEnabledFromConfig(host string) bool {
	return ssh_config.Get(host, "ForwardAgent") == "yes"
}

func GetPrivateKeysFromConfig(host string) ([][]byte, error) {
	identityFiles := ssh_config.GetAll(host, "IdentityFile")
	privKeys := make([][]byte, 0, len(identityFiles))
	// todo: check escape characters processing:
	// The file name may use the tilde syntax to refer to a user's home directory or one of
	//          the following escape characters: ‘%d’ (local user's home directory), ‘%u’ (local
	//          user name), ‘%l’ (local host name), ‘%h’ (remote host name) or ‘%r’ (remote user
	//          name)
	for _, v := range identityFiles {
		content, err := os.ReadFile(v)
		if err != nil {
			return nil, fmt.Errorf("failed to read identity file %s: %w", v, err)
		}
		privKeys = append(privKeys, content)
	}
	return privKeys, nil
}
