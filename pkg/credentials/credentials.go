/*
Package credentials describes credentials.
*/
package credentials

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/user"

	"github.com/kevinburke/ssh_config"
	"github.com/mitchellh/go-homedir"
	"go.uber.org/zap"
)

type Credentials interface {
	GetUsername() (string, error)
	GetPasswords(ctx context.Context) []Secret
	GetPrivateKeys() [][]byte
	GetPassphrase() Secret
	GetAgentSocket() string
}

type SimpleCredentials struct {
	username    string
	passwords   []Secret
	privKeys    [][]byte
	passphrase  Secret
	agentSocket string
	logger      *zap.Logger
}

type CredentialsOption func(*SimpleCredentials)

func NewSimpleCredentials(opts ...CredentialsOption) *SimpleCredentials {
	cred := &SimpleCredentials{
		username:    "",
		passwords:   []Secret{},
		passphrase:  "",
		agentSocket: "",
		logger:      zap.NewNop(),
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

func WithSSHAgentSocket(agentSocket string) CredentialsOption {
	return func(h *SimpleCredentials) {
		h.agentSocket = agentSocket
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

func (m SimpleCredentials) GetPasswords(ctx context.Context) []Secret {
	return m.passwords
}

func (m SimpleCredentials) GetPassphrase() Secret {
	return m.passphrase
}

func (m SimpleCredentials) GetPrivateKeys() [][]byte {
	return m.privKeys
}

func (m SimpleCredentials) GetAgentSocket() string {
	return m.agentSocket
}

// GetDefaultAgentSocket returns default ssh authentication agent socket (read from SSH_AUTH_SOCK env)
func GetDefaultAgentSocket() string {
	return os.Getenv("SSH_AUTH_SOCK")
}

// GetLogin tries to get sudo user from env, falling back to current user
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

// GetUsernameFromConfig extracts User keyword value for given host from default ssh config.
func GetUsernameFromConfig(host string) string {
	return ssh_config.Get(host, "User")
}

// GetAgentSocketFromConfig computes SSH authentication agent socket path using default ssh config's IdentityAgent and ForwardAgent keywords.
// IdentityAgent value supports tilde syntax, but it doesn't support %d, %h, %l and %r.
func GetAgentSocketFromConfig(host string) (string, error) {
	// TODO:
	// IdentityAgent and IdentityFile accept the tokens %%, %d, %h, %l, %r, and %u.
	// use ExpandTokens()
	ia, err := ssh_config.GetStrict(host, "IdentityAgent")
	if err != nil {
		return "", err
	}
	if ia == "none" {
		return "", nil
	}
	expandedIa, err := homedir.Expand(ia)
	if err != nil {
		return "", err
	}
	if expandedIa == "SSH_AUTH_SOCK" || len(expandedIa) == 0 {
		return GetDefaultAgentSocket(), nil
	}
	if ssh_config.Get(host, "ForwardAgent") == "yes" {
		return GetDefaultAgentSocket(), nil
	}

	return expandedIa, nil
}

// GetPrivateKeysFromConfig tries to extract PrivateKeys from default config's IdentityFiles specified for provided host.
// IdentityFile value supports tilde syntax, but it doesn't support %d, %u, %l, %h and %r.
func GetPrivateKeysFromConfig(host string) ([][]byte, error) {
	identityFiles := ssh_config.GetAll(host, "IdentityFile")
	privKeys := make([][]byte, 0, len(identityFiles))
	for _, v := range identityFiles {
		// todo:
		// IdentityAgent and IdentityFile accept the tokens %%, %d, %h, %l, %r, and %u.
		expandedPath, err := homedir.Expand(v)
		if err != nil {
			return nil, fmt.Errorf("failed to expand path of identity file %s: %w", v, err)
		}
		content, err := os.ReadFile(expandedPath)
		if err != nil && isSSHConfigMadeUpDefaultFileError(identityFiles, err) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read identity file %s: %w", v, err)
		}
		privKeys = append(privKeys, content)
	}
	return privKeys, nil
}

// isSSHConfigMadeUpDefaultFileError checks if given error occurred because
// ssh_config lib made up a default value for IdentityFile due to it's absence in config
func isSSHConfigMadeUpDefaultFileError(identityFiles []string, err error) bool {
	if len(identityFiles) == 1 && identityFiles[0] == "~/.ssh/identity" && errors.Is(err, fs.ErrNotExist) {
		return true
	}
	return false
}
