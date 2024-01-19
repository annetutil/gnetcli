/*
Package credentials describes credentials.
*/
package credentials

import (
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
	GetPasswords() []Secret
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

func (m SimpleCredentials) GetPasswords() []Secret {
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

func GetDefaultAgentSocket() string {
	return os.Getenv("SSH_AUTH_SOCK")
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

// todo:
// IdentityAgent and IdentityFile accept the tokens %%, %d, %h, %l, %r, and %u.
func GetAgentSocketFromConfig(host string) string {
	identityAgent := ssh_config.Get(host, "IdentityAgent")
	if identityAgent == "none" {
		return ""
	}
	if identityAgent == "SSH_AUTH_SOCK" {
		return GetDefaultAgentSocket()
	}
	if identityAgent == "" && ssh_config.Get(host, "ForwardAgent") == "yes" {
		return GetDefaultAgentSocket()
	}

	return identityAgent
}

func GetPrivateKeysFromConfig(host string) ([][]byte, error) {
	identityFiles, err := ssh_config.GetAllStrict(host, "IdentityFile")
	if err != nil {
		return nil, err
	}
	privKeys := make([][]byte, 0, len(identityFiles))
	for _, v := range identityFiles {
		// todo: check escape characters processing:
		// The file name may use the tilde syntax to refer to a user's home directory or one of
		//          the following escape characters: ‘%d’ (local user's home directory), ‘%u’ (local
		//          user name), ‘%l’ (local host name), ‘%h’ (remote host name) or ‘%r’ (remote user
		//          name)
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

// when IdentityFile is not set in ssh config,
// ssh_config lib makes up a default value `~/.ssh/identity`, which may result in not exist error
func isSSHConfigMadeUpDefaultFileError(identityFiles []string, err error) bool {
	if len(identityFiles) == 1 && identityFiles[0] == "~/.ssh/identity" && errors.Is(err, fs.ErrNotExist) {
		return true
	}
	return false
}
