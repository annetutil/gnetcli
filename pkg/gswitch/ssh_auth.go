package gswitch

import (
	"bytes"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// LoadAuthorizedKeysFromFile parses an OpenSSH authorized_keys file.
func LoadAuthorizedKeysFromFile(path string) ([]ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseAuthorizedKeys(data, path)
}

// ParseAuthorizedKeys parses authorized_keys file contents (path is only for errors).
func ParseAuthorizedKeys(data []byte, pathHint string) ([]ssh.PublicKey, error) {
	var keys []ssh.PublicKey
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", pathHint, err)
		}
		keys = append(keys, pubKey)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid keys in %s", pathHint)
	}
	return keys, nil
}
