package server

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/annetutil/gnetcli/internal/tssh"
)

// getSetEnv uses the first matching directive, as OpenSSH does. The supported
// tokens are %n (the original client hostname) and %% (a literal percent).
func (m authApp) getSetEnv(host string) (map[string]string, error) {
	if !m.config.SshConfig || m.sshConfig == nil {
		return nil, nil
	}
	directives, err := m.sshConfig.GetSetEnv(host)
	if err != nil {
		return nil, fmt.Errorf("SetEnv for %q: %w", host, err)
	}
	if len(directives) == 0 {
		return nil, nil
	}
	words, err := splitSetEnv(directives[0])
	if err != nil {
		return nil, fmt.Errorf("SetEnv for %q: %w", host, err)
	}
	params := tssh.NewSshParam("", "", "", nil, tssh.WithOriginalHost(host))
	result := make(map[string]string, len(words))
	for _, word := range words {
		name, value, ok := strings.Cut(word, "=")
		if !ok || name == "" || strings.IndexFunc(name, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return nil, fmt.Errorf("SetEnv for %q: expected NAME=VALUE with a nonempty name", host)
		}
		if _, exists := result[name]; exists {
			continue
		}
		expanded, err := tssh.ExpandTokens(value, params, "%n")
		if err != nil {
			return nil, fmt.Errorf("SetEnv for %q: %w", host, err)
		}
		result[name] = expanded
	}
	return result, nil
}

// splitSetEnv handles quoted spaces and escaped quotes without running a shell.
func splitSetEnv(value string) ([]string, error) {
	var words []string
	var word strings.Builder
	var quote byte
	started := false
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if ch == '\\' && i+1 < len(value) && strings.ContainsRune("\\\"' \t", rune(value[i+1])) {
			i++
			word.WriteByte(value[i])
			started = true
		} else if quote != 0 {
			if ch == quote {
				quote = 0
			} else {
				word.WriteByte(ch)
			}
		} else if ch == '"' || ch == '\'' {
			quote = ch
			started = true
		} else if ch == '#' && !started {
			break
		} else if ch == ' ' || ch == '\t' {
			if started {
				words = append(words, word.String())
				word.Reset()
				started = false
			}
		} else {
			word.WriteByte(ch)
			started = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quote")
	}
	if started {
		words = append(words, word.String())
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("expected NAME=VALUE")
	}
	return words, nil
}
