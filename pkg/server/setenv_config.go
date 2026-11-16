package server

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kevinburke/ssh_config"
)

// Keep Include as an ordinary AST node so this reader, rather than Decode's
// eager loader, resolves relative paths in the correct user/system directory.
var setEnvInclude = regexp.MustCompile(`(?im)^([\t ]*)Include([\t =])`)

const setEnvIncludeKey = "GnetcliSetEnvInclude"

func sshConfigHome() string {
	if current, err := user.Current(); err == nil {
		return current.HomeDir
	}
	return os.Getenv("HOME")
}

func setEnvDirective(node *ssh_config.KV) string {
	// String preserves the original whitespace and the text which the lexer
	// incorrectly classified as a comment inside a quoted value.
	line := strings.TrimLeft(node.String(), " \t")
	value := strings.TrimLeft(line[len(node.Key):], " \t")
	if strings.HasPrefix(value, "=") {
		value = strings.TrimLeft(value[1:], " \t")
	}
	return value
}

func readSetEnvFile(path, host, base string, depth int) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	values, err := readSetEnvConfig(string(data), host, base, depth)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return values, nil
}

func readSetEnvConfig(source, host, base string, depth int) ([]string, error) {
	if depth > 5 {
		return nil, ssh_config.ErrDepthExceeded
	}
	source = setEnvInclude.ReplaceAllString(source, `${1}`+setEnvIncludeKey+`${2}`)
	config, err := ssh_config.Decode(strings.NewReader(source + "\n"))
	if err != nil {
		return nil, err
	}
	var values []string
	for _, block := range config.Hosts {
		if !block.Matches(host) {
			continue
		}
		for _, node := range block.Nodes {
			kv, ok := node.(*ssh_config.KV)
			if !ok {
				continue
			}
			if strings.EqualFold(kv.Key, "SetEnv") {
				values = append(values, setEnvDirective(kv))
			} else if strings.EqualFold(kv.Key, setEnvIncludeKey) {
				patterns, err := splitSetEnv(setEnvDirective(kv))
				if err != nil {
					return nil, fmt.Errorf("Include: %w", err)
				}
				seen := make(map[string]bool)
				for _, pattern := range patterns {
					if strings.HasPrefix(pattern, "~/") {
						pattern = filepath.Join(sshConfigHome(), pattern[2:])
					}
					if !filepath.IsAbs(pattern) {
						pattern = filepath.Join(base, pattern)
					}
					paths, err := filepath.Glob(pattern)
					if err != nil {
						return nil, fmt.Errorf("Include: %w", err)
					}
					for _, path := range paths {
						if seen[path] {
							continue
						}
						seen[path] = true
						included, err := readSetEnvFile(path, host, base, depth+1)
						if err != nil {
							return nil, err
						}
						values = append(values, included...)
					}
				}
			}
		}
	}
	return values, nil
}

func (r realSSHConfigReader) GetSetEnv(host string) ([]string, error) {
	userPath, systemPath := r.userConfigPath, r.systemConfigPath
	if userPath == "" {
		userPath = filepath.Join(sshConfigHome(), ".ssh", "config")
	}
	if systemPath == "" {
		systemPath = "/etc/ssh/ssh_config"
	}
	for _, path := range []string{userPath, systemPath} {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return nil, err
		}
		values, err := readSetEnvFile(path, host, filepath.Dir(path), 0)
		if err != nil || len(values) > 0 {
			return values, err
		}
	}
	return nil, nil
}

func (r parsedSSHConfigReader) GetSetEnv(host string) ([]string, error) {
	return readSetEnvConfig(r.source, host, filepath.Join(sshConfigHome(), ".ssh"), 0)
}

func (m mockSSHConfigReader) GetSetEnv(host string) ([]string, error) {
	return m.GetAll(host, "SetEnv"), nil
}
