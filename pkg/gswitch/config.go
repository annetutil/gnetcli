package gswitch

import (
	"bufio"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// RunningConfig is the in-memory device configuration shared by CLI sessions.
// Its zero value is ready for use. CLI modes and selected interfaces are NOT
// shared: each connection keeps its own CLIState.
type RunningConfig struct {
	mu         sync.RWMutex
	global     map[string]struct{}
	interfaces map[string]map[string]struct{}
}

// NewRunningConfig returns an empty device configuration.
func NewRunningConfig() *RunningConfig { return &RunningConfig{} }

// Load replaces the configuration from a Cisco-style fragment: global lines,
// interface blocks with indented child lines, and optional !/end separators.
// A malformed fragment leaves the previous configuration intact.
func (c *RunningConfig) Load(text string) error {
	global := make(map[string]struct{})
	interfaces := make(map[string]map[string]struct{})
	scope := ""
	scanner := bufio.NewScanner(strings.NewReader(text))
	for line := 1; scanner.Scan(); line++ {
		raw := scanner.Text()
		command := strings.TrimSpace(raw)
		if command == "" {
			continue
		}
		if command == "!" || command == "end" {
			scope = ""
			continue
		}
		indented := raw[0] == ' ' || raw[0] == '\t'
		if !indented {
			scope = ""
			if command == "interface" || strings.HasPrefix(command, "interface ") {
				name := strings.TrimSpace(strings.TrimPrefix(command, "interface"))
				if !validInterfaceName(name) {
					return fmt.Errorf("line %d: expected one interface name", line)
				}
				scope = name
				if interfaces[name] == nil {
					interfaces[name] = make(map[string]struct{})
				}
				continue
			}
			global[command] = struct{}{}
		} else {
			if scope == "" {
				return fmt.Errorf("line %d: indented command outside an interface", line)
			}
			if command == "description" {
				return fmt.Errorf("line %d: empty description", line)
			}
			putLine(interfaces[scope], command)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read configuration: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.global, c.interfaces = global, interfaces
	return nil
}

// String returns a deterministic LF-separated configuration snapshot.
func (c *RunningConfig) String() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var out strings.Builder
	for _, line := range sortedKeys(c.global) {
		out.WriteString(line + "\n")
	}
	names := make([]string, 0, len(c.interfaces))
	for name := range c.interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		out.WriteString("interface " + name + "\n")
		for _, line := range sortedKeys(c.interfaces[name]) {
			out.WriteString(" " + line + "\n")
		}
		out.WriteString("!\n")
	}
	return out.String()
}

func validInterfaceName(name string) bool { return name != "" && len(strings.Fields(name)) == 1 }

func (c *RunningConfig) ensureInterface(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.interfaces == nil {
		c.interfaces = make(map[string]map[string]struct{})
	}
	if c.interfaces[name] == nil {
		c.interfaces[name] = make(map[string]struct{})
	}
}

func (c *RunningConfig) removeInterface(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.interfaces, name)
}

func (c *RunningConfig) apply(scope, command string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.global == nil {
		c.global = make(map[string]struct{})
	}
	lines := c.global
	if scope != "" {
		if c.interfaces == nil {
			c.interfaces = make(map[string]map[string]struct{})
		}
		if c.interfaces[scope] == nil {
			c.interfaces[scope] = make(map[string]struct{})
		}
		lines = c.interfaces[scope]
	}
	if command == "no description" || strings.HasPrefix(command, "no description ") {
		for line := range lines {
			if strings.HasPrefix(line, "description ") {
				delete(lines, line)
			}
		}
	} else if strings.HasPrefix(command, "no ") {
		delete(lines, strings.TrimPrefix(command, "no "))
	} else {
		delete(lines, "no "+command)
		putLine(lines, command)
	}
}

func putLine(lines map[string]struct{}, command string) {
	if strings.HasPrefix(command, "description ") {
		for line := range lines {
			if strings.HasPrefix(line, "description ") {
				delete(lines, line)
			}
		}
	}
	lines[command] = struct{}{}
}

func sortedKeys(lines map[string]struct{}) []string {
	keys := make([]string, 0, len(lines))
	for line := range lines {
		keys = append(keys, line)
	}
	sort.Strings(keys)
	return keys
}
