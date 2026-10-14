package emulator

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// ConfigurationSection describes a subtree, independent of the command displaying it.
// Path is relative to the parent value. Each enumerates a map in sorted key order.
// Templates receive Config (whole tree), Value, Key and Keys (ancestor selections).
type ConfigurationSection struct {
	ID       string                 `yaml:"id"`
	Path     []string               `yaml:"path"`
	Each     bool                   `yaml:"each"`
	Header   string                 `yaml:"header"`
	Lines    []string               `yaml:"lines"`
	Footer   string                 `yaml:"footer"`
	Children []ConfigurationSection `yaml:"children"`
}

func (p *Profile) compileConfiguration(root *ConfigurationSection) error {
	p.configurationSections = map[string]*ConfigurationSection{}
	if root == nil {
		return nil
	}
	var visit func(*ConfigurationSection, int) error
	visit = func(s *ConfigurationSection, depth int) error {
		if depth > 32 || len(p.configurationSections) >= 256 {
			return fmt.Errorf("configuration tree exceeds size/depth limit")
		}
		if s.ID == "" || len(s.ID) > 128 || strings.ContainsFunc(s.ID, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			return fmt.Errorf("invalid configuration section id")
		}
		if p.configurationSections[s.ID] != nil {
			return fmt.Errorf("duplicate configuration section %q", s.ID)
		}
		if len(s.Path) > 32 || len(s.Lines) > 256 {
			return fmt.Errorf("configuration section too large")
		}
		for _, key := range s.Path {
			if key == "" || len(key) > 256 || strings.ContainsFunc(key, unicode.IsControl) {
				return fmt.Errorf("invalid configuration path")
			}
		}
		p.configurationSections[s.ID] = s
		for _, text := range append([]string{s.Header, s.Footer}, s.Lines...) {
			if err := p.compileText(text); err != nil {
				return err
			}
		}
		for i := range s.Children {
			if err := visit(&s.Children[i], depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(root, 0)
}

// RenderConfiguration formats an entire tree or a section. Selection keys name Each
// sections; values select a map key. No input is mutated. Output is capped at 1 MiB.
func (p *Profile) RenderConfiguration(name string, selection map[string]string, config map[string]any) (string, error) {
	root := p.def.Configuration
	if root == nil {
		return "", fmt.Errorf("profile has no configuration renderer")
	}
	if name == "" {
		name = root.ID
	}
	if p.configurationSections[name] == nil {
		return "", fmt.Errorf("unknown configuration section %q", name)
	}
	for id := range selection {
		section := p.configurationSections[id]
		if section == nil || !section.Each {
			return "", fmt.Errorf("selection requires an each section: %q", id)
		}
	}
	var out strings.Builder
	writer := &limitedWriter{w: &out, left: 1 << 20}
	write := func(text string) error {
		if text == "" {
			return nil
		}
		if !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		_, err := writer.Write([]byte(text))
		return err
	}
	var walk func(*ConfigurationSection, any, string, map[string]string, bool) error
	walk = func(s *ConfigurationSection, parent any, key string, keys map[string]string, render bool) error {
		node := parent
		for _, component := range s.Path {
			m, ok := node.(map[string]any)
			if !ok {
				return nil
			}
			node = m[component]
		}
		emit := func(value any, key string, keys map[string]string) error {
			chosen := render || s.ID == name
			if chosen {
				data := map[string]any{"Config": config, "Value": value, "Key": key, "Keys": keys}
				for _, text := range append([]string{s.Header}, s.Lines...) {
					result, err := p.render(text, data)
					if err != nil {
						return err
					}
					if err = write(result); err != nil {
						return err
					}
				}
			}
			for i := range s.Children {
				if err := walk(&s.Children[i], value, key, keys, chosen); err != nil {
					return err
				}
			}
			if chosen {
				result, err := p.render(s.Footer, map[string]any{"Config": config, "Value": value, "Key": key, "Keys": keys})
				if err != nil {
					return err
				}
				return write(result)
			}
			return nil
		}
		if !s.Each {
			if node == nil {
				return nil
			}
			return emit(node, key, keys)
		}
		m, ok := node.(map[string]any)
		if node != nil && !ok {
			return fmt.Errorf("configuration section %q requires a map", s.ID)
		}
		var names []string
		if selected, exists := selection[s.ID]; exists {
			names = []string{selected}
		} else {
			for key := range m {
				names = append(names, key)
			}
			sort.Strings(names)
		}
		for _, key := range names {
			if key == "" {
				return fmt.Errorf("empty configuration selection")
			}
			value, exists := m[key]
			if !exists {
				value = map[string]any{}
			} // A new selected view may have no committed object yet.
			next := make(map[string]string, len(keys)+1)
			for k, v := range keys {
				next[k] = v
			}
			next[s.ID] = key
			if err := emit(value, key, next); err != nil {
				return err
			}
		}
		return nil
	}
	err := walk(root, config, "", map[string]string{}, false)
	return out.String(), err
}
