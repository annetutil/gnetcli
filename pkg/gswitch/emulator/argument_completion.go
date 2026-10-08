package emulator

import (
	"fmt"
	"slices"
	"sort"
	"strings"
	"unicode"
)

// ArgumentCompletion supplies advisory values for a word argument. StatePath
// selects a configuration map whose keys are offered; it never validates or
// changes the argument. Values are resolved for each query, not cached globally.
type ArgumentCompletion struct {
	StatePath   []string `yaml:"statePath"`
	Prefix      string   `yaml:"prefix"`
	StripPrefix bool     `yaml:"stripPrefix"`
}

func (p *Profile) registerArgumentCompletions(mode string, pat pattern, sources map[string]ArgumentCompletion) error {
	for name, source := range sources {
		index := -1
		for i, token := range pat.tokens {
			if token.name == name {
				index = i
				break
			}
		}
		if index < 0 || pat.tokens[index].kind != "word" {
			return fmt.Errorf("command %s: completion %q must refer to a word argument", pat.id, name)
		}
		if source.StripPrefix && source.Prefix == "" {
			return fmt.Errorf("command %s: stripPrefix requires prefix", pat.id)
		}
		if len(source.Prefix) > 256 || strings.ContainsFunc(source.Prefix, unicode.IsControl) {
			return fmt.Errorf("command %s: invalid completion prefix", pat.id)
		}
		if len(source.StatePath) == 0 || len(source.StatePath) > 32 {
			return fmt.Errorf("command %s: completion statePath must contain 1..32 keys", pat.id)
		}
		for _, key := range source.StatePath {
			if key == "" || len(key) > 256 || strings.ContainsFunc(key, unicode.IsControl) {
				return fmt.Errorf("command %s: invalid completion statePath key", pat.id)
			}
		}
		if p.argumentCompletions == nil {
			p.argumentCompletions = map[string]map[string]ArgumentCompletion{}
		}
		if p.argumentCompletions[mode] == nil {
			p.argumentCompletions[mode] = map[string]ArgumentCompletion{}
		}
		path := helpPath(pat, index)
		if old, exists := p.argumentCompletions[mode][path]; exists && (!slices.Equal(old.StatePath, source.StatePath) || old.Prefix != source.Prefix || old.StripPrefix != source.StripPrefix) {
			return fmt.Errorf("conflicting completion source for %q in mode %q", path, mode)
		}
		p.argumentCompletions[mode][path] = source
	}
	return nil
}

func (p *Profile) argumentValues(mode string, pat pattern, index int, state map[string]any) []string {
	source, configured := p.argumentCompletions[mode][helpPath(pat, index)]
	if !configured {
		return nil
	}
	var node any = state
	for _, key := range source.StatePath {
		object, ok := node.(map[string]any)
		if !ok {
			return nil
		}
		node = object[key]
	}
	object, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	var values []string
	for key := range object {
		if !strings.HasPrefix(key, source.Prefix) {
			continue
		}
		if source.StripPrefix {
			key = strings.TrimPrefix(key, source.Prefix)
		}
		// This editor accepts ASCII single-word arguments. Do not inject control
		// bytes, whitespace, or text that it cannot subsequently edit safely.
		valid := key != "" && len(key) <= p.def.Terminal.MaxInput
		for _, b := range []byte(key) {
			if b <= ' ' || b > '~' {
				valid = false
				break
			}
		}
		if valid {
			values = append(values, key)
		}
	}
	sort.Strings(values)
	return values
}
