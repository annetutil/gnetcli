package emulator

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ArgumentSpec customizes a word argument without changing its grammar type.
// Hint is display-only. Lengths count Unicode code points, not bytes; zero means
// no additional bound. The terminal editor itself remains ASCII-only.
type ArgumentSpec struct {
	Hint      string `yaml:"hint"`
	MinLength int    `yaml:"minLength"`
	MaxLength int    `yaml:"maxLength"`
}

func (p *Profile) registerArguments(mode string, pat pattern, specs map[string]ArgumentSpec) error {
	for name, spec := range specs {
		index := -1
		for i, token := range pat.tokens {
			if token.name == name {
				index = i
				break
			}
		}
		if index < 0 || pat.tokens[index].kind != "word" {
			return fmt.Errorf("command %s: argument specification %q must refer to a word argument", pat.id, name)
		}
		if spec.MinLength < 0 || spec.MaxLength < 0 || (spec.MaxLength > 0 && spec.MinLength > spec.MaxLength) {
			return fmt.Errorf("command %s: invalid argument length bounds for %q", pat.id, name)
		}
		if len(spec.Hint) > 256 || spec.Hint == "<cr>" || strings.ContainsFunc(spec.Hint, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			return fmt.Errorf("command %s: argument hint must be at most 256 bytes without whitespace/control characters and cannot be <cr>", pat.id)
		}
		if p.arguments == nil {
			p.arguments = map[string]map[string]ArgumentSpec{}
		}
		if p.arguments[mode] == nil {
			p.arguments[mode] = map[string]ArgumentSpec{}
		}
		path := helpPath(pat, index)
		if old, exists := p.arguments[mode][path]; exists && old != spec {
			return fmt.Errorf("conflicting argument specification for %q in mode %q", path, mode)
		}
		p.arguments[mode][path] = spec
	}
	return nil
}

func (p *Profile) argumentSpec(mode string, pat pattern, index int) ArgumentSpec {
	return p.arguments[mode][helpPath(pat, index)]
}

func (a ArgumentSpec) acceptsLength(value string) bool {
	length := utf8.RuneCountInString(value)
	return length >= a.MinLength && (a.MaxLength == 0 || length <= a.MaxLength)
}
