package emulator

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

type token struct{ word, label, name, kind string }
type pattern struct {
	id, signature string
	tokens        []token
}
type inputToken struct {
	text  string
	start int
}

type Match struct {
	Command string
	Args    map[string]string
}

// ParseError distinguishes grammar errors independently of vendor error rendering.
type ParseError struct {
	Kind   string
	Offset int
}

func (e *ParseError) Error() string { return fmt.Sprintf("%s command at byte %d", e.Kind, e.Offset) }

func compilePattern(id, syntax string) (pattern, error) {
	p := pattern{id: id}
	parts := strings.Fields(syntax)
	if len(parts) == 0 {
		return p, fmt.Errorf("empty syntax for %s", id)
	}
	names := map[string]bool{}
	for i, part := range parts {
		t := token{word: strings.ToLower(part), label: part}
		if strings.HasPrefix(part, "<") {
			if !strings.HasSuffix(part, ">") {
				return p, fmt.Errorf("invalid parameter %q", part)
			}
			name, kind, ok := strings.Cut(part[1:len(part)-1], ":")
			if !ok || name == "" || names[name] {
				return p, fmt.Errorf("invalid/duplicate parameter %q", part)
			}
			if kind != "word" && kind != "rest" && kind != "uint" {
				return p, fmt.Errorf("unsupported parameter type %q", kind)
			}
			if kind == "rest" && i != len(parts)-1 {
				return p, fmt.Errorf("rest parameter must be last")
			}
			names[name] = true
			t = token{name: name, kind: kind}
			p.signature += " <" + kind + ">"
		} else {
			p.signature += " " + t.word
		}
		p.tokens = append(p.tokens, t)
	}
	return p, nil
}

// This first frontend uses whitespace-delimited keywords/words and a raw rest
// argument. It deliberately does not pretend to implement shell/RouterOS quoting.
func words(line string) []inputToken {
	var out []inputToken
	start := -1
	for i, r := range line {
		if unicode.IsSpace(r) {
			if start >= 0 {
				out = append(out, inputToken{line[start:i], start})
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, inputToken{line[start:], start})
	}
	return out
}

// Parse implements context-dependent unique keyword abbreviations. An exact
// keyword takes precedence over its longer siblings. Argument spelling is kept.
func (p *Profile) Parse(mode, line string) (Match, error) {
	input := words(line)
	candidates := append([]pattern(nil), p.grammar[mode]...)
	for i, w := range input {
		var err error
		candidates, err = p.consume(candidates, i, w)
		if err != nil {
			return Match{}, err
		}
	}
	var complete []pattern
	for _, c := range candidates {
		if len(input) >= len(c.tokens) {
			complete = append(complete, c)
		}
	}
	if len(complete) == 0 {
		return Match{}, &ParseError{Kind: "incomplete", Offset: len(line)}
	}
	if len(complete) > 1 {
		return Match{}, &ParseError{Kind: "ambiguous", Offset: len(line)}
	}
	c := complete[0]
	m := Match{Command: c.id, Args: map[string]string{}}
	for i, t := range c.tokens {
		if t.kind == "rest" {
			m.Args[t.name] = line[input[i].start:]
			break
		}
		if t.name != "" {
			m.Args[t.name] = input[i].text
		}
	}
	return m, nil
}

// consume applies the parser rules to one complete word. The last word being
// edited is handled separately by completion, where prefixes are always useful.
func (p *Profile) consume(candidates []pattern, i int, w inputToken) ([]pattern, error) {
	exact := false
	for _, c := range candidates {
		if i < len(c.tokens) && c.tokens[i].word != "" && strings.EqualFold(c.tokens[i].word, w.text) {
			exact = true
		}
	}
	if !exact && p.def.Abbreviations {
		prefixes := map[string]bool{}
		for _, c := range candidates {
			if i < len(c.tokens) {
				t := c.tokens[i]
				if t.word != "" && strings.HasPrefix(t.word, strings.ToLower(w.text)) {
					prefixes[t.word] = true
				}
			}
		}
		if len(prefixes) > 1 {
			return nil, &ParseError{Kind: "ambiguous", Offset: w.start}
		}
	}
	var next []pattern
	for _, c := range candidates {
		if i >= len(c.tokens) {
			if len(c.tokens) > 0 && c.tokens[len(c.tokens)-1].kind == "rest" {
				next = append(next, c)
			}
			continue
		}
		t := c.tokens[i]
		if t.word != "" {
			if strings.EqualFold(t.word, w.text) || (!exact && p.def.Abbreviations && strings.HasPrefix(t.word, strings.ToLower(w.text))) {
				next = append(next, c)
			}
		} else if !exact {
			if t.kind == "uint" {
				if _, err := strconv.ParseUint(w.text, 10, 32); err != nil {
					continue
				}
			}
			next = append(next, c)
		}
	}
	if len(next) == 0 {
		return nil, &ParseError{Kind: "invalid", Offset: w.start}
	}
	return next, nil
}
