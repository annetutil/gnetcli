package emulator

import (
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Completion describes end-of-line token completion, never command execution.
// Line is the edited buffer. Candidates contains sorted keywords and display-only
// argument/<cr> hints. Declared state-backed argument values are also insertable.
type Completion struct {
	Line       string
	Candidates []string
}

type suggestion struct {
	description string
	text        string
	keyword     bool
	value       bool
}

// suggestions consumes complete words using exactly the same rules as Parse:
// current mode, exact keyword priority, unique abbreviations and typed arguments.
// Only the word currently being edited uses unrestricted prefix matching.
func (p *Profile) suggestions(mode, line string, state map[string]any) (start int, prefix string, result []suggestion) {
	input := words(line)
	start = len(line)
	last, _ := utf8.DecodeLastRuneInString(line)
	if len(input) > 0 && !unicode.IsSpace(last) {
		word := input[len(input)-1]
		start, prefix = word.start, word.text
		input = input[:len(input)-1]
	}
	candidates := p.grammar[mode]
	for i, word := range input {
		var err error
		candidates, err = p.consume(candidates, i, word)
		if err != nil {
			return start, prefix, nil
		}
	}
	seen := map[string]suggestion{}
	for _, candidate := range candidates {
		i := len(input)
		if i >= len(candidate.tokens) {
			if candidate.tokens[len(candidate.tokens)-1].kind == "rest" {
				// The rest argument absorbs all subsequent words/spaces.
				i = len(candidate.tokens) - 1
			} else {
				if prefix == "" {
					seen["<cr>"] = suggestion{text: "<cr>"}
				}
				continue
			}
		}
		t := candidate.tokens[i]
		if t.word != "" {
			if strings.HasPrefix(t.word, strings.ToLower(prefix)) {
				key := "keyword:" + t.word
				if _, exists := seen[key]; !exists {
					seen[key] = suggestion{text: t.label, keyword: true, description: p.helpDescription(mode, candidate, i)}
				}
			}
			continue
		}
		if t.kind == "uint" && prefix != "" {
			if _, err := strconv.ParseUint(prefix, 10, 32); err != nil {
				continue
			}
		}
		if values := p.argumentValues(mode, candidate, i, state); len(values) > 0 {
			for _, value := range values {
				if strings.HasPrefix(strings.ToLower(value), strings.ToLower(prefix)) {
					seen["value:"+value] = suggestion{text: value, value: true, description: p.helpDescription(mode, candidate, i)}
				}
			}
			continue
		}
		text := "<" + t.name + ":" + t.kind + ">"
		seen[text] = suggestion{text: text, description: p.helpDescription(mode, candidate, i)}
	}
	for _, entry := range seen {
		if entry.value {
			if _, exists := seen["keyword:"+strings.ToLower(entry.text)]; exists {
				continue
			}
		}
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].text < result[j].text })
	return start, prefix, result
}

// Help returns sorted keyword/argument hints for the current grammar position.
// Unlike Complete, word help also lists longer siblings of an exact keyword.
func (p *Profile) Help(mode, line string) []string {
	return p.HelpWithState(mode, line, p.def.InitialState)
}

// HelpWithState resolves declared argument values from the supplied configuration.
func (p *Profile) HelpWithState(mode, line string, state map[string]any) []string {
	_, _, suggestions := p.suggestions(mode, line, state)
	var result []string
	for _, s := range suggestions {
		result = append(result, s.text)
	}
	return result
}

// Complete uses the initial configuration for declared argument values. One
// keyword/value match expands to its canonical spelling plus a space; several
// matches expand only their common prefix. Unconfigured free-form arguments and
// preceding words/whitespace are preserved. Keywords can be completed even when
// execution abbreviations are disabled.
func (p *Profile) Complete(mode, line string) Completion {
	return p.CompleteWithState(mode, line, p.def.InitialState)
}

// CompleteWithState completes keywords and explicitly configured argument values.
// It reads, but never changes, the supplied configuration.
func (p *Profile) CompleteWithState(mode, line string, state map[string]any) Completion {
	start, prefix, suggestions := p.suggestions(mode, line, state)
	out := Completion{Line: line}
	// Match Parse's exact keyword priority, e.g. show before showing.
	for _, s := range suggestions {
		if s.keyword && strings.EqualFold(s.text, prefix) {
			return Completion{Line: line[:start] + s.text + " ", Candidates: []string{s.text}}
		}
	}
	// Opaque arguments may differ only in case; prefer an exact-case value.
	for _, s := range suggestions {
		if s.value && s.text == prefix {
			return Completion{Line: line[:start] + s.text + " ", Candidates: []string{s.text}}
		}
	}
	allInsertable := len(suggestions) > 0
	for _, s := range suggestions {
		out.Candidates = append(out.Candidates, s.text)
		allInsertable = allInsertable && (s.keyword || s.value)
	}
	if !allInsertable {
		return out
	}
	common := suggestions[0].text
	for _, s := range suggestions[1:] {
		for !strings.HasPrefix(strings.ToLower(s.text), strings.ToLower(common)) {
			_, size := utf8.DecodeLastRuneInString(common)
			common = common[:len(common)-size]
		}
	}
	if len(suggestions) == 1 {
		out.Line = line[:start] + common + " "
	} else if len(common) > len(prefix) {
		out.Line = line[:start] + common
	}
	return out
}

func (d *Device) complete(s *terminalSession) {
	line := string(s.input)
	result := d.profile.CompleteWithState(s.mode().name, line, d.config(s))
	if len(result.Line) > d.profile.def.Terminal.MaxInput {
		d.emit(s, "\a")
		return
	}
	if result.Line != line {
		s.input = []byte(result.Line)
		if s.echo == "character" {
			if strings.HasPrefix(result.Line, line) {
				d.emit(s, result.Line[len(line):])
			} else {
				// Canonicalizing upper-case input requires replacing visible text.
				d.emit(s, "\r\x1b[2K")
				d.prompt(s)
			}
		}
		if len(result.Candidates) == 1 {
			return
		}
	}
	if len(result.Candidates) == 0 {
		d.emit(s, "\a")
		return
	}
	// Show ambiguous choices (and display-only argument hints) without changing
	// modes or executing actions. Redraw uses the updated buffer and echo policy.
	newline := d.profile.def.Terminal.Newline
	d.emit(s, newline+strings.Join(result.Candidates, newline)+newline)
	d.prompt(s)
}
