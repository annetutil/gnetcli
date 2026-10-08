package emulator

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// HelpFormat controls only '?' rendering. Tab retains its compact suggestions.
// A nil format preserves the original unadorned, one-token-per-line output.
type HelpFormat struct {
	LineWidth          int      `yaml:"lineWidth"`
	NestedKeywordWidth *int     `yaml:"nestedKeywordWidth"`
	TailOrder          []string `yaml:"tailOrder"`
	BlankLineAfter     bool     `yaml:"blankLineAfter"`
	RootHeader         string   `yaml:"rootHeader"`
	Indent             int      `yaml:"indent"`
	KeywordWidth       int      `yaml:"keywordWidth"`
	EchoQuestion       bool     `yaml:"echoQuestion"`
}

// HelpEntry describes exactly one immediate grammar child, never a full path.
// Kind is "keyword", "value", "argument", or "end" (the <cr> marker).
type HelpEntry struct {
	Token       string
	Description string
	Kind        string
}

func validateHelpText(text string) error {
	if len(text) > 4096 || strings.ContainsFunc(text, unicode.IsControl) {
		return fmt.Errorf("help text must be a single line of at most 4096 bytes without control characters")
	}
	return nil
}

func validateHelpFormat(format *HelpFormat) error {
	if format == nil {
		return nil
	}
	if format.LineWidth < 0 || format.LineWidth > 4096 {
		return fmt.Errorf("help lineWidth must be 0..4096")
	}
	if format.Indent < 0 || format.Indent > 32 || format.KeywordWidth < 0 || format.KeywordWidth > 256 {
		return fmt.Errorf("help indent must be 0..32 and keywordWidth 0..256")
	}
	if format.NestedKeywordWidth != nil && (*format.NestedKeywordWidth < 0 || *format.NestedKeywordWidth > 256) {
		return fmt.Errorf("help nestedKeywordWidth must be 0..256")
	}
	if len(format.TailOrder) > 64 {
		return fmt.Errorf("help tailOrder must contain at most 64 tokens")
	}
	seen := map[string]bool{}
	for _, token := range format.TailOrder {
		if token == "" || strings.ContainsFunc(token, unicode.IsSpace) || validateHelpText(token) != nil {
			return fmt.Errorf("help tailOrder requires nonempty tokens without whitespace/control characters")
		}
		if seen[token] {
			return fmt.Errorf("duplicate help tailOrder token %q", token)
		}
		seen[token] = true
	}
	return validateHelpText(format.RootHeader)
}

func helpPath(p pattern, index int) string {
	parts := make([]string, index+1)
	for i, token := range p.tokens[:index+1] {
		parts[i] = token.word
		if token.kind != "" {
			// As in the grammar signature, argument type identifies the node;
			// the variable's local name does not create another grammar branch.
			parts[i] = "<" + token.kind + ">"
		}
	}
	return strings.Join(parts, " ")
}

func (p *Profile) registerHelp(mode string, pattern pattern, descriptions []string) error {
	if p.helpDescriptions[mode] == nil {
		p.helpDescriptions[mode] = map[string]string{}
	}
	for i, description := range descriptions {
		if err := validateHelpText(description); err != nil {
			return fmt.Errorf("command %s: %w", pattern.id, err)
		}
		if description == "" {
			continue
		}
		path := helpPath(pattern, i)
		old := p.helpDescriptions[mode][path]
		if old != "" && old != description {
			return fmt.Errorf("conflicting help for %q in mode %q", path, mode)
		}
		p.helpDescriptions[mode][path] = description
	}
	return nil
}

func (p *Profile) helpDescription(mode string, pattern pattern, index int) string {
	return p.helpDescriptions[mode][helpPath(pattern, index)]
}

// HelpEntries uses the same one-level grammar query as Help and Complete.
// Without a trailing space it filters the current word; after a space it
// lists only the next words. Shared prefixes appear once, with their own help.
func (p *Profile) HelpEntries(mode, line string) []HelpEntry {
	return p.HelpEntriesWithState(mode, line, p.def.InitialState)
}

// HelpEntriesWithState includes declared values from the supplied configuration.
func (p *Profile) HelpEntriesWithState(mode, line string, state map[string]any) []HelpEntry {
	_, _, suggestions := p.suggestions(mode, line, state)
	var entries []HelpEntry
	for _, suggestion := range suggestions {
		kind := "argument"
		if suggestion.keyword {
			kind = "keyword"
		} else if suggestion.value {
			kind = "value"
		} else if suggestion.text == "<cr>" {
			kind = "end"
		}
		entries = append(entries, HelpEntry{Token: suggestion.text, Description: suggestion.description, Kind: kind})
	}
	return entries
}

// RenderHelp returns LF-terminated help text without echo, surrounding newlines
// or a prompt. Device applies terminal newlines and restores the input buffer.
func (p *Profile) RenderHelp(mode, line string) string {
	return p.RenderHelpWithState(mode, line, p.def.InitialState)
}

// RenderHelpWithState formats help against a live/session configuration snapshot.
func (p *Profile) RenderHelpWithState(mode, line string, state map[string]any) string {
	entries := p.HelpEntriesWithState(mode, line, state)
	format := p.def.Terminal.Help
	var out strings.Builder
	if format == nil {
		for _, entry := range entries {
			out.WriteString(entry.Token + "\n")
		}
		return out.String()
	}
	if strings.TrimSpace(line) == "" && format.RootHeader != "" {
		out.WriteString(format.RootHeader + "\n")
	}
	// Keep ordinary entries alphabetic, then show configured suffix tokens.
	// This orders only existing grammar entries; it never invents operators/<cr>.
	rank := map[string]int{}
	for i, token := range format.TailOrder {
		rank[token] = i + 1
	}
	sort.SliceStable(entries, func(i, j int) bool { return rank[entries[i].Token] < rank[entries[j].Token] })
	width := format.KeywordWidth
	if format.NestedKeywordWidth != nil {
		completeWords := len(words(line))
		last, _ := utf8.DecodeLastRuneInString(line)
		if completeWords > 0 && !unicode.IsSpace(last) {
			completeWords--
		}
		if completeWords > 0 {
			width = *format.NestedKeywordWidth
		}
	}
	for _, entry := range entries {
		width = max(width, utf8.RuneCountInString(entry.Token)+2)
	}
	indent := strings.Repeat(" ", format.Indent)
	for _, entry := range entries {
		out.WriteString(indent + entry.Token)
		if entry.Description != "" {
			out.WriteString(strings.Repeat(" ", width-utf8.RuneCountInString(entry.Token)))
			lines := []string{entry.Description}
			if format.LineWidth > 0 {
				lines = wrapHelpDescription(entry.Description, max(1, format.LineWidth-format.Indent-width))
			}
			out.WriteString(strings.Join(lines, "\n"+strings.Repeat(" ", format.Indent+width)))
		}
		out.WriteByte('\n')
	}
	return out.String()
}

func (d *Device) showHelp(s *terminalSession) {
	format := d.profile.def.Terminal.Help
	if format != nil && format.EchoQuestion && s.echo == "character" {
		d.emit(s, "?")
	}
	text := d.profile.RenderHelpWithState(s.mode().name, string(s.input), d.config(s))
	if text == "" {
		// Preserve the previous empty-help output for profiles without metadata.
		text = "\n"
	}
	d.emit(s, d.profile.def.Terminal.Newline+d.newline(text))
	if format != nil && format.BlankLineAfter {
		d.emit(s, d.profile.def.Terminal.Newline)
	}
	d.prompt(s)
}

// wrapHelpDescription wraps words, not terminal cells. Unbreakable long words
// are preserved. The profile chooses the width; SSH resize is not yet modeled.
func wrapHelpDescription(text string, width int) []string {
	if utf8.RuneCountInString(text) <= width {
		return []string{text}
	}
	var lines []string
	line := ""
	for _, word := range strings.Fields(text) {
		if line != "" && utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) > width {
			lines = append(lines, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}
