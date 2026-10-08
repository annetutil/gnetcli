// Package emulator implements a small, deterministic, stateful CLI emulator.
// It models terminal interactions, not a switch data or control plane.
package emulator

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"
)

// Definition is the versioned source format. LoadProfile validates and compiles it.
type Definition struct {
	Validation    *Validation       `yaml:"validation"`
	APIVersion    string            `yaml:"apiVersion"`
	Name          string            `yaml:"name"`
	InitialMode   string            `yaml:"initialMode"`
	InitialState  map[string]any    `yaml:"initialState"`
	Abbreviations bool              `yaml:"abbreviations"`
	Modes         map[string]Mode   `yaml:"modes"`
	Commands      []Command         `yaml:"commands"`
	Dialogs       map[string]Dialog `yaml:"dialogs"`
	Terminal      Terminal          `yaml:"terminal"`
	Login         Login             `yaml:"login"`
	Boot          []Event           `yaml:"boot"`
	Errors        map[string]string `yaml:"errors"`
}

type Mode struct {
	Prompt string `yaml:"prompt"`
}

type Terminal struct {
	HistorySize *int        `yaml:"historySize"`
	Help        *HelpFormat `yaml:"help"`
	Echo        string      `yaml:"echo"`
	Newline     string      `yaml:"newline"`
	PageLines   int         `yaml:"pageLines"`
	Pager       string      `yaml:"pager"`
	LogPolicy   string      `yaml:"logPolicy"`
	MaxInput    int         `yaml:"maxInput"`
}

type Login struct {
	UsernamePrompt string `yaml:"usernamePrompt"`
	PasswordPrompt string `yaml:"passwordPrompt"`
	Failure        string `yaml:"failure"`
	Attempts       int    `yaml:"attempts"`
}

type Command struct {
	Completions map[string]ArgumentCompletion `yaml:"completions"`
	Help        []string                      `yaml:"help"`
	ID          string                        `yaml:"id"`
	Modes       []string                      `yaml:"modes"`
	Syntax      string                        `yaml:"syntax"`
	Actions     []Action                      `yaml:"actions"`
}

// Action is deliberately a closed set of operations, not arbitrary Go or shell code.
// Strings in text, path, context and value may use Go text/template expressions.
type Action struct {
	Op      string            `yaml:"op"`
	Mode    string            `yaml:"mode"`
	Context map[string]string `yaml:"context"`
	Path    []string          `yaml:"path"`
	Value   any               `yaml:"value"`
	Text    string            `yaml:"text"`
	File    string            `yaml:"file"`
	After   time.Duration     `yaml:"after"`
	Dialog  string            `yaml:"dialog"`
	Name    string            `yaml:"name"`
}

type Dialog struct {
	Prompt  string   `yaml:"prompt"`
	Secret  bool     `yaml:"secret"`
	Answers []Answer `yaml:"answers"`
}

type Answer struct {
	Input   string   `yaml:"input"`
	Actions []Action `yaml:"actions"`
}

// Event times are relative to device boot, never to attachment or login.
// raw events deliver exact fixture bytes; log events use terminal log policy.
type Event struct {
	At     time.Duration `yaml:"at"`
	Kind   string        `yaml:"kind"`
	Text   string        `yaml:"text"`
	File   string        `yaml:"file"`
	Source string        `yaml:"source"`
	Route  string        `yaml:"route"`
	Policy string        `yaml:"policy"`
}

type Trigger struct {
	On    string        `yaml:"on"`
	After time.Duration `yaml:"after"`
	Event Event         `yaml:"event"`
}

type Scenario struct {
	APIVersion string    `yaml:"apiVersion"`
	Timeline   []Event   `yaml:"timeline"`
	Triggers   []Trigger `yaml:"triggers"`
}

// Profile is immutable after compilation and may be shared by independent devices.
type Profile struct {
	argumentCompletions map[string]map[string]ArgumentCompletion
	helpDescriptions    map[string]map[string]string
	validator           *validator
	def                 Definition
	commands            map[string]Command
	grammar             map[string][]pattern
	templates           map[string]*template.Template
}

func decode(r io.Reader, dst any) error {
	d := yaml.NewDecoder(io.LimitReader(r, 4<<20))
	d.KnownFields(true)
	if err := d.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("expected exactly one YAML document")
	}
	return nil
}

// LoadProfile resolves fixtures only inside files; pass nil when none are used.
func LoadProfile(r io.Reader, files fs.FS) (*Profile, error) {
	p := &Profile{commands: map[string]Command{}, grammar: map[string][]pattern{}, templates: map[string]*template.Template{}}
	if err := decode(r, &p.def); err != nil {
		return nil, err
	}
	d := &p.def
	p.helpDescriptions = map[string]map[string]string{}
	if err := validateHelpFormat(d.Terminal.Help); err != nil {
		return nil, err
	}
	if d.APIVersion != "cli-emulator/v1" || d.Name == "" {
		return nil, fmt.Errorf("profile requires apiVersion cli-emulator/v1 and name")
	}
	if _, ok := d.Modes[d.InitialMode]; !ok {
		return nil, fmt.Errorf("unknown initialMode %q", d.InitialMode)
	}
	if d.InitialState == nil {
		d.InitialState = map[string]any{}
	}
	if err := validateState(d.InitialState, 0); err != nil {
		return nil, err
	}
	if d.Errors == nil {
		d.Errors = map[string]string{}
	}
	defaults := map[string]string{"invalid": "% Invalid input detected at '^' marker.\n", "incomplete": "% Incomplete command.\n", "ambiguous": "% Ambiguous command: \"{{ .Line }}\"\n"}
	defaults["validation"] = "% Invalid input: {{ .Message }}\n"
	for kind, text := range defaults {
		if d.Errors[kind] == "" {
			d.Errors[kind] = text
		}
	}
	for kind, text := range d.Errors {
		if defaults[kind] == "" {
			return nil, fmt.Errorf("unknown error kind %s", kind)
		}
		if err := p.compileText(text); err != nil {
			return nil, err
		}
	}
	if d.Terminal.Echo == "" {
		d.Terminal.Echo = "character"
	}
	if !echoMode(d.Terminal.Echo) {
		return nil, fmt.Errorf("invalid echo mode")
	}
	if d.Terminal.Newline == "" {
		d.Terminal.Newline = "\r\n"
	}
	if d.Terminal.Newline != "\r\n" && d.Terminal.Newline != "\n" {
		return nil, fmt.Errorf("newline must be LF or CRLF")
	}
	if d.Terminal.Pager == "" {
		d.Terminal.Pager = "--More--"
	}
	if d.Terminal.LogPolicy == "" {
		d.Terminal.LogPolicy = "raw"
	}
	if !logPolicy(d.Terminal.LogPolicy) || d.Terminal.PageLines < 0 || d.Terminal.MaxInput < 0 {
		return nil, fmt.Errorf("invalid terminal settings")
	}
	if d.Terminal.HistorySize == nil {
		size := defaultHistorySize
		d.Terminal.HistorySize = &size
	}
	if *d.Terminal.HistorySize < 0 || *d.Terminal.HistorySize > maxHistorySize {
		return nil, fmt.Errorf("terminal historySize must be 0..%d", maxHistorySize)
	}
	if d.Terminal.MaxInput == 0 {
		d.Terminal.MaxInput = 4096
	}
	if d.Login.UsernamePrompt == "" {
		d.Login.UsernamePrompt = "Username: "
	}
	if d.Login.PasswordPrompt == "" {
		d.Login.PasswordPrompt = "Password: "
	}
	if d.Login.Failure == "" {
		d.Login.Failure = "Authentication failed"
	}
	if d.Login.Attempts == 0 {
		d.Login.Attempts = 3
	}
	if d.Login.Attempts < 0 {
		return nil, fmt.Errorf("login attempts must be positive")
	}
	for name, mode := range d.Modes {
		if mode.Prompt == "" {
			return nil, fmt.Errorf("mode %q has empty prompt", name)
		}
		if err := p.compileText(mode.Prompt); err != nil {
			return nil, err
		}
	}
	for name, dialog := range d.Dialogs {
		if dialog.Prompt == "" || len(dialog.Answers) == 0 {
			return nil, fmt.Errorf("incomplete dialog %q", name)
		}
		if err := p.compileText(dialog.Prompt); err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for i := range dialog.Answers {
			a := &dialog.Answers[i]
			if seen[a.Input] {
				return nil, fmt.Errorf("duplicate answer in %q", name)
			}
			seen[a.Input] = true
			if err := p.compileActions(a.Actions, files); err != nil {
				return nil, fmt.Errorf("dialog %s: %w", name, err)
			}
		}
		d.Dialogs[name] = dialog
	}
	for _, cmd := range d.Commands {
		if cmd.ID == "" || len(cmd.Modes) == 0 {
			return nil, fmt.Errorf("command requires id and modes")
		}
		if _, ok := p.commands[cmd.ID]; ok {
			return nil, fmt.Errorf("duplicate command %q", cmd.ID)
		}
		pat, err := compilePattern(cmd.ID, cmd.Syntax)
		if err != nil {
			return nil, err
		}
		if cmd.Help != nil && len(cmd.Help) != len(pat.tokens) {
			return nil, fmt.Errorf("command %s: help must have one entry per syntax token", cmd.ID)
		}
		if err := p.compileActions(cmd.Actions, files); err != nil {
			return nil, fmt.Errorf("command %s: %w", cmd.ID, err)
		}
		for _, mode := range cmd.Modes {
			if _, ok := d.Modes[mode]; !ok {
				return nil, fmt.Errorf("command %s: unknown mode %s", cmd.ID, mode)
			}
			for _, old := range p.grammar[mode] {
				if old.signature == pat.signature {
					return nil, fmt.Errorf("duplicate syntax in mode %s: %s", mode, cmd.Syntax)
				}
			}
			if err := p.registerHelp(mode, pat, cmd.Help); err != nil {
				return nil, err
			}
			if err := p.registerArgumentCompletions(mode, pat, cmd.Completions); err != nil {
				return nil, err
			}
			p.grammar[mode] = append(p.grammar[mode], pat)
		}
		p.commands[cmd.ID] = cmd
	}
	for i := range d.Boot {
		if err := compileEvent(&d.Boot[i], files); err != nil {
			return nil, err
		}
		if d.Boot[i].Route == "session" {
			return nil, fmt.Errorf("boot cannot target a session")
		}
	}
	var err error
	p.validator, err = compileValidation(d.Validation, files)
	if err != nil {
		return nil, err
	}
	if err := p.ValidateConfiguration(d.InitialState); err != nil {
		return nil, fmt.Errorf("initialState validation: %w", err)
	}
	return p, nil
}

func (p *Profile) compileText(s string) error {
	if _, ok := p.templates[s]; ok {
		return nil
	}
	t, err := template.New("cli").Option("missingkey=error").Parse(s)
	if err != nil {
		return err
	}
	p.templates[s] = t
	return nil
}

func fixture(name string, files fs.FS) (string, error) {
	if files == nil || !fs.ValidPath(name) {
		return "", fmt.Errorf("invalid fixture path %q", name)
	}
	f, err := files.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if len(b) > 1<<20 {
		return "", fmt.Errorf("fixture too large: %s", name)
	}
	return string(b), err
}

func (p *Profile) compileActions(actions []Action, files fs.FS) error {
	for i := range actions {
		a := &actions[i]
		if a.After < 0 {
			return fmt.Errorf("negative action delay")
		}
		switch a.Op {
		case "push", "mode":
			if _, ok := p.def.Modes[a.Mode]; !ok {
				return fmt.Errorf("unknown mode %q", a.Mode)
			}
		case "dialog":
			if _, ok := p.def.Dialogs[a.Dialog]; !ok {
				return fmt.Errorf("unknown dialog %q", a.Dialog)
			}
		case "set", "delete":
			if len(a.Path) == 0 {
				return fmt.Errorf("%s requires path", a.Op)
			}
		case "output", "raw", "pause", "pop", "pager", "echo", "monitor", "save", "begin", "commit", "abort", "disconnect", "logout", "reboot":
		case "checkpoint":
			if a.Name == "" {
				return fmt.Errorf("checkpoint requires name")
			}
		default:
			return fmt.Errorf("unknown action %q", a.Op)
		}
		if a.File != "" {
			if (a.Op != "raw" && a.Op != "output") || a.Text != "" {
				return fmt.Errorf("file requires raw/output and no text")
			}
			var err error
			a.Text, err = fixture(a.File, files)
			if err != nil {
				return err
			}
		}
		texts := append([]string{}, a.Path...)
		if a.Op != "raw" {
			texts = append(texts, a.Text)
		}
		for _, v := range a.Context {
			texts = append(texts, v)
		}
		switch v := a.Value.(type) {
		case string:
			texts = append(texts, v)
		case nil, bool, int, float64:
		default:
			return fmt.Errorf("action value must be scalar")
		}
		for _, v := range texts {
			if err := p.compileText(v); err != nil {
				return err
			}
		}
	}
	return nil
}

func logPolicy(s string) bool { return s == "raw" || s == "redraw" || s == "defer" }

func compileEvent(e *Event, files fs.FS) error {
	if e.At < 0 {
		return fmt.Errorf("negative event time")
	}
	switch e.Kind {
	case "log", "raw", "lifecycle":
	case "ready":
		if e.Text != "true" && e.Text != "false" {
			return fmt.Errorf("ready text must be true or false")
		}
	default:
		return fmt.Errorf("unknown event kind %q", e.Kind)
	}
	if e.Route == "" {
		e.Route = "console"
	}
	if e.Route != "console" && e.Route != "monitor" && e.Route != "all" && e.Route != "session" {
		return fmt.Errorf("unknown event route %q", e.Route)
	}
	if e.Policy != "" && !logPolicy(e.Policy) {
		return fmt.Errorf("unknown log policy %q", e.Policy)
	}
	if e.File != "" {
		if e.Kind != "raw" || e.Text != "" {
			return fmt.Errorf("event fixture requires raw and no text")
		}
		var err error
		e.Text, err = fixture(e.File, files)
		e.File = ""
		return err
	}
	return nil
}

func LoadScenario(r io.Reader, files fs.FS) (*Scenario, error) {
	var s Scenario
	if err := decode(r, &s); err != nil {
		return nil, err
	}
	if err := validateScenario(&s, files); err != nil {
		return nil, err
	}
	return &s, nil
}

func (p *Profile) render(text string, data any) (string, error) {
	var b bytes.Buffer
	t, ok := p.templates[text]
	if !ok {
		return "", fmt.Errorf("uncompiled template")
	}
	if err := t.Execute(&limitedWriter{w: &b, left: 1 << 20}, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

type limitedWriter struct {
	w    io.Writer
	left int
}

func (w *limitedWriter) Write(b []byte) (int, error) {
	if len(b) > w.left {
		return 0, fmt.Errorf("render exceeds 1 MiB")
	}
	n, err := w.w.Write(b)
	w.left -= n
	return n, err
}

func validateState(v any, depth int) error {
	if depth > 32 {
		return fmt.Errorf("state nesting exceeds 32")
	}
	switch x := v.(type) {
	case map[string]any:
		for _, v := range x {
			if err := validateState(v, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for _, v := range x {
			if err := validateState(v, depth+1); err != nil {
				return err
			}
		}
	case nil, string, bool, int, float64:
	default:
		return fmt.Errorf("state must contain string-keyed maps and scalar/list values, got %T", v)
	}
	return nil
}

func echoMode(s string) bool { return s == "character" || s == "line" || s == "none" }
