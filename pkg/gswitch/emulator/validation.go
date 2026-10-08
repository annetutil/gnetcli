package emulator

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/syntax"
)

const defaultValidationSteps = 100_000

// Validation defines a read-only configuration invariant. Exactly one of
// Starlark (inline source) and File (relative to the profile FS) must be set.
type Validation struct {
	Starlark string `yaml:"starlark"`
	File     string `yaml:"file"`
	MaxSteps uint64 `yaml:"maxSteps"`
}

// ValidationError is an intentional rejection returned by validate(config).
// Interpreter errors and invalid return types are ordinary errors instead.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string { return e.Message }

type validator struct {
	fn       *starlark.Function
	maxSteps uint64
}

func validationThread(steps uint64) *starlark.Thread {
	t := &starlark.Thread{
		Name: "cli-config-validation",
		// Do not leak configuration or unsolicited output to stderr/CLI.
		Print: func(*starlark.Thread, string) {},
		Load: func(_ *starlark.Thread, _ string) (starlark.StringDict, error) {
			return nil, fmt.Errorf("load() is disabled in configuration validators")
		},
	}
	t.SetMaxExecutionSteps(steps)
	return t
}

func compileValidation(def *Validation, files fs.FS) (*validator, error) {
	if def == nil {
		return nil, nil
	}
	if (strings.TrimSpace(def.Starlark) == "") == (def.File == "") {
		return nil, fmt.Errorf("validation requires exactly one of starlark or file")
	}
	steps := def.MaxSteps
	if steps == 0 {
		steps = defaultValidationSteps
	}
	if steps > 1_000_000 {
		return nil, fmt.Errorf("validation maxSteps must not exceed 1000000")
	}
	filename, source := "validation.star", def.Starlark
	if def.File != "" {
		var err error
		source, err = fixture(def.File, files)
		if err != nil {
			return nil, fmt.Errorf("validation file: %w", err)
		}
		filename = def.File
	}
	if len(source) > 1<<20 {
		return nil, fmt.Errorf("validation source exceeds 1 MiB")
	}
	// Per-file options avoid process-global resolver settings. No recursion,
	// while loops, host builtins or externally loaded modules are enabled.
	_, program, err := starlark.SourceProgramOptions(&syntax.FileOptions{}, filename, source, func(string) bool { return false })
	if err != nil {
		return nil, fmt.Errorf("compile validation: %w", err)
	}
	globals, err := program.Init(validationThread(steps), nil)
	if err != nil {
		return nil, fmt.Errorf("initialize validation: %w", err)
	}
	fn, ok := globals["validate"].(*starlark.Function)
	if !ok || fn.NumParams() != 1 || fn.NumKwonlyParams() != 0 || fn.HasVarargs() || fn.HasKwargs() {
		return nil, fmt.Errorf("validation must define validate(config) with one positional parameter")
	}
	// Frozen globals make the callable safe to share across devices and prevent
	// previous validations from affecting later results through module state.
	globals.Freeze()
	return &validator{fn: fn, maxSteps: steps}, nil
}

// ValidateConfiguration checks a proposed complete configuration without
// changing it. validate(config) receives a recursively frozen copy and returns
// None to accept or a non-empty string to reject. Any interpreter failure also
// rejects the change, but is not classified as a ValidationError.
func (p *Profile) ValidateConfiguration(config map[string]any) error {
	if p.validator == nil {
		return nil
	}
	if err := validateState(config, 0); err != nil {
		return fmt.Errorf("validation input: %w", err)
	}
	value := validationValue(config)
	value.Freeze()
	result, err := starlark.Call(validationThread(p.validator.maxSteps), p.validator.fn, starlark.Tuple{value}, nil)
	if err != nil {
		return fmt.Errorf("Starlark validation failed: %w", err)
	}
	if result == starlark.None {
		return nil
	}
	message, ok := starlark.AsString(result)
	if !ok || strings.TrimSpace(message) == "" {
		return fmt.Errorf("Starlark validate(config) must return None or a non-empty string, got %s", result.Type())
	}
	if len(message) > 4096 {
		return fmt.Errorf("Starlark validation message exceeds 4096 bytes")
	}
	return &ValidationError{Message: message}
}

// validateState has already restricted the input to these JSON-like types.
// Sort keys so validator iteration/rejection order does not depend on Go maps.
func validationValue(v any) starlark.Value {
	switch x := v.(type) {
	case nil:
		return starlark.None
	case bool:
		return starlark.Bool(x)
	case int:
		return starlark.MakeInt(x)
	case float64:
		return starlark.Float(x)
	case string:
		return starlark.String(x)
	case []any:
		values := make([]starlark.Value, len(x))
		for i, item := range x {
			values[i] = validationValue(item)
		}
		return starlark.NewList(values)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for key := range x {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		dict := starlark.NewDict(len(x))
		for _, key := range keys {
			// Fresh dict and string keys: SetKey cannot fail.
			_ = dict.SetKey(starlark.String(key), validationValue(x[key]))
		}
		return dict
	default:
		panic("unvalidated configuration type")
	}
}

// checkConfiguration aborts the remaining command actions on any rejection.
// Validation errors are visible CLI errors, not transport disconnects. The
// caller publishes the new state/revision only after this returns true.
func (d *Device) checkConfiguration(s *terminalSession, config map[string]any) (bool, error) {
	if err := d.profile.ValidateConfiguration(config); err != nil {
		d.record(s, "validation-rejected", err.Error())
		text, renderErr := d.profile.render(d.profile.def.Errors["validation"], map[string]any{"Message": err.Error()})
		if renderErr != nil {
			return false, renderErr
		}
		d.emit(s, d.newline(text))
		s.actions = nil
		return false, nil
	}
	return true, nil
}
