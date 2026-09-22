// Package models runs external Starlark models over an already connected device.
package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/annetutil/gnetcli/pkg/cmd"
	starjson "go.starlark.net/lib/json"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

var (
	ErrInvalidName = errors.New("invalid model name")
	ErrNotFound    = errors.New("model not found")
	modelName      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)
)

// Executor is the command-execution subset of device.Device. The caller owns
// the connection; concurrent calls must not share a device unless it supports it.
type Executor interface {
	ExecuteCtx(context.Context, cmd.Cmd) (cmd.CmdRes, error)
}

type Option func(*Runner)

// WithMaxExecutionSteps sets the per-collection budget, including imports.
func WithMaxExecutionSteps(steps uint64) Option {
	return func(r *Runner) { r.maxSteps = steps }
}

// WithCommandOptions supplies defaults to every command executed by a model.
func WithCommandOptions(opts ...cmd.CmdOption) Option {
	return func(r *Runner) { r.commandOptions = append([]cmd.CmdOption(nil), opts...) }
}

// Runner is safe for concurrent use. Source files are reloaded on every call.
type Runner struct {
	directory      string
	maxSteps       uint64
	commandOptions []cmd.CmdOption
}

func New(directory string, opts ...Option) (*Runner, error) {
	if directory == "" {
		return nil, errors.New("empty models directory")
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, fmt.Errorf("models directory: %w", err)
	}
	if err := root.Close(); err != nil {
		return nil, err
	}
	r := &Runner{directory: directory, maxSteps: 1000000}
	for _, opt := range opts {
		opt(r)
	}
	if r.maxSteps == 0 {
		return nil, errors.New("model execution step limit must be positive")
	}
	return r, nil
}

// Check validates a model name and that its source is readable inside the root.
// It performs no evaluation and does not access a device.
func (r *Runner) Check(name string) error {
	if !modelName.MatchString(name) {
		return ErrInvalidName
	}
	root, err := os.OpenRoot(r.directory)
	if err != nil {
		return err
	}
	defer root.Close()
	_, err = root.ReadFile(name + ".star")
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	return err
}

// Collect executes <name>.star's collect(device) and returns a JSON object.
// Neither Connect nor Close is called here. No partial result is returned.
func (r *Runner) Collect(ctx context.Context, dev Executor, deviceType, name string) (json.RawMessage, error) {
	if !modelName.MatchString(name) {
		return nil, ErrInvalidName
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if dev == nil {
		return nil, errors.New("nil model device")
	}
	root, err := os.OpenRoot(r.directory)
	if err != nil {
		return nil, fmt.Errorf("models directory: %w", err)
	}
	defer root.Close()
	thread := &starlark.Thread{Name: name}
	thread.SetMaxExecutionSteps(r.maxSteps)
	stop := context.AfterFunc(ctx, func() { thread.Cancel(ctx.Err().Error()) })
	defer stop()
	// Imports have per-execution state; a nil entry marks an import in progress.
	cache := map[string]starlark.StringDict{}
	thread.Load = func(thread *starlark.Thread, path string) (starlark.StringDict, error) {
		if !fs.ValidPath(path) || strings.Contains(path, `\`) || !strings.HasSuffix(path, ".star") {
			return nil, fmt.Errorf("invalid model import %q", path)
		}
		if globals, ok := cache[path]; ok {
			if globals == nil {
				return nil, fmt.Errorf("cyclic model import %q", path)
			}
			return globals, nil
		}
		if globals, ok := standardModule(path); ok {
			cache[path] = globals
			return globals, nil
		}
		cache[path] = nil
		data, err := root.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("load %s: %w", path, err)
		}
		globals, err := starlark.ExecFileOptions(&syntax.FileOptions{}, thread, path, data, nil)
		if err != nil {
			return nil, err
		}
		globals.Freeze()
		cache[path] = globals
		return globals, nil
	}
	source, err := root.ReadFile(name + ".star")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if err != nil {
		return nil, err
	}
	cache[name+".star"] = nil
	globals, err := starlark.ExecFileOptions(&syntax.FileOptions{}, thread, name+".star", source, nil)
	if err == nil {
		globals.Freeze()
		cache[name+".star"] = globals
		collect, ok := globals["collect"].(starlark.Callable)
		if !ok {
			return nil, fmt.Errorf("model %s: collect must be callable", name)
		}
		execute := starlark.NewBuiltin("device.execute", func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var command string
			if err := starlark.UnpackArgs(b.Name(), args, kwargs, "command", &command); err != nil {
				return nil, err
			}
			if command == "" {
				return nil, errors.New("empty model command")
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			res, err := dev.ExecuteCtx(ctx, cmd.NewCmd(command, r.commandOptions...))
			if err != nil {
				return nil, fmt.Errorf("execute %q: %w", command, err)
			}
			if res == nil {
				return nil, fmt.Errorf("execute %q: empty result", command)
			}
			if res.Status() != 0 {
				return nil, fmt.Errorf("execute %q: status %d: %s", command, res.Status(), res.Error())
			}
			return starlark.String(res.Output()), nil
		})
		target := starlarkstruct.FromStringDict(starlark.String("device"), starlark.StringDict{"type": starlark.String(deviceType), "execute": execute})
		var value starlark.Value
		value, err = starlark.Call(thread, collect, starlark.Tuple{target}, nil)
		if err == nil {
			if _, ok := value.(*starlark.Dict); !ok {
				return nil, fmt.Errorf("model %s: collect must return a dict", name)
			}
			value, err = starlark.Call(thread, starjson.Module.Members["encode"], starlark.Tuple{value}, nil)
			if err == nil {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return json.RawMessage(value.(starlark.String)), nil
			}
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var evalErr *starlark.EvalError
	if errors.As(err, &evalErr) {
		return nil, fmt.Errorf("model %s: %s: %w", name, evalErr.Backtrace(), err)
	}
	return nil, fmt.Errorf("model %s: %w", name, err)
}
