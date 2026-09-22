package models_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/models"
	"github.com/stretchr/testify/require"
)

type executor func(context.Context, cmd.Cmd) (cmd.CmdRes, error)

func (e executor) ExecuteCtx(ctx context.Context, c cmd.Cmd) (cmd.CmdRes, error) { return e(ctx, c) }

func noCommands(t *testing.T) executor {
	return func(context.Context, cmd.Cmd) (cmd.CmdRes, error) {
		t.Error("unexpected command")
		return nil, errors.New("unexpected command")
	}
}

func runner(t *testing.T, script string, opts ...models.Option) (*models.Runner, string) {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.star"), []byte(script), 0600))
	r, err := models.New(dir, opts...)
	require.NoError(t, err)
	return r, dir
}

func TestCollect(t *testing.T) {
	r, _ := runner(t, `def collect(device):
    first = device.execute("first")
    second = device.execute(first)
    return {"value": 1770000000123456789, "type": device.type, "output": second}
`)
	var calls []string
	fake := executor(func(_ context.Context, c cmd.Cmd) (cmd.CmdRes, error) {
		calls = append(calls, string(c.Value()))
		return cmd.NewCmdRes([]byte("next")), nil
	})
	result, err := r.Collect(t.Context(), fake, "test-device", "test")
	require.NoError(t, err)
	require.Equal(t, []string{"first", "next"}, calls)
	require.Contains(t, string(result), "1770000000123456789")
	require.JSONEq(t, `{"value":1770000000123456789,"type":"test-device","output":"next"}`, string(result))
}

func TestCollectErrors(t *testing.T) {
	for _, tc := range []struct{ name, script, want string }{
		{"syntax", "def (", "test.star"},
		{"missing collect", "value = 1", "collect must be callable"},
		{"return type", "def collect(d): return []", "return a dict"},
		{"runtime", `def collect(d): fail("bad data")`, "bad data"},
		{"json", `def collect(d): return {"value": d.execute}`, "encode"},
		{"invalid import", `load("../outside.star", "value")`, "invalid model import"},
		{"absolute import", `load("/outside.star", "value")`, "invalid model import"},
		{"missing import", `load("missing.star", "value")`, "load missing.star"},
		{"self cycle", `load("test.star", "value")`, "cyclic model import"},
		{"regex", `load("re.star", "re")
def collect(d): return {"value": re.search("[", "text")}`, "error parsing regexp"},
		{"time", `load("time.star", "time")
def collect(d): return {"value": time.parse_ns("2026-01-01 00:00:00 XYZ", "2006-01-02 15:04:05 MST")}`, "unknown timezone"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := runner(t, tc.script)
			result, err := r.Collect(t.Context(), noCommands(t), "test", "test")
			require.ErrorContains(t, err, tc.want)
			require.Nil(t, result)
		})
	}
}

func TestCommandErrors(t *testing.T) {
	transportError := errors.New("transport failed")
	for _, tc := range []struct {
		name   string
		result cmd.CmdRes
		err    error
		want   string
	}{
		{"transport", nil, transportError, "transport failed"},
		{"status", cmd.NewCmdResFull([]byte("partial"), []byte("rejected"), 1, nil), nil, "rejected"},
		{"nil result", nil, nil, "empty result"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _ := runner(t, `def collect(d):
    d.execute("first")
    d.execute("must not run")
    return {}
`)
			calls := 0
			result, err := r.Collect(t.Context(), executor(func(context.Context, cmd.Cmd) (cmd.CmdRes, error) { calls++; return tc.result, tc.err }), "test", "test")
			require.ErrorContains(t, err, tc.want)
			require.Nil(t, result)
			require.Equal(t, 1, calls)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
			}
		})
	}
}

func TestLoading(t *testing.T) {
	r, dir := runner(t, `load("helper.star", "value")
def collect(d): return {"value": value}
`)
	for _, value := range []int{1, 2} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "helper.star"), []byte(fmt.Sprintf("value = %d\n", value)), 0600))
		result, err := r.Collect(t.Context(), noCommands(t), "test", "test")
		require.NoError(t, err)
		require.JSONEq(t, fmt.Sprintf(`{"value":%d}`, value), string(result))
	}
	_, err := r.Collect(t.Context(), noCommands(t), "test", "missing")
	require.ErrorIs(t, err, models.ErrNotFound)
	for _, name := range []string{"", "../test", "/test", "test.star", `a\b`} {
		_, err := r.Collect(t.Context(), noCommands(t), "test", name)
		require.ErrorIs(t, err, models.ErrInvalidName)
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "helper.star"), []byte(`load("test.star", "collect")`), 0600))
	_, err = r.Collect(t.Context(), noCommands(t), "test", "test")
	require.ErrorContains(t, err, "cyclic model import")
}

func TestSymlinkEscape(t *testing.T) {
	r, dir := runner(t, `load("escape.star", "value")
def collect(d): return {"value": value}
`)
	outside := filepath.Join(t.TempDir(), "outside.star")
	require.NoError(t, os.WriteFile(outside, []byte("value = 123"), 0600))
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "escape.star")))
	_, err := r.Collect(t.Context(), noCommands(t), "test", "test")
	require.Error(t, err)
	require.NoError(t, os.Symlink(outside, filepath.Join(dir, "outside.star")))
	_, err = r.Collect(t.Context(), noCommands(t), "test", "outside")
	require.Error(t, err)
}

func TestExecutionLimits(t *testing.T) {
	script := `def collect(d):
    value = 0
    for i in range(1000000000):
        value += i
    return {"value": value}
`
	r, _ := runner(t, script, models.WithMaxExecutionSteps(100))
	_, err := r.Collect(t.Context(), noCommands(t), "test", "test")
	require.ErrorContains(t, err, "too many steps")
	r, _ = runner(t, script, models.WithMaxExecutionSteps(1<<60))
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	_, err = r.Collect(ctx, noCommands(t), "test", "test")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	ctx, cancel = context.WithCancel(t.Context())
	cancel()
	_, err = r.Collect(ctx, noCommands(t), "test", "test")
	require.ErrorIs(t, err, context.Canceled)
	r, _ = runner(t, `def collect(d): return {"value": d.execute("wait")}`)
	ctx, cancel = context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	_, err = r.Collect(ctx, executor(func(ctx context.Context, _ cmd.Cmd) (cmd.CmdRes, error) { <-ctx.Done(); return nil, ctx.Err() }), "test", "test")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestConcurrentCollect(t *testing.T) {
	r, _ := runner(t, `def collect(d):
    values = []
    values.append(d.type)
    return {"values": values}
`)
	for i := range 20 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			result, err := r.Collect(t.Context(), noCommands(t), fmt.Sprint(i), "test")
			require.NoError(t, err)
			require.JSONEq(t, fmt.Sprintf(`{"values":["%d"]}`, i), string(result))
		})
	}
}

func TestRunnerConfiguration(t *testing.T) {
	_, err := models.New("")
	require.Error(t, err)
	_, err = models.New(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
	_, err = models.New(t.TempDir(), models.WithMaxExecutionSteps(0))
	require.Error(t, err)
	r, _ := runner(t, `def collect(d): return {}`)
	require.NoError(t, r.Check("test"))
	require.ErrorIs(t, r.Check("../test"), models.ErrInvalidName)
	require.ErrorIs(t, r.Check("missing"), models.ErrNotFound)
	_, err = r.Collect(t.Context(), nil, "test", "test")
	require.ErrorContains(t, err, "nil model device")
}

func TestCommandOptions(t *testing.T) {
	r, _ := runner(t, `def collect(d): return {"output": d.execute("show value")}`, models.WithCommandOptions(cmd.WithCmdTimeout(time.Second), cmd.WithReadTimeout(2*time.Second)))
	_, err := r.Collect(t.Context(), executor(func(_ context.Context, c cmd.Cmd) (cmd.CmdRes, error) {
		require.Equal(t, time.Second, c.GetCmdTimeout())
		require.Equal(t, 2*time.Second, c.GetReadTimeout())
		return cmd.NewCmdRes(nil), nil
	}), "test", "test")
	require.NoError(t, err)
}

func TestStandardModulesSharedWithinCollection(t *testing.T) {
	r, dir := runner(t, `load("helper.star", "helper_re")
load("re.star", "re")
def collect(d): return {"same": re == helper_re}
`)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "helper.star"), []byte(`load("re.star", "re")
helper_re = re
`), 0600))
	result, err := r.Collect(t.Context(), noCommands(t), "test", "test")
	require.NoError(t, err)
	require.JSONEq(t, `{"same": true}`, string(result))
}
