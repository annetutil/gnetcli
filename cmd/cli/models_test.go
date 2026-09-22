package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	m "github.com/annetutil/gnetcli/pkg/testutils/mock"
	"github.com/stretchr/testify/require"
)

func TestCLIModelArguments(t *testing.T) {
	for _, args := range [][]string{
		{"-model", "uptime"},
		{"-model", "uptime", "-models-dir", "models", "-command", "show version"},
		{"-model", "uptime", "-models-dir", "models", "-test"},
		{"-models-dir", "models"},
	} {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		process := osexec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestCLIProcess$", "--"}, args...)...)
		process.Env = append(os.Environ(), "GNETCLI_TEST_PROCESS=1")
		output, err := process.CombinedOutput()
		cancel()
		var exit *osexec.ExitError
		require.ErrorAs(t, err, &exit, string(output))
		require.Equal(t, 2, exit.ExitCode())
		require.Contains(t, string(output), "-model")
	}
}

func TestCLIModel(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(strconv.FormatBool(fail), func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "sample.star"), []byte(`def collect(d): return {"value": int(d.execute("show value")), "type": d.type}`), 0600))
			value := "1770000000123456789"
			if fail {
				value = "% Invalid command"
			}
			dialog := []m.Action{m.Send("lab#")}
			for _, command := range []string{"terminal length 0", "enable"} {
				dialog = append(dialog, m.Expect(command+"\n"), m.SendEcho(command+"\r\n"), m.Send("lab#"))
			}
			dialog = append(dialog, m.Expect("show value\n"), m.SendEcho("show value\r\n"), m.Send(value+"\r\nlab#"))
			server, err := m.NewMockSSHServer(dialog)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- server.Run(ctx) }()
			host, port := server.GetAddress()
			args := []string{"-test.run=^TestCLIProcess$", "--", "-hostname", host, "-port", strconv.Itoa(port), "-devtype", "arista", "-models-dir", dir, "-model", "sample"}
			process := osexec.CommandContext(ctx, os.Args[0], args...)
			process.Env = append(os.Environ(), "GNETCLI_TEST_PROCESS=1")
			var stdout, stderr bytes.Buffer
			process.Stdout = &stdout
			process.Stderr = &stderr
			err = process.Run()
			if fail {
				var exit *osexec.ExitError
				require.ErrorAs(t, err, &exit, stderr.String())
				require.Equal(t, 1, exit.ExitCode())
				require.Empty(t, stdout.String())
			} else {
				require.NoError(t, err, stderr.String())
				var result struct {
					Value int64
					Type  string
				}
				require.NoError(t, json.Unmarshal(stdout.Bytes(), &result))
				require.EqualValues(t, 1770000000123456789, result.Value)
				require.Equal(t, "arista", result.Type)
			}
			select {
			case err := <-done:
				require.NoError(t, err)
			case <-ctx.Done():
				t.Fatal("connection was not closed")
			}
		})
	}
}
