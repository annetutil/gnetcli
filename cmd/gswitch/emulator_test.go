package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEmulatorChildProcess(t *testing.T) {
	if os.Getenv("GSWITCH_EMULATOR_CHILD") != "1" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("GSWITCH_EMULATOR_ARGS")), &args); err != nil {
		panic(err)
	}
	flag.CommandLine = flag.NewFlagSet("gswitch", flag.ExitOnError)
	os.Args = append([]string{os.Args[0]}, args...)
	if err := run(); err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

type profileProcessCase struct {
	profile, usernamePrompt, passwordPrompt, loginPrompt, prepare, prompt, slowCommand string
}

func TestDeclarativeProfileProcess(t *testing.T) {
	for _, tc := range []profileProcessCase{
		{"iosxe.yaml", "Username: ", "Password: ", "sw1>", "enable", "sw1#", "show slow"},
		{"huawei.yaml", "Username:", "Password:", "<sw1>", "", "<sw1>", "display slow"},
	} {
		t.Run(tc.profile, func(t *testing.T) { testDeclarativeProfileProcess(t, tc) })
	}
}

func testDeclarativeProfileProcess(t *testing.T, tc profileProcessCase) {
	t.Helper()
	dir := t.TempDir()
	ready := filepath.Join(dir, "ready.json")
	root, err := filepath.Abs("../../examples/gswitch")
	require.NoError(t, err)
	args, err := json.Marshal([]string{"-host", "127.0.0.1", "-port", "0", "-console-port", "0", "-profile", filepath.Join(root, tc.profile), "-scenario", filepath.Join(root, "noisy.yaml"), "-ready-file", ready, "-username", "test", "-password", "secret"})
	require.NoError(t, err)
	process := exec.Command(os.Args[0], "-test.run=^TestEmulatorChildProcess$")
	process.Env = append(os.Environ(), "GSWITCH_EMULATOR_CHILD=1", "GSWITCH_EMULATOR_ARGS="+string(args))
	logfile, err := os.Create(filepath.Join(dir, "server.log"))
	require.NoError(t, err)
	defer logfile.Close()
	process.Stdout, process.Stderr = logfile, logfile
	require.NoError(t, process.Start())
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	t.Cleanup(func() { _ = process.Process.Kill() })
	var addresses map[string]string
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(ready)
		if err != nil {
			return false
		}
		return json.Unmarshal(b, &addresses) == nil
	}, 5*time.Second, 10*time.Millisecond)
	require.NotEmpty(t, addresses["ssh"])
	require.NotEmpty(t, addresses["console"])
	c, err := net.Dial("tcp", addresses["console"])
	require.NoError(t, err)
	defer c.Close()
	r := bufio.NewReader(c)
	var transcript strings.Builder
	read := func(suffix string) string {
		require.NoError(t, c.SetReadDeadline(time.Now().Add(5*time.Second)))
		var out strings.Builder
		for !strings.HasSuffix(out.String(), suffix) {
			b, err := r.ReadByte()
			require.NoError(t, err)
			out.WriteByte(b)
		}
		transcript.WriteString(out.String())
		return out.String()
	}
	read(tc.usernamePrompt)
	_, err = io.WriteString(c, "test\n")
	require.NoError(t, err)
	read(tc.passwordPrompt)
	_, err = io.WriteString(c, "secret\n")
	require.NoError(t, err)
	require.NotContains(t, read(tc.loginPrompt), "secret")
	if tc.prepare != "" {
		_, err = io.WriteString(c, tc.prepare+"\n")
		require.NoError(t, err)
		read(tc.prompt)
	}
	_, err = io.WriteString(c, tc.slowCommand+"\n")
	require.NoError(t, err)
	output := read("Body\r\n" + tc.prompt)
	require.Contains(t, output, "Header\r\nSYSLOG: event between command output chunks\r\n")
	require.Contains(t, transcript.String(), "SYSTEM: background initialization after login")
	require.NoError(t, process.Process.Signal(syscall.SIGTERM))
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("emulator process did not stop")
	}
	_, err = os.Stat(ready)
	require.True(t, os.IsNotExist(err))
}
