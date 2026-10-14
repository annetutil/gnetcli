package main

import (
	"context"
	"encoding/json"
	"flag"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device/cisco"
	sshstream "github.com/annetutil/gnetcli/pkg/streamer/ssh"
	"github.com/stretchr/testify/require"
)

func TestSwitchProcess(t *testing.T) {
	if os.Getenv("GSWITCH_TEST_PROCESS") != "1" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("GSWITCH_TEST_ARGS")), &args); err != nil {
		panic(err)
	}
	flag.CommandLine = flag.NewFlagSet("gswitch", flag.ExitOnError)
	os.Args = append([]string{os.Args[0]}, args...)
	main()
	os.Exit(0)
}

func TestConfigAndReadyFileCLI(t *testing.T) {
	dir := t.TempDir()
	configFile, readyFile := filepath.Join(dir, "config.txt"), filepath.Join(dir, "ready.json")
	require.NoError(t, os.WriteFile(configFile, []byte("interface Ethernet1\n description initial\n!\n"), 0600))
	args, err := json.Marshal([]string{"-host", "127.0.0.1", "-port", "0", "-enable-telnet", "-telnet-port", "0", "-username", "test", "-password", "secret", "-config-file", configFile, "-ready-file", readyFile})
	require.NoError(t, err)
	process := exec.Command(os.Args[0], "-test.run=^TestSwitchProcess$")
	process.Env = append(os.Environ(), "GSWITCH_TEST_PROCESS=1", "GSWITCH_TEST_ARGS="+string(args))
	logfile, err := os.Create(filepath.Join(dir, "server.log"))
	require.NoError(t, err)
	defer logfile.Close()
	process.Stdout, process.Stderr = logfile, logfile
	require.NoError(t, process.Start())
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	t.Cleanup(func() {
		_ = process.Process.Kill()
	})
	var addresses map[string]string
	require.Eventually(t, func() bool {
		data, err := os.ReadFile(readyFile)
		if err != nil {
			return false
		}
		require.NoError(t, json.Unmarshal(data, &addresses), "ready file must appear atomically")
		return true
	}, 5*time.Second, 10*time.Millisecond)
	require.Len(t, addresses, 2)
	host, port, err := net.SplitHostPort(addresses["ssh"])
	require.NoError(t, err)
	n, err := strconv.Atoi(port)
	require.NoError(t, err)
	require.NotZero(t, n)
	require.NotEqual(t, addresses["ssh"], addresses["telnet"])
	dev := cisco.NewDevice(sshstream.NewStreamer(host, credentials.NewSimpleCredentials(credentials.WithUsername("test"), credentials.WithPassword("secret")), sshstream.WithPort(n)))
	defer dev.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, dev.Connect(ctx))
	result, err := dev.ExecuteCtx(ctx, cmd.NewCmd("show running-config"))
	require.NoError(t, err)
	require.Zero(t, result.Status())
	require.Contains(t, string(result.Output()), "description initial")
	require.NoError(t, process.Process.Signal(syscall.SIGTERM))
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("gswitch did not shut down")
	}
	_, err = os.Stat(readyFile)
	require.True(t, os.IsNotExist(err))
}

func TestInvalidConfigDoesNotLeaveReadinessFile(t *testing.T) {
	dir := t.TempDir()
	configFile, readyFile := filepath.Join(dir, "invalid.cfg"), filepath.Join(dir, "ready.json")
	require.NoError(t, os.WriteFile(configFile, []byte(" description orphan\n"), 0600))
	require.NoError(t, os.WriteFile(readyFile, []byte("stale"), 0600))
	args, err := json.Marshal([]string{"-config-file", configFile, "-ready-file", readyFile})
	require.NoError(t, err)
	process := exec.Command(os.Args[0], "-test.run=^TestSwitchProcess$")
	process.Env = append(os.Environ(), "GSWITCH_TEST_PROCESS=1", "GSWITCH_TEST_ARGS="+string(args))
	output, err := process.CombinedOutput()
	require.Error(t, err)
	require.Contains(t, string(output), "indented command outside an interface")
	_, err = os.Stat(readyFile)
	require.True(t, os.IsNotExist(err))
}
