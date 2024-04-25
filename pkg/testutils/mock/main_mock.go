package mock

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/streamer"
	"github.com/annetutil/gnetcli/pkg/streamer/ssh"
)

func ConcatMultipleSlices[T any](slices [][]T) []T {
	var totalLen int

	for _, s := range slices {
		totalLen += len(s)
	}

	result := make([]T, totalLen)

	var i int

	for _, s := range slices {
		i += copy(result[i:], s)
	}

	return result
}

type deviceMaker func(streamer.Connector) device.Device

func RunDialogWithDefaultCreds(t *testing.T, devMaker deviceMaker, dialog []Action, command, expected string) {
	RunDialog(t, devMaker, dialog, command, expected, credentials.NewSimpleCredentials())
}

func RunDialog(t *testing.T, devMaker deviceMaker, dialog []Action, command, expected string, creds credentials.Credentials) {
	// Mock SSH server setup
	sshServer, err := NewMockSSHServer(dialog, WithLogger(zap.Must(zap.NewDevelopmentConfig().Build())))
	require.NoError(t, err, "failed to start mock ssh server: %s", err)
	ctx := context.Background()
	g := new(errgroup.Group)
	g.Go(func() error {
		return sshServer.Run(ctx)
	})

	connector := ssh.NewStreamer([]ssh.Endpoint{sshServer.GetAddress()}, creds, ssh.WithLogger(zap.Must(zap.NewDevelopmentConfig().Build())))
	dev := devMaker(connector)
	connCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = dev.Connect(connCtx)
	require.NoError(t, err, "failed to connect to device: %s", err)

	res, err := dev.Execute(cmd.NewCmd(command))
	require.NoError(t, err, "failed to execute command %s: %s", command, err)
	require.Equal(t, expected, string(res.Output()), "should be equal")

	dev.Close()

	err = g.Wait()
	require.NoError(t, err, "dialog failed: %s", err)
}

func RunInvalidDialog(t *testing.T, devMaker deviceMaker, dialog []Action, command string) {
	// Mock SSH server setup

	sshServer, err := NewMockSSHServer(dialog, WithLogger(zap.Must(zap.NewDevelopmentConfig().Build())))
	require.NoError(t, err, "failed to start mock ssh server: %s", err)

	g := new(errgroup.Group)
	ctx := context.Background()
	g.Go(func() error {
		err := sshServer.Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return err
	})

	connector := ssh.NewStreamer([]ssh.Endpoint{sshServer.GetAddress()}, credentials.NewSimpleCredentials())
	dev := devMaker(connector)

	connCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	err = dev.Connect(connCtx)
	require.NoError(t, err, "failed to connect to device: %s", err)

	res, err := dev.Execute(cmd.NewCmd(command))
	require.NoError(t, err)
	require.Equal(t, 1, res.Status())
	require.True(t, len(res.Error()) > 0)

	dev.Close()

	err = g.Wait()
	require.NoError(t, err, "dialog failed: %s", err)
}

func RunInvalidDialogWithException(t *testing.T, devMaker deviceMaker, dialog []Action, command string, expErr error) {
	// Mock SSH server setup

	sshServer, err := NewMockSSHServer(dialog, WithLogger(zap.Must(zap.NewDevelopmentConfig().Build())))
	require.NoError(t, err, "failed to start mock ssh server: %s", err)

	g := new(errgroup.Group)
	ctx := context.Background()
	g.Go(func() error {
		err := sshServer.Run(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return err
	})

	connector := ssh.NewStreamer([]ssh.Endpoint{sshServer.GetAddress()}, credentials.NewSimpleCredentials())
	dev := devMaker(connector)

	connCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	err = dev.Connect(connCtx)
	require.NoError(t, err, "failed to connect to device: %s", err)

	res, err := dev.Execute(cmd.NewCmd(command))
	require.Nil(t, res)
	require.Error(t, err)
	require.Equal(t, expErr, err)

	dev.Close()

	err = g.Wait()
	require.NoError(t, err, "dialog failed: %s", err)
}

func RunCmd(devMaker deviceMaker, dialog []Action, commands []cmd.Cmd, logger *zap.Logger, serverNetwork, clientNetwork string) (cmdRes []cmd.CmdRes, resErr, serverErr, err error) {
	// Mock SSH server setup

	sshServer, err := NewMockSSHServer(dialog, WithLogger(logger), WithNetwork(serverNetwork))
	if err != nil {
		return nil, nil, nil, err
	}

	g := new(errgroup.Group)
	ctx := context.Background()
	g.Go(func() error {
		err := sshServer.Run(ctx)
		return err
	})

	endpoint := sshServer.GetAddress()
	endpoint.Network = ssh.Network(clientNetwork)
	connector := ssh.NewStreamer([]ssh.Endpoint{endpoint}, credentials.NewSimpleCredentials(), ssh.WithLogger(logger))
	dev := devMaker(connector)

	connCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()

	err = dev.Connect(connCtx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to connect to device: %w", err)
	}
	cmdRes = []cmd.CmdRes{}
	for _, command := range commands {
		res, err := dev.Execute(command)
		if err != nil {
			return cmdRes, err, nil, nil
		}
		cmdRes = append(cmdRes, res)
	}

	dev.Close()

	err = g.Wait()
	return cmdRes, nil, err, nil
}
