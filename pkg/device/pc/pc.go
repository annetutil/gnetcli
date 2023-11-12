/*
Package pc implements upon generic SSH-server with ability to exec like Linux, macOS, etc.
*/
package pc

import (
	"context"

	gcmd "github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

var _ device.Device = (*Device)(nil)

type Device struct {
	connector   streamer.Connector
	credentials credentials.Credentials
}

func (m *Device) GetAux() map[string]any {
	return nil
}

func NewDevice(connector streamer.Connector) device.Device {
	return &Device{
		connector:   connector,
		credentials: nil,
	}
}

func (m *Device) Connect(ctx context.Context) error {
	err := m.connector.Init(ctx)
	if sftpSupported, ok := m.connector.(device.SFTPSupport); ok {
		sftpSupported.EnableSFTP()
	}
	if err != nil {
		return err
	}
	if !m.connector.HasFeature(streamer.Cmd) {
		return device.ErrorStreamerNotSupportedByDevice
	}
	return nil
}

func (m *Device) Close() {
	m.connector.Close()
}

func (m *Device) Execute(command gcmd.Cmd) (gcmd.CmdRes, error) {
	ctx := context.Background()
	if cmdTimeout := command.GetCmdTimeout(); cmdTimeout > 0 {
		newCtx, cancel := context.WithTimeout(ctx, cmdTimeout)
		ctx = newCtx
		defer cancel()
	}
	if command.GetAgentForward() {
		err := m.connector.InitAgentForward()
		if err != nil {
			return nil, err
		}
	}
	return m.connector.Cmd(ctx, string(command.Value()))
}

func (m *Device) Download(paths []string) (map[string]streamer.File, error) {
	res, err := m.connector.Download(paths, true)
	return res, err
}

func (m *Device) Upload(paths map[string]streamer.File) error {
	err := m.connector.Upload(paths)
	return err
}
