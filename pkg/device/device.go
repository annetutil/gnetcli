/*
Package device describes high-level interface for interaction with a device.
*/
package device

import (
	"context"
	"errors"

	gcmd "github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/streamer"
)

var ErrorStreamerNotSupportedByDevice = errors.New("unsupported streamer")

type Device interface {
	Connect(ctx context.Context) error
	Execute(command gcmd.Cmd) (gcmd.CmdRes, error)
	Download(paths []string) (map[string]streamer.File, error)
	Upload(paths map[string]streamer.File) error
	Close()
	GetAux() map[string]any
	// get any additional data
}

func ExecuteBulk(dev Device, commands []gcmd.Cmd) ([]gcmd.CmdRes, error) {
	var res []gcmd.CmdRes
	for _, command := range commands {
		out, err := dev.Execute(command)
		if err != nil {
			return nil, err
		}
		res = append(res, out)
	}
	return res, nil
}

type SFTPSupport interface {
	EnableSFTP()
}
