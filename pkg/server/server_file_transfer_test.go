package server

import (
	"context"
	"errors"
	"testing"

	gcmd "github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device"
	pb "github.com/annetutil/gnetcli/pkg/server/proto"
	"github.com/annetutil/gnetcli/pkg/streamer"
	"go.uber.org/zap"
)

var errFileTransferTest = errors.New("file transfer failed")

type fileTransferTestDevice struct {
	connectErr  error
	downloadErr error
	uploadErr   error
	closeCalls  int
}

func (d *fileTransferTestDevice) Connect(context.Context) error {
	return d.connectErr
}

func (d *fileTransferTestDevice) Execute(gcmd.Cmd) (gcmd.CmdRes, error) {
	return nil, streamer.ErrNotSupported
}

func (d *fileTransferTestDevice) ExecuteCtx(context.Context, gcmd.Cmd) (gcmd.CmdRes, error) {
	return nil, streamer.ErrNotSupported
}

func (d *fileTransferTestDevice) Download([]string) (map[string]streamer.File, error) {
	return map[string]streamer.File{}, d.downloadErr
}

func (d *fileTransferTestDevice) Upload(map[string]streamer.File) error {
	return d.uploadErr
}

func (d *fileTransferTestDevice) Close() {
	d.closeCalls++
}

func (d *fileTransferTestDevice) GetAux() map[string]any {
	return nil
}

func newFileTransferTestServer(dev device.Device) *Server {
	logger := zap.NewNop()
	return &Server{
		log:        logger,
		deviceMaps: map[string]func(streamer.Connector) device.Device{"file-transfer-test": func(streamer.Connector) device.Device { return dev }},
		hostParams: map[string]hostParams{},
		devAuthApp: NewAuthApp(authAppConfig{}, logger),
	}
}

func TestDownloadClosesDevice(t *testing.T) {
	tests := []struct {
		name        string
		connectErr  error
		downloadErr error
	}{
		{name: "success"},
		{name: "connect error", connectErr: errFileTransferTest},
		{name: "download error", downloadErr: errFileTransferTest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev := &fileTransferTestDevice{connectErr: tt.connectErr, downloadErr: tt.downloadErr}
			srv := newFileTransferTestServer(dev)

			_, _ = srv.Download(t.Context(), &pb.FileDownloadRequest{
				Host:       "device.example.net",
				Paths:      []string{"/tmp/config"},
				HostParams: &pb.HostParams{Device: "file-transfer-test"},
			})

			if dev.closeCalls != 1 {
				t.Fatalf("Close called %d times, want 1", dev.closeCalls)
			}
		})
	}
}

func TestUploadClosesDevice(t *testing.T) {
	tests := []struct {
		name       string
		connectErr error
		uploadErr  error
	}{
		{name: "success"},
		{name: "connect error", connectErr: errFileTransferTest},
		{name: "upload error", uploadErr: errFileTransferTest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev := &fileTransferTestDevice{connectErr: tt.connectErr, uploadErr: tt.uploadErr}
			srv := newFileTransferTestServer(dev)

			_, _ = srv.Upload(t.Context(), &pb.FileUploadRequest{
				Host: "device.example.net",
				Files: []*pb.FileData{
					{Path: "/tmp/config", Data: []byte("config")},
				},
				HostParams: &pb.HostParams{Device: "file-transfer-test"},
			})

			if dev.closeCalls != 1 {
				t.Fatalf("Close called %d times, want 1", dev.closeCalls)
			}
		})
	}
}
