package server

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/device"
	"github.com/annetutil/gnetcli/pkg/models"
	pb "github.com/annetutil/gnetcli/pkg/server/proto"
	"github.com/annetutil/gnetcli/pkg/streamer"
	gateway "github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type modelTestDevice struct {
	fileTransferTestDevice
	execute      func(context.Context, cmd.Cmd) (cmd.CmdRes, error)
	connectCalls int
}

func (d *modelTestDevice) Connect(ctx context.Context) error {
	d.connectCalls++
	return d.fileTransferTestDevice.Connect(ctx)
}
func (d *modelTestDevice) ExecuteCtx(ctx context.Context, c cmd.Cmd) (cmd.CmdRes, error) {
	return d.execute(ctx, c)
}

func modelServer(t *testing.T, script string, dev *modelTestDevice) *Server {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "test.star"), []byte(script), 0600))
	runner, err := models.New(dir)
	require.NoError(t, err)
	srv := newFileTransferTestServer(dev)
	srv.deviceMaps = map[string]func(streamer.Connector) device.Device{"model-test": func(streamer.Connector) device.Device { return dev }}
	WithModelRunner(runner)(srv)
	return srv
}
func modelRequest() *pb.CollectModelRequest {
	return &pb.CollectModelRequest{Host: "device.example.net", Model: "test", HostParams: &pb.HostParams{Device: "model-test"}}
}

func TestCollectModelRPC(t *testing.T) {
	dev := &modelTestDevice{execute: func(_ context.Context, c cmd.Cmd) (cmd.CmdRes, error) {
		require.Equal(t, "show value", string(c.Value()))
		return cmd.NewCmdRes([]byte("1770000000123456789")), nil
	}}
	srv := modelServer(t, `def collect(d): return {"value": int(d.execute("show value")), "type": d.type}`, dev)
	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	pb.RegisterGnetcliServer(grpcServer, srv)
	go grpcServer.Serve(listener)
	t.Cleanup(grpcServer.Stop)
	conn, err := grpc.DialContext(t.Context(), "bufnet", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	client := pb.NewGnetcliClient(conn)
	result, err := client.CollectModel(t.Context(), modelRequest())
	require.NoError(t, err)
	require.Contains(t, result.Json, "1770000000123456789")
	require.Contains(t, result.Json, "model-test")
	require.Equal(t, 1, dev.closeCalls)

	mux := gateway.NewServeMux()
	require.NoError(t, pb.RegisterGnetcliHandler(t.Context(), mux, conn))
	response := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "/api/v1/collect_model", strings.NewReader(`{"host":"device.example.net","model":"test","host_params":{"device":"model-test"}}`))
	request.Header.Set("Content-Type", "application/json")
	mux.ServeHTTP(response, request)
	require.Equal(t, 200, response.Code, response.Body.String())
	var envelope struct {
		JSON string `json:"json"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &envelope))
	var data struct {
		Value int64 `json:"value"`
	}
	require.NoError(t, json.Unmarshal([]byte(envelope.JSON), &data))
	require.EqualValues(t, 1770000000123456789, data.Value)
	require.Equal(t, 2, dev.closeCalls)
}

func TestCollectModelErrors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		code       codes.Code
		connectErr error
		script     string
		alter      func(*Server, *pb.CollectModelRequest)
	}{
		{name: "disabled", code: codes.FailedPrecondition, alter: func(s *Server, _ *pb.CollectModelRequest) { s.modelRunner = nil }},
		{name: "empty host", code: codes.InvalidArgument, alter: func(_ *Server, r *pb.CollectModelRequest) { r.Host = "" }},
		{name: "invalid name", code: codes.InvalidArgument, alter: func(_ *Server, r *pb.CollectModelRequest) { r.Model = "../test" }},
		{name: "not found", code: codes.NotFound, alter: func(_ *Server, r *pb.CollectModelRequest) { r.Model = "missing" }},
		{name: "connect error", code: codes.Internal, connectErr: errors.New("connection failed")},
		{name: "connect deadline", code: codes.DeadlineExceeded, connectErr: context.DeadlineExceeded},
		{name: "script error", code: codes.Internal, script: `def collect(d): fail("bad data")`},
		{name: "command error", code: codes.Internal, script: `def collect(d): return {"value": d.execute("bad")}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := &modelTestDevice{fileTransferTestDevice: fileTransferTestDevice{connectErr: tc.connectErr}, execute: func(context.Context, cmd.Cmd) (cmd.CmdRes, error) {
				return cmd.NewCmdResFull(nil, []byte("rejected"), 1, nil), nil
			}}
			script := tc.script
			if script == "" {
				script = `def collect(d): return {}`
			}
			srv := modelServer(t, script, dev)
			req := modelRequest()
			if tc.alter != nil {
				tc.alter(srv, req)
			}
			result, err := srv.CollectModel(t.Context(), req)
			require.Equal(t, tc.code, status.Code(err), err)
			require.Nil(t, result)
			require.Equal(t, dev.connectCalls, dev.closeCalls)
		})
	}
}

func TestCollectModelCancellation(t *testing.T) {
	dev := &modelTestDevice{execute: func(ctx context.Context, _ cmd.Cmd) (cmd.CmdRes, error) { <-ctx.Done(); return nil, ctx.Err() }}
	srv := modelServer(t, `def collect(d): return {"value": d.execute("wait")}`, dev)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	_, err := srv.CollectModel(ctx, modelRequest())
	require.Equal(t, codes.DeadlineExceeded, status.Code(err))
	require.Equal(t, 1, dev.closeCalls)
	ctx, cancel = context.WithCancel(t.Context())
	cancel()
	_, err = srv.CollectModel(ctx, modelRequest())
	require.Equal(t, codes.Canceled, status.Code(err))
	require.Equal(t, 1, dev.closeCalls)
}

func TestCollectModelStoredHostParams(t *testing.T) {
	dev := &modelTestDevice{}
	srv := modelServer(t, `def collect(d): return {"type": d.type}`, dev)
	_, err := srv.SetupHostParams(t.Context(), &pb.HostParams{Host: "device.example.net", Device: "model-test"})
	require.NoError(t, err)
	req := modelRequest()
	req.HostParams = nil
	result, err := srv.CollectModel(t.Context(), req)
	require.NoError(t, err)
	require.Contains(t, result.Json, "model-test")
}

func TestModelsDirectoryConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"yaml", nil, "/configured/models"},
		{"override", []string{"--models-dir", "/flag/models"}, "/flag/models"},
		{"disable", []string{"--models-dir="}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(file, []byte("models_dir: /configured/models\n"), 0600))
			oldFlags, oldArgs := flag.CommandLine, os.Args
			flag.CommandLine = flag.NewFlagSet("config-test", flag.ContinueOnError)
			os.Args = append([]string{"test", "--conf-file", file}, tc.args...)
			t.Cleanup(func() { flag.CommandLine = oldFlags; os.Args = oldArgs })
			config, err := LoadConf()
			require.NoError(t, err)
			require.Equal(t, tc.want, config.ModelsDir)
		})
	}
}

func TestCollectModelCommandTimeoutDefaults(t *testing.T) {
	dev := &modelTestDevice{execute: func(_ context.Context, c cmd.Cmd) (cmd.CmdRes, error) {
		require.Equal(t, 3*time.Second, c.GetCmdTimeout())
		require.Equal(t, 2*time.Second, c.GetReadTimeout())
		return cmd.NewCmdRes([]byte("ok")), nil
	}}
	srv := modelServer(t, `def collect(d): return {"value": d.execute("show value")}`, dev)
	WithDefaultCmdTimeout(3 * time.Second)(srv)
	WithDefaultReadTimeout(2 * time.Second)(srv)
	_, err := srv.CollectModel(t.Context(), modelRequest())
	require.NoError(t, err)
}
