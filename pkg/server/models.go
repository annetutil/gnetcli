package server

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/annetutil/gnetcli/pkg/cmd"
	"github.com/annetutil/gnetcli/pkg/models"
	pb "github.com/annetutil/gnetcli/pkg/server/proto"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// WithModelRunner enables collection of externally supplied Starlark models.
func WithModelRunner(runner *models.Runner) Option {
	return func(s *Server) { s.modelRunner = runner }
}

// CollectModel uses the same authentication, host resolution and transports as Exec.
func (s *Server) CollectModel(ctx context.Context, req *pb.CollectModelRequest) (*pb.CollectModelResult, error) {
	if req == nil || strings.TrimSpace(req.GetHost()) == "" || req.GetModel() == "" {
		return nil, status.Error(codes.InvalidArgument, "host and model are required")
	}
	if s.modelRunner == nil {
		return nil, status.Error(codes.FailedPrecondition, "models are disabled")
	}
	if err := ctx.Err(); err != nil {
		return nil, status.FromContextError(err).Err()
	}
	if err := s.modelRunner.Check(req.GetModel()); err != nil {
		return nil, modelRPCError(err)
	}
	params, err := s.getHostParams(req.GetHost(), req.GetHostParams())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if params.GetDevice() == "" {
		return nil, status.Error(codes.InvalidArgument, "device type is required")
	}
	dev, err := s.makeDevice(req.GetHost(), params, nil, s.log.With(zap.String("host", req.GetHost()), zap.String("model", req.GetModel())))
	if err != nil {
		return nil, modelRPCError(err)
	}
	defer dev.Close()
	// Bound connection setup even when the RPC caller provides no deadline.
	connectCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err = dev.Connect(connectCtx)
	cancel()
	if err != nil {
		return nil, modelRPCError(err)
	}
	result, err := s.modelRunner.Collect(ctx, modelExecutor{Executor: dev, cmdTimeout: s.defaultCmdTimeout, readTimeout: s.defaultReadTimeout}, params.GetDevice(), req.GetModel())
	if err != nil {
		return nil, modelRPCError(err)
	}
	return &pb.CollectModelResult{Json: string(result)}, nil
}

func modelRPCError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return status.FromContextError(err).Err()
	case errors.Is(err, models.ErrInvalidName):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, models.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	default:
		return makeGRPCDeviceExecError(err)
	}
}

// Apply server command defaults without losing the runner's answer/callback options.
type modelExecutor struct {
	models.Executor
	cmdTimeout, readTimeout time.Duration
}

func (e modelExecutor) ExecuteCtx(ctx context.Context, command cmd.Cmd) (cmd.CmdRes, error) {
	return e.Executor.ExecuteCtx(ctx, modelCommand{Cmd: command, cmdTimeout: e.cmdTimeout, readTimeout: e.readTimeout})
}

type modelCommand struct {
	cmd.Cmd
	cmdTimeout, readTimeout time.Duration
}

func (c modelCommand) GetCmdTimeout() time.Duration {
	if c.cmdTimeout > 0 {
		return c.cmdTimeout
	}
	return c.Cmd.GetCmdTimeout()
}

func (c modelCommand) GetReadTimeout() time.Duration {
	if c.readTimeout > 0 {
		return c.readTimeout
	}
	return c.Cmd.GetReadTimeout()
}
