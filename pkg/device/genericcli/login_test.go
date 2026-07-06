package genericcli

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	gmock "github.com/annetutil/gnetcli/pkg/testutils/mock"

	"github.com/annetutil/gnetcli/pkg/credentials"
	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/gerror"
	"github.com/annetutil/gnetcli/pkg/streamer/ssh"
)

const (
	loginPromptExpression      = `(\r\n|^)(?P<prompt>(<\w+>))$`
	loginErrorExpression       = `(\r\n|^)Error: .+$`
	loginUsernameExpression    = `.*Username:$`
	loginPasswordExpression    = `.*Password:$`
	loginPasswordErrExpression = `.*Authentication failed(\r\n|\n)$`
)

func runManualLogin(t *testing.T, dialog []gmock.Action, creds credentials.Credentials) error {
	t.Helper()
	logger := zap.Must(zap.NewDevelopmentConfig().Build())

	sshServer, err := gmock.NewMockSSHServer(dialog, gmock.WithLogger(logger))
	require.NoError(t, err)

	ctx := context.Background()
	g := new(errgroup.Group)
	g.Go(func() error {
		return sshServer.Run(ctx)
	})

	host, port := sshServer.GetAddress()
	connector := ssh.NewStreamer(host, creds, ssh.WithPort(port), ssh.WithLogger(logger))
	cli := MakeGenericCLI(
		expr.NewSimpleExprLast200().FromPattern(loginPromptExpression),
		expr.NewSimpleExprLast200().FromPattern(loginErrorExpression),
		WithLoginExprs(
			expr.NewSimpleExprLast200().FromPattern(loginUsernameExpression),
			expr.NewSimpleExprLast200().FromPattern(loginPasswordExpression),
			expr.NewSimpleExprLast200().FromPattern(loginPasswordErrExpression),
		),
		WithManualAuth(),
	)
	dev := MakeGenericDevice(cli, connector, WithDevLogger(logger))

	connCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	require.NoError(t, dev.Connect(connCtx))

	err = dev.connectCLI(connCtx)
	dev.Close()
	_ = g.Wait()
	return err
}

func TestManualLoginPasswordFirstTry(t *testing.T) {
	dialog := gmock.ConcatMultipleSlices([][]gmock.Action{
		{
			gmock.Send("\r\nPassword:"),
			gmock.Expect("p4$$М0rD!\n"),
			gmock.Send("\r\n<device>"),
		},
	})
	creds := credentials.NewSimpleCredentials(
		credentials.WithUsername("admin"),
		credentials.WithPassword("p4$$М0rD!"),
	)

	err := runManualLogin(t, dialog, creds)
	require.NoError(t, err)
}

func TestManualLoginUsernameAndPassword(t *testing.T) {
	dialog := gmock.ConcatMultipleSlices([][]gmock.Action{
		{
			gmock.Send("\r\nUsername:"),
			gmock.Expect("admin\n"),
			gmock.Send("\r\nPassword:"),
			gmock.Expect("p4$$М0rD!\n"),
			gmock.Send("\r\n<device>"),
		},
	})
	creds := credentials.NewSimpleCredentials(
		credentials.WithUsername("admin"),
		credentials.WithPassword("p4$$М0rD!"),
	)

	err := runManualLogin(t, dialog, creds)
	require.NoError(t, err)
}

func TestManualLoginPasswordRetry(t *testing.T) {
	dialog := gmock.ConcatMultipleSlices([][]gmock.Action{
		{
			gmock.Send("\r\nPassword:"),
			gmock.Expect("p4$$М0rD!\n"),
			gmock.Send("\r\nAuthentication failed\r\n"),
			gmock.Send("\r\nPassword:"),
			gmock.Expect("admin\n"),
			gmock.Send("\r\n<device>"),
		},
	})
	creds := credentials.NewSimpleCredentials(
		credentials.WithUsername("admin"),
		credentials.WithPasswords([]credentials.Secret{"p4$$М0rD!", "admin"}),
	)

	err := runManualLogin(t, dialog, creds)
	require.NoError(t, err)
}

func TestManualLoginAllPasswordsRejected(t *testing.T) {
	dialog := gmock.ConcatMultipleSlices([][]gmock.Action{
		{
			gmock.Send("\r\nPassword:"),
			gmock.Expect("p4$$М0rD!\n"),
			gmock.Send("\r\nAuthentication failed\r\n"),
			gmock.Send("\r\nPassword:"),
			gmock.Expect("admin\n"),
			gmock.Send("\r\nAuthentication failed\r\n"),
			gmock.Close(),
		},
	})
	creds := credentials.NewSimpleCredentials(
		credentials.WithUsername("admin"),
		credentials.WithPasswords([]credentials.Secret{"p4$$М0rD!", "admin"}),
	)

	err := runManualLogin(t, dialog, creds)
	require.Error(t, err)
	var authErr *gerror.AuthException
	require.ErrorAs(t, err, &authErr, "")
	require.EqualError(t, err, "auth error cli auth user")
}

func TestManualLoginEmptyPasswordList(t *testing.T) {
	dialog := gmock.ConcatMultipleSlices([][]gmock.Action{
		{
			gmock.Send("\r\nPassword:"),
		},
	})
	creds := credentials.NewSimpleCredentials(
		credentials.WithUsername("admin"),
	)

	err := runManualLogin(t, dialog, creds)
	require.EqualError(t, err, "no passwords supplied")
}

func TestManualLoginNoPassword(t *testing.T) {
	dialog := gmock.ConcatMultipleSlices([][]gmock.Action{
		{
			gmock.Send("\r\nUsername:"),
			gmock.Expect("admin\n"),
			gmock.Send("\r\n<device>"),
		},
	})
	creds := credentials.NewSimpleCredentials(
		credentials.WithUsername("admin"),
	)

	err := runManualLogin(t, dialog, creds)
	require.NoError(t, err)
}
