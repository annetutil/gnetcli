package aruos

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/testutils"
)

func TestPrompt(t *testing.T) {
	cases := [][]byte{
		[]byte("\r\nrrrrrr-w1# "),
		[]byte("\r\nrrrrrr-w1 (config) # "),
		[]byte("\r\n00:4e:35:11:22:33# "),
		[]byte("\r\n00:4e:35:11:22:33 (config) # "),
	}
	testutils.ExprTester(t, cases, promptExpression)
}

func TestErrors(t *testing.T) {
	cases := [][]byte{
		[]byte("            ^\r\n% Parse error"),
		[]byte("% Incomplete command."),
	}
	testutils.ExprTester(t, cases, errorExpression)
}

func TestLogin(t *testing.T) {
	cases := [][]byte{
		[]byte("\r\n\r\nUser: "),
		[]byte("Login incorrect, reason code 6\r\nUser: "),
	}
	testutils.ExprTester(t, cases, loginExpression)
}

func TestLoginFail(t *testing.T) {
	cases := [][]byte{
		[]byte("Login incorrect, reason code 6\r\n"),
	}
	testutils.ExprTester(t, cases, passwordErrorExpression)
}
