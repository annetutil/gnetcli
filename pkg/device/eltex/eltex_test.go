package eltex

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/testutils"
)

func TestErrors(t *testing.T) {

	errorCases := [][]byte{
		[]byte("              ^\r\n% Invalid input detected at '^' marker\r\n"),
		[]byte("\r% Ambiguous Command\r\n"),
		[]byte("\r% Invalid Command\r\n"),
		[]byte("\r% Unrecognized command\r\n"),
		[]byte("\r% Incomplete command.\r\n"),
	}
	testutils.ExprTester(t, errorCases, errorExpression)
}

func TestPrompt(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\ndcx1-j1#"),
		[]byte("\r\nhost-s2(config)#"),
		[]byte("\r\nhost-s2(config-if)#"),
		[]byte("\r\nhost-s2(config-sntp)#"),
		[]byte("\r\nhost-s2.abc.def(config-vlan)#"),
	}
	testutils.ExprTester(t, errorCases, promptExpression)
}

func TestLogin(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\t\tEltex Switch\n\nmes2424-acher22p9pd login: "),
		[]byte("\n\n\n\nUser Name:"),
	}
	testutils.ExprTester(t, errorCases, loginExpression)
}

func TestPassword(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\nPassword: "),
	}
	testutils.ExprTester(t, errorCases, passwordExpression)
}

func TestErrorPassword(t *testing.T) {
	cases := [][]byte{
		[]byte("\n\n% Incorrect Login/Password\n\n"),
		[]byte("\nauthentication failed\n\n\npress ENTER key to retry authentication\n"),
	}
	testutils.ExprTester(t, cases, passwordErrorExpression)
}
