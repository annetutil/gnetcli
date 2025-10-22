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
