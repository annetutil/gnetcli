package cisco

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/expr"
	"github.com/annetutil/gnetcli/pkg/testutils"
)

func TestErrors(t *testing.T) {
	errorCases := [][]byte{
		[]byte("              ^\r\n% Invalid input detected at '^' marker.\r\n\r\n"),
		[]byte("% Bad IP address or host name% Unknown command or computer name, or unable to find computer address"),
		[]byte("% Ambiguous command:  \"dis clock\""),
		[]byte("                  ^\n% Ambiguous command at '^' marker."),
	}
	testutils.ExprTester(
		t,
		errorCases,
		expr.NewExprMatcher(errorExpression, nil),
	)
}

func TestPrompt(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\ndcx1-j1#"),
		[]byte("\r\nhost-s2(config)#"),
		[]byte("\r\nhost-s2(config-if)#"),
		[]byte("\r\nhost-s2(config-if)#"),
		[]byte("\r\nhost-s2(config-archive-log-cfg)#"),
	}
	testutils.ExprTester(
		t,
		errorCases,
		expr.NewExprMatcher(promptExpression, nil),
	)
}

func TestLogin(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\n\r\nUser Access Verification\r\n\r\nUsername: "),
	}
	testutils.ExprTester(
		t,
		errorCases,
		expr.NewExprMatcher(loginExpression, nil),
	)
}

func TestPassword(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\nPassword: "),
	}
	testutils.ExprTester(
		t,
		errorCases,
		expr.NewExprMatcher(passwordExpression, nil),
	)
}

func TestQuestion(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\nWarning: The current configuration will be written to the device. Continue? [Y/N]:"),
	}
	testutils.ExprTester(
		t,
		errorCases,
		expr.NewExprMatcher(questionExpression, nil),
	)
}
