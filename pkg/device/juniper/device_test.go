package juniper

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/testutils"
)

func TestPrompt(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\nloginlog@lab-xdc-d1> "),
		[]byte("\r\n{master}\r\nloginlog@xdc-13f3> "),
	}
	testutils.ExprTester(t, errorCases, promptExpression)
}

func TestError(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\n                          ^\r\nsyntax error, expecting <command>.\r\n"),
		[]byte("\r\n                      ^\r\nunknown command.\r\n"),
		[]byte("\r\n                           ^\r\nsyntax error.\r\n\r\n"),
	}
	testutils.ExprTester(t, errorCases, errorExpression)
}

func TestPager(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\n---(more)---"),
		[]byte("\n---(more 100%)---"),
	}
	testutils.ExprTester(t, errorCases, pagerExpression)
}
