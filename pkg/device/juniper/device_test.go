package juniper

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/testutils"
)

func TestPrompt(t *testing.T) {
	cases := [][]byte{
		[]byte("\r\nloginlog@lab-xdc-d1> "),
		[]byte("\r\n{master}\r\nloginlog@xdc-13f3> "),
		[]byte("\r\n[edit]\r\nlogin-login@host-dc-1d# "),
		[]byte("\r\n{master}[edit]\r\nlogin-login@hosth# "),
	}
	testutils.ExprTester(t, cases, promptExpression)
}

func TestError(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\n                          ^\r\nsyntax error, expecting <command>.\r\n"),
		[]byte("\r\n                      ^\r\nunknown command.\r\n"),
		[]byte("\r\n                           ^\r\nsyntax error.\r\n\r\n"),
		[]byte("configure exclusive error: configuration database modified\r\n"),
		[]byte("error: configuration database modified\r\n"),
		[]byte("error: configuration check-out failed\r\n"),
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
