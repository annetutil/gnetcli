package nxos

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/testutils"
)

func TestPrompt(t *testing.T) {
	cases := [][]byte{
		[]byte("\r\n\rn9k-9316-test# "),
		[]byte("\r\n\rn9k-9316-test(config)# "),
		[]byte("\r\n\rn3k-test(config-tacacs+)# "),
	}
	testutils.ExprTester(t, cases, promptExpression)
}

func TestErrors(t *testing.T) {
	cases := [][]byte{
		[]byte("                   ^\r\n% Invalid command at '^' marker."),
		[]byte("                              ^\r\n% Incomplete command at '^' marker."),
		[]byte("                                              ^\r\nInvalid range at '^' marker."),
	}
	testutils.ExprTester(t, cases, errorExpression)
}

func TestPager(t *testing.T) {
	cases := [][]byte{
		[]byte("\r\n\u001b[7m--More--\u001b[m\""),
		[]byte("\r\n\x1b[7m--More--\x1b[27m"),
	}
	testutils.ExprTester(t, cases, pagerExpression)
}
