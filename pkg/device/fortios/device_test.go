package fortios

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/testutils"
)

func TestPrompt(t *testing.T) {
	cases := [][]byte{
		[]byte("Forti1 # "),
		[]byte("end\r\n\r\nForti1 # "),
		[]byte("\r\nForti1 # "),
		[]byte("Forti-Gate (context) # "),
		[]byte("F-Gate $ "),
		[]byte("forti-fw~-01 $ "),
		[]byte("\r\n\r\nforti-fw~-01 (vdom) $ "),
		[]byte("end\r\n\r\nforti-fw~-01 (address) $ "),
	}
	testutils.ExprTester(t, cases, promptExpression)
}

func TestErrors(t *testing.T) {
	cases := [][]byte{
		[]byte("failover status: unset"),
		[]byte("\r\ncommand parse error before 'reboot'\r\nCommand fail. Return code -61\r\n\r\n"),
		[]byte("invalid unsigned integer value: unexist\r\n\r\nvalue parse error before 'unexist'\r\nCommand fail. Return code -651\r\n"),
		[]byte("Unknown action\r\n\r\nForti1 (policy) # "),
	}
	testutils.ExprTester(t, cases, errorExpression)
}

func TestQuestion(t *testing.T) {
	cases := [][]byte{
		[]byte("This operation will reboot the system !\r\nDo you want to continue? (y/n)"),
		[]byte("Do you want to continue? (y/n) "),
		[]byte("\r\ndo you want to continue? (y/n)"),
	}
	testutils.ExprTester(t, cases, questionExpression)
}

func TestPager(t *testing.T) {
	cases := [][]byte{
		[]byte("-- More --"),
		[]byte("--More--"),
		[]byte("-- more --"),
		[]byte("--more--"),
	}
	testutils.ExprTester(t, cases, pagerExpression)
}

func TestNotPrompt(t *testing.T) {
	errorCases := [][]byte{
		[]byte("config system stp"),
		[]byte("end"),
		[]byte("Forti1 # some-text"),
	}
	testutils.ExprTesterFalse(t, errorCases, promptExpression)
}
