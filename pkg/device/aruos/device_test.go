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

func TestWriteFlashFail(t *testing.T) {
	cases := [][]byte{
		[]byte("[  504.613753] ubi1 error: ubi_open_volume: cannot open device 1, volume 0, error -16\r\nWriteFlash open /dev/env: Device or resource busysaveenv:WriteApFlash unsuccessful (flash_off=0)(size=10000)(env_data=0x04618dc8)\r\n"),
		[]byte("WriteFlash open /dev/env: Device or resource busysaveenv:WriteApFlash unsuccessful (flash_off=0)(size=10000)(env_data=0x04618dc8)\r\n"),
		[]byte("saveenv:WriteApFlash unsuccessful (flash_off=0)(size=10000)(env_data=0x04618dc8)\r\n"),
		[]byte("saveenv: WriteApFlash unsuccessful (flash_off=0)(size=10000)(env_data=0x04618dc8)\r\n"),
	}
	testutils.ExprTester(t, cases, errorExpression)
}
