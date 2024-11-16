package arista

import (
	"testing"

	"github.com/annetutil/gnetcli/pkg/testutils"
)

func TestPrompt(t *testing.T) {
	errorCases := [][]byte{
		// u001b[5 - CSI
		// Device status report ESC 5n
		// https://vt100.net/docs/vt510-rm/DSR-OS.html
		// Request
		// (Host to terminal)	CSI 5 n	The host requests the terminal's operating status. The host asks if the terminal is in good operating condition.
		// Responses
		// (Terminal to host)	CSI 0 n	The terminal indicates that it is in good operating condition.
		// or
		// CSI 3 n	The terminal indicates that it has a malfunction.
		[]byte("11:12:1:1::1:2\r\r\n\u001b[5nabc-abc-1f1>"), // only after login
		[]byte("11:12:1:1::1:2\r\r\n\u001b[5nabc-abc-1f1#"), // only after login
		[]byte("abc-abc-1f1>"),
		[]byte("abc-abc-1f1(config)#"),
		[]byte("abc-abc-1f1(config-if-Et1/1)#"),
	}
	testutils.ExprTester(t, errorCases, promptExpression)
}

func TestErrors(t *testing.T) {
	errorCases := [][]byte{
		[]byte("% Invalid input\r\n"),
		[]byte("% Incomplete command\r\n"),
		[]byte("% Invalid input (privileged mode required)\r\n"),
		// following test cases are inspired by error messages specified in documentation https://www.arista.com/assets/data/docs/Manuals/EOS-4.17.0F-Manual.pdf
		[]byte("% Host name is invalid. Host name must contain only alphanumeric characters, '.' and '-'.\r\nIt must begin and end with an alphanumeric character. \r\nMaximum characters in hostname is 64.\r\n"),
		[]byte("% Cannot enable HTTP and HTTPS simultaneously\r\n"),
		[]byte("% Ambiguous command\r\n"),
		[]byte("%% Please use copy <url> running-config\r\n"),
		[]byte("% Maximum number of nameservers reached. '10.10.10.10' not added\r\n"),
		[]byte("% One of the prefix lengths must be 32\r\n"),
		[]byte("% BGP is already running with AS number 50\r\n"),
		[]byte("% More than 1 ISIS instance is not supported\r\n"),
		[]byte("% Error: cannot specify source range with group range\r\n"),
		[]byte("% Invalid input (privileged mode required)"),
	}
	testutils.ExprTesterWithExclude(t, errorCases, testutils.ExpressionPair{Pattern: errorExpression, ExcludePattern: excludeErrorExpression})
}

func TestErrorsNoMatch(t *testing.T) {
	errorCases := [][]byte{
		// following test cases are inspired by error messages specified in documentation https://www.arista.com/assets/data/docs/Manuals/EOS-4.17.0F-Manual.pdf
		[]byte("% Writing 0 Arp, 0 Route, 1 Mac events to the database\r\n2012-01-19 13:57:55|1|08:08:08:08:08:08|Ethernet1|configuredStaticMac|added|0\r\n"),
		[]byte("%SAND-4-SERDES_WITHDRAWN_FROM_FABRIC: Serdes Arad10/5-FabricSerdes-11 withdrawn\r\nfrom the switch fabric.\r\n"),
		[]byte("%SECURITY-4-ARP_PACKET_DROPPED: Dropped ARP packet on interface Ethernet28/1 Vlan 2121\r\nbecause invalid mac and ip binding. Received: 00:0a:00:bc:00:00/1.1.1.1.\r\n"),
	}
	testutils.ExprTesterFalseWithExclude(t, errorCases, testutils.ExpressionPair{Pattern: errorExpression, ExcludePattern: excludeErrorExpression})
}

func TestPager(t *testing.T) {
	errorCases := [][]byte{
		[]byte("\r\n\u001b[7m --More-- \u001b[27m\u001b[K"),
	}
	testutils.ExprTester(t, errorCases, pagerExpression)
}
