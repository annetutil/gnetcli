package terminal

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseCub(t *testing.T) {
	// CUB
	res, err := Parse([]byte("off\r\n  ---- More ----\u001b[16D                \u001b[16Dinfo-center source aaa channel 7\r\n"))
	assert.NoError(t, err)
	assert.Equal(t, "off\r\ninfo-center source aaa channel 7\r\n", string(res))
}

func TestEkinops(t *testing.T) {
	res, err := Parse([]byte("olo\u001B[?1l\u001B>olo"))
	assert.NoError(t, err)
	assert.Equal(t, "oloolo", string(res))
}

func TestEkinops2(t *testing.T) {
	res, err := Parse([]byte("test\x1b[1;1H\x1b[2J\r\n***"))
	assert.NoError(t, err)
	assert.Equal(t, "test\r\n***", string(res))
}

func TestParseR(t *testing.T) {
	res, err := Parse([]byte("1234\r\n---(more 83%)---\r                                        \r5678"))
	assert.NoError(t, err)
	assert.Equal(t, "1234\r\n5678", string(res))
}

func TestParseRN(t *testing.T) {
	res, err := Parse([]byte("1\r\n2\r\n3\r"))
	assert.NoError(t, err)
	assert.Equal(t, "1\r\n2\r\n", string(res))
}

func TestParseRN2(t *testing.T) {
	res, err := Parse([]byte("\rbad \n\r\r\r\rolo"))
	assert.NoError(t, err)
	assert.Equal(t, "bad \nolo", string(res))
}

func TestParseRN3(t *testing.T) {
	res, err := Parse([]byte("foo\r\r\nbar"))
	assert.NoError(t, err)
	assert.Equal(t, "foo\r\r\nbar", string(res))
}

func TestParseEL(t *testing.T) {
	res, err := Parse([]byte("\rset api-ssl disabled=yes\r\n" +
		"\r\r\r\r[mk-rb3011-test1] >   \r[mk-rb3011-test2] > \r\r[mk-rb3011-test3] >     \x1b[K"))
	assert.NoError(t, err)
	assert.Equal(t, "set api-ssl disabled=yes\r\n[mk-rb3011-test3] >     ", string(res))
}

func TestParseErase(t *testing.T) {
	magics := []string{
		"\x1b[K",
		"\x1b[0K",
	}
	for _, magic := range magics {
		check(t, "", magic)
		check(t, "foo bar", "foo"+magic+" bar")
	}
}

func TestParseCursorBackward(t *testing.T) {
	// Juniper/vrp
	check(t, " text", "\x1b[42D                                          \x1b[42D text")

	check(t, "", cback(0))
	check(t, "", cback(1))
	check(t, "", "foo"+cback(4))
	check(t, "", "foo"+cback(3))
	check(t, "f", "foo"+cback(2))
	check(t, "fo", "foo"+cback(1))

	check(t, "bar", cback(1)+"bar")
	check(t, "hello world", "hello.."+cback(1)+cback(1)+" world."+cback(1))
	check(t, "", cback(1)+cback(2))

	// Check that the cursor movement is applied before newline.
	check(t, "foo\nbar", "foo\nfoo"+cback(42)+"bar")

	// TODO(manushkin): cursor back implemented as __deletion__ symbol.
	// But it is not equivalent if prefix is longer than suffix.
	// manushkin@laptop:~$ echo -e 'bar bar\e[42Dfoo'
	// foo bar
	// will return "foo".
}

func TestBadEscape(t *testing.T) {
	checkError(t, "\x1b")
	checkError(t, "\x1b[")
	checkError(t, "\x1b[D")
}

func TestBS(t *testing.T) {
	res, err := Parse([]byte("test   \u0008\u0008\u0008123"))
	assert.NoError(t, err)
	assert.Equal(t, "test123", string(res))
}

func TestBS2(t *testing.T) {
	res, err := Parse([]byte("0         \r\n\b\b\b\b\b\b\b\b        \b\b\b\b\b\b\b\b|access"))
	assert.NoError(t, err)
	assert.Equal(t, "0         \r\n|access", string(res))
}

func TestLeadingBS(t *testing.T) {
	// Test case: leading backspaces (should be ignored as there's nothing to delete)
	res, err := Parse([]byte("\b\b\binterface GigabitEthernet1/38"))
	assert.NoError(t, err)
	assert.Equal(t, "interface GigabitEthernet1/38", string(res))
}

func TestPagerBackspaces(t *testing.T) {
	// Test case from real Cisco telnet output with pager clearing
	// Pattern: backspaces + spaces + backspaces (clearing "-- More --" prompt)
	res, err := Parse([]byte("\b\b\b\b\b\b\b\b\b         \b\b\b\b\b\b\b\b\binterface GigabitEthernet1/38"))
	assert.NoError(t, err)
	assert.Equal(t, "interface GigabitEthernet1/38", string(res))
}

func TestCiscoPagerMidLine(t *testing.T) {
	// Cisco pager appearing after description line
	// Real output: "description CCR-Dudovi-Po1\r\n --More-- "
	// Then after space, backspaces clear the pager
	// Expected: description line should remain intact
	input := []byte(" description CCR-Dudovi-Po1\r\n --More-- \b\b\b\b\b\b\b\b\b\b         \b\b\b\b\b\b\b\b\b\bno switchport")
	res, err := Parse(input)
	assert.NoError(t, err)
	fmt.Printf("Result: %q\n", string(res))
	// Should preserve the full description
	assert.Contains(t, string(res), "description CCR-Dudovi-Po1")
	assert.Contains(t, string(res), "no switchport")
	assert.Equal(t, " description CCR-Dudovi-Po1\r\nno switchport", string(res))
}

func TestCiscoPagerTooManyBackspaces(t *testing.T) {
	// If there are 11 backspaces but only 10 chars in " --More-- "
	// the extra backspace might eat the newline
	input := []byte(" description CCR-Dudovi-Po1\r\n --More-- \b\b\b\b\b\b\b\b\b\b\b         \b\b\b\b\b\b\b\b\b\b\bno switchport")
	res, err := Parse(input)
	assert.NoError(t, err)
	fmt.Printf("Result with extra BS: %q\n", string(res))
	// This might incorrectly eat the \n
}

func check(t *testing.T, want string, s string) {
	res, err := Parse([]byte(s))
	assert.NoError(t, err)
	assert.Equal(t, want, string(res))
}

func checkError(t *testing.T, s string) {
	_, err := Parse([]byte(s))
	assert.Error(t, err)
}

func cback(n int) string {
	return fmt.Sprintf("\x1b[%dD", n)
}
