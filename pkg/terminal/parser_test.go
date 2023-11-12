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
