package gerror

import "fmt"

type AuthException struct {
	msg string
}

func (m *AuthException) Error() string {
	return fmt.Sprintf("auth error %s", m.msg)
}

func (m *AuthException) Is(target error) bool {
	if _, ok := target.(*AuthException); ok {
		return true
	}
	return false
}

func NewAuthException(msg string) error {
	return &AuthException{msg: msg}
}
