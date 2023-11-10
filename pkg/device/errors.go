package device

import "fmt"

type ExecException struct {
	Data string
}

func (m *ExecException) Error() string {
	ret := "exec error"
	if m != nil {
		ret = fmt.Sprintf("%s %s", ret, m.Data)
	}
	return ret
}

func (m *ExecException) Is(target error) bool {
	if _, ok := target.(*ExecException); ok {
		return true
	}
	return false
}

func ThrowExecException(data string) error {
	return &ExecException{Data: data}
}

type EchoReadException struct {
	lastRead []byte
}

func (e *EchoReadException) Error() string {
	return fmt.Sprintf("echo read error %s", e.lastRead)
}

func ThrowEchoReadException(lastRead []byte) error {
	return &EchoReadException{lastRead: lastRead}
}

type QuestionException struct {
	Question []byte
}

func (e *QuestionException) Error() string {
	return fmt.Sprintf("no answer for question: %s", e.Question)
}

func ThrowQuestionException(question []byte) error {
	return &QuestionException{Question: question}
}
