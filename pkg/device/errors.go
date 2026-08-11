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
	lastRead      []byte
	promptFound   bool // indicates if we found prompt after echo read error
	questionFound bool // indicates if we found question after echo error
}

func (e *EchoReadException) Error() string {
	return fmt.Sprintf("echo read error %s", e.lastRead)
}

// PromptFound indicates if gnetcli succeeded in reading prompt after echo read failure
func (e *EchoReadException) PromptFound() bool {
	return e.promptFound
}

// QuestionFound indicates if gnetcli succeeded in reading question after echo read failure
func (e *EchoReadException) QuestionFound() bool {
	return e.questionFound
}

func ThrowEchoReadException(lastRead []byte, promptFound bool, questionFound bool) error {
	return &EchoReadException{
		lastRead:      lastRead,
		promptFound:   promptFound,
		questionFound: questionFound,
	}
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
