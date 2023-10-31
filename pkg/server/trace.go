package server

import (
	"fmt"

	gtrace "github.com/annetutil/gnetcli/pkg/trace"
)

type MultiTrace interface {
	AddTrace(gtrace.Trace) int
	DelTrace(int) error
}

type MultiTraceImp struct {
	trs map[int]gtrace.Trace
}

func NewMultiTrace() *MultiTraceImp {
	return &MultiTraceImp{
		trs: map[int]gtrace.Trace{},
	}
}

var _ MultiTrace = (*MultiTraceImp)(nil)
var _ gtrace.Trace = (*MultiTraceImp)(nil)

func (m *MultiTraceImp) Add(op gtrace.Operation, data []byte) {
	for _, tr := range m.trs {
		tr.Add(op, data)
	}
}

func (m *MultiTraceImp) List() []gtrace.Item {
	panic("not implement List() for MultiTraceImp")
}

func (m *MultiTraceImp) AddTrace(tr gtrace.Trace) int {

	for i := 0; i <= len(m.trs); i++ {
		if _, ok := m.trs[i]; !ok {
			m.trs[i] = tr
			return i
		}
	}
	panic("unknown error")
}

func (m *MultiTraceImp) DelTrace(index int) error {
	if _, ok := m.trs[index]; ok {
		delete(m.trs, index)
	} else {
		return fmt.Errorf("unknown trace")
	}
	return nil
}
