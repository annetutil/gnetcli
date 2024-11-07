/*
Package trace provides interface and implementation for collecting communication with an CLI.
*/
package trace

import (
	"fmt"
	"strings"
	"time"
)

type Trace interface {
	Add(s Operation, data []byte)
	List() []Item
}

type Item interface {
	GetTime() time.Time
	GetOperation() Operation
	GetData() []byte
}

type Operation int64
type CB func(operation Operation, data []byte)

const (
	Unknown Operation = 0
	Write   Operation = 1
	Read    Operation = 2
)

type traceItem struct {
	operation Operation
	time      time.Time
	data      []byte
}

func (m traceItem) GetTime() time.Time {
	return m.time
}

func (m traceItem) GetOperation() Operation {
	return m.operation
}

func (m traceItem) GetData() []byte {
	return m.data
}

type TraceImp struct {
	data       []traceItem
	limit      int
	limitIndex int
}

func newTraceItem(operation Operation, data []byte) traceItem {
	return traceItem{
		operation: operation,
		time:      time.Now(),
		data:      data,
	}
}

func NewTraceImp() *TraceImp {
	return NewTraceLimited(-1)
}

func NewTraceLimited(limit int) *TraceImp {
	return &TraceImp{data: []traceItem{}, limit: limit, limitIndex: 0}
}

func (m *TraceImp) Add(op Operation, data []byte) {
	if len(data) == 0 {
		return
	}
	if len(m.data) > 0 { // merge
		prev := m.data[len(m.data)-1]
		if prev.operation == op && time.Since(prev.time) < time.Second {
			newData := append(prev.data, data...)
			m.data[len(m.data)-1].data = newData
			return
		}
	}
	if m.limit > 0 && len(m.data) >= m.limit {
		m.data[m.limitIndex] = newTraceItem(op, data)
		m.limitIndex++
		if m.limitIndex >= m.limit {
			m.limitIndex = 0
		}
	} else {
		m.data = append(m.data, newTraceItem(op, data))
	}
}

func (m *TraceImp) List() []Item {
	res := []Item{}
	for i := m.limitIndex; i < len(m.data); i++ {
		res = append(res, m.data[i])
	}
	if m.limitIndex > 0 {
		for i := 0; i < m.limitIndex; i++ {
			res = append(res, m.data[i])
		}
	}
	return res
}

func (l Operation) String() string {
	switch l {
	case Unknown:
		return "Unknown"
	case Write:
		return "Write"
	case Read:
		return "Read"
	default:
		return fmt.Sprintf("Unknown(%d)", l)
	}
}

func FormatTrace(tr Trace) string {
	res := []string{}
	for _, t := range tr.List() {
		res = append(res, fmt.Sprintf("%s %s %q", t.GetOperation(), t.GetTime().Round(0), t.GetData()))
	}
	return strings.Join(res, "\n")
}
