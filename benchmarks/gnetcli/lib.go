package main

import (
	"encoding/json"
	"os"
	"time"
)

const NextCmd = "next"

type Result struct {
	Items    []resultItem
	Duration time.Duration
}

type resultItem struct {
	cmd string
	res []byte
	err error
}

type resultJSON struct {
	Cmd string `json:"cmd"`
	Res []byte `json:"res"`
	Err string `err:"err"`
}

func newResultJSON(cmd string, res []byte, err error) resultJSON {
	errSting := ""
	if err != nil {
		errSting = err.Error()
	}
	return resultJSON{
		Cmd: cmd,
		Res: res,
		Err: errSting,
	}
}

type resultsJSON struct {
	Items      []resultJSON `json:"items"`
	DurationMS uint64       `json:"duration_ms"`
	Err        string       `err:"error"`
}

func newResultItem(cmd string, res []byte, err error) resultItem {
	return resultItem{
		cmd: cmd,
		res: res,
		err: err,
	}
}

func (m *Result) Add(cmd string, b []byte, err error) {
	m.Items = append(m.Items, newResultItem(cmd, b, err))
}

func (m *Result) Dump() ([]byte, error) {
	res := resultsJSON{
		Items:      make([]resultJSON, 0, len(m.Items)),
		DurationMS: uint64(m.Duration.Milliseconds()),
	}
	for _, item := range m.Items {
		res.Items = append(res.Items, newResultJSON(item.cmd, item.res, item.err))
	}

	return json.Marshal(res)
}

func (m *Result) SetDuration(duration time.Duration) {
	m.Duration = duration
}

func NewResult() *Result {
	return &Result{
		Items: []resultItem{},
	}
}

func SaveReport(path string, res *Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	formattedRes, err := res.Dump()
	if err != nil {
		return err
	}
	_, err = f.Write(formattedRes)
	if err != nil {
		return err
	}
	return nil
}
