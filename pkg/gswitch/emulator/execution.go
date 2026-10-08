package emulator

import (
	"fmt"
	"strconv"
)

func (d *Device) continueTask(s *terminalSession) {
	for s.actionIndex < len(s.actions) {
		a := s.actions[s.actionIndex]
		s.actionIndex++
		if a.After > 0 {
			generation := s.generation
			d.schedule(a.After, func() {
				if s.generation != generation {
					return
				}
				blocked, err := d.action(s, a)
				if err != nil {
					d.failure(s, err)
					return
				}
				if !blocked {
					d.continueTask(s)
				}
			})
			return
		}
		blocked, err := d.action(s, a)
		if err != nil {
			d.failure(s, err)
			return
		}
		if blocked {
			return
		}
	}
	d.finish(s)
}

func (d *Device) action(s *terminalSession, a Action) (bool, error) {
	data := d.data(s)
	render := func(text string) (string, error) { return d.profile.render(text, data) }
	value := a.Value
	if text, ok := value.(string); ok {
		var err error
		value, err = render(text)
		if err != nil {
			return false, err
		}
	}
	switch a.Op {
	case "output":
		text, err := render(a.Text)
		if err != nil {
			return false, err
		}
		return d.page(s, d.newline(text), s.pageLines), nil
	case "raw":
		d.emit(s, a.Text)
	case "pause":
	case "checkpoint":
		d.trigger("checkpoint:"+a.Name, s)
		d.advanceTo(d.now)
	case "push", "mode":
		context := map[string]string{}
		for key, v := range a.Context {
			text, err := render(v)
			if err != nil {
				return false, err
			}
			context[key] = text
		}
		frame := modeFrame{a.Mode, context}
		if a.Op == "push" {
			if len(s.stack) >= 32 {
				return false, fmt.Errorf("mode stack limit exceeded")
			}
			s.stack = append(s.stack, frame)
		} else {
			s.stack = []modeFrame{frame}
		}
	case "pop":
		if len(s.stack) > 1 {
			s.stack = s.stack[:len(s.stack)-1]
		}
	case "set", "delete":
		path := make([]string, len(a.Path))
		for i, v := range a.Path {
			key, err := render(v)
			if err != nil {
				return false, err
			}
			if key == "" {
				return false, fmt.Errorf("empty state path component")
			}
			path[i] = key
		}
		cfg := cloneMap(d.config(s))
		node := cfg
		for _, key := range path[:len(path)-1] {
			if node[key] == nil {
				node[key] = map[string]any{}
			}
			next, ok := node[key].(map[string]any)
			if !ok {
				return false, fmt.Errorf("state path crosses scalar %q", key)
			}
			node = next
		}
		key := path[len(path)-1]
		if a.Op == "delete" {
			delete(node, key)
		} else {
			node[key] = value
		}
		if s.candidate != nil {
			s.candidate = cfg
		} else {
			if ok, err := d.checkConfiguration(s, cfg); !ok || err != nil {
				return false, err
			}
			d.running = cfg
			d.revision++
		}
	case "pager":
		n, err := strconv.Atoi(fmt.Sprint(value))
		if err != nil || n < 0 || n > 10000 {
			return false, fmt.Errorf("invalid page length %v", value)
		}
		s.pageLines = n
	case "echo":
		mode := fmt.Sprint(value)
		if !echoMode(mode) {
			return false, fmt.Errorf("invalid echo mode %q", mode)
		}
		s.echo = mode
	case "monitor":
		v, err := strconv.ParseBool(fmt.Sprint(value))
		if err != nil {
			return false, err
		}
		s.monitor = v
	case "begin":
		if s.candidate == nil {
			s.candidate = cloneMap(d.running)
			s.baseRevision = d.revision
		}
	case "commit":
		if s.candidate != nil {
			if s.baseRevision != d.revision {
				d.emit(s, "% Candidate conflicts with running configuration"+d.profile.def.Terminal.Newline)
				s.actions = nil
				return false, nil
			}
			if ok, err := d.checkConfiguration(s, s.candidate); !ok || err != nil {
				return false, err
			}
			d.running = cloneMap(s.candidate)
			d.revision++
			s.baseRevision = d.revision
		}
	case "abort":
		s.candidate = nil
	case "save":
		d.startup = cloneMap(d.running)
	case "dialog":
		s.dialog = a.Dialog
		s.interaction = "dialog"
		d.prompt(s)
		return true, nil
	case "disconnect":
		d.detach(s, nil)
		return true, nil
	case "logout":
		if s.console == "" {
			d.detach(s, nil)
		} else {
			s.reset(d.profile)
			s.interaction = "username"
			d.prompt(s)
		}
		return true, nil
	case "reboot":
		d.reboot()
		return true, nil
	default:
		return false, fmt.Errorf("unimplemented action %q", a.Op)
	}
	return false, nil
}
