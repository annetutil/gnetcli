package emulator

import (
	"fmt"
	"io/fs"
	"strings"
)

func validateScenario(s *Scenario, files fs.FS) error {
	if s.APIVersion != "cli-emulator/v1" {
		return fmt.Errorf("invalid scenario apiVersion")
	}
	for i := range s.Timeline {
		if err := compileEvent(&s.Timeline[i], files); err != nil {
			return err
		}
		if s.Timeline[i].Route == "session" {
			return fmt.Errorf("timeline cannot target a session")
		}
	}
	for i := range s.Triggers {
		t := &s.Triggers[i]
		if t.After < 0 || t.Event.At != 0 {
			return fmt.Errorf("trigger uses nonnegative after, not event.at")
		}
		if t.On != "authenticated" && !strings.HasPrefix(t.On, "command:") && !strings.HasPrefix(t.On, "checkpoint:") {
			return fmt.Errorf("unknown trigger %q", t.On)
		}
		if err := compileEvent(&t.Event, files); err != nil {
			return err
		}
	}
	return nil
}
