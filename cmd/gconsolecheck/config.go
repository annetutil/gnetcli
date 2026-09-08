package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	defaultConserverPort = 10101
	defaultTimeout       = 10 * time.Second
	defaultDuration      = time.Minute
	defaultChunkSize     = 4096
	defaultExtraWait     = time.Second
)

var allScenarioNames = []string{"test_one_way", "test_all_bytes", "test_random_soak", "test_random_soak_ascii", "test_discovery", "test_discovery_all_ports"}

var defaultScenarioNames = []string{"test_one_way", "test_all_bytes", "test_random_soak"}

var scenarioDescriptions = map[string]string{
	"test_one_way":             "send data framed with test/source/target console markers in both directions; detect echo and extra data",
	"test_all_bytes":           "send 0..255 and 255..0 simultaneously; verify every byte in both directions",
	"test_random_soak":         "exchange framed iter_N deterministic random data in full duplex for -duration",
	"test_random_soak_ascii":   "exchange only printable ASCII characters in full duplex for -duration; disabled by default",
	"test_discovery":           "exchange fixed-size source/target markers and verify console pairing; disabled by default",
	"test_discovery_all_ports": "discover all conserver ports, exchange printable source markers, and report physical pairing; disabled by default",
}

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

type portPair struct {
	left  string
	right string
}

func (p portPair) String() string {
	return p.left + "=" + p.right
}

type config struct {
	host           string
	port           int
	username       string
	speed          int
	timeout        time.Duration
	readTimeout    time.Duration
	duration       time.Duration
	extraWait      time.Duration
	chunkSize      int
	seed           uint64
	parallel       int
	pairs          []portPair
	scenarios      []string
	debug          bool
	ssl            bool
	jumpHost       string
	useSSHConfig   bool
	sshPassphrase  string
	pairValues     stringList
	scenarioValues stringList
}

func parseConfig(args []string, output io.Writer) (config, error) {
	cfg := config{}
	fs := flag.NewFlagSet("gconsolecheck", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.StringVar(&cfg.host, "host", "", "Conserver host")
	fs.IntVar(&cfg.port, "port", defaultConserverPort, "Conserver TCP port")
	fs.StringVar(&cfg.username, "username", "", "Conserver username (empty means anonymous)")
	fs.IntVar(&cfg.speed, "speed", 0, "Serial speed; 0 keeps the configured speed")
	fs.DurationVar(&cfg.timeout, "timeout", defaultTimeout, "Timeout for connection and one data exchange")
	fs.DurationVar(&cfg.readTimeout, "read-timeout", 0, "Read inactivity timeout; defaults to -timeout")
	fs.DurationVar(&cfg.duration, "duration", defaultDuration, "Duration of test_random_soak")
	fs.DurationVar(&cfg.extraWait, "extra-wait", defaultExtraWait, "Time to wait for unexpected data after receiving the expected payload")
	fs.IntVar(&cfg.chunkSize, "chunk-size", defaultChunkSize, "Random-data bytes per test_random_soak iteration, excluding the iter_N marker")
	fs.IntVar(&cfg.parallel, "parallel", 0, "Maximum number of port pairs tested concurrently; 0 means all")
	fs.Func("seed", "Deterministic random seed", func(value string) error {
		seed, err := strconv.ParseUint(value, 0, 64)
		if err != nil {
			return fmt.Errorf("invalid seed %q: %w", value, err)
		}
		cfg.seed = seed
		return nil
	})
	fs.Var(&cfg.pairValues, "t", "Console port pair in left=right form; may be repeated")
	fs.Var(&cfg.scenarioValues, "scenario", scenarioHelp())
	fs.BoolVar(&cfg.debug, "debug", false, "Enable console streamer debug logs")
	fs.BoolVar(&cfg.ssl, "ssl", true, "Enable conserver SSL (use -ssl=false for plaintext)")
	fs.StringVar(&cfg.jumpHost, "J", "", "SSH jump host in [user@]host form")
	fs.BoolVar(&cfg.useSSHConfig, "use-ssh-config", false, "Use ~/.ssh/config for jump-host address and credentials")
	fs.StringVar(&cfg.sshPassphrase, "ssh-config-passphrase", "", "Passphrase for jump-host identity files from SSH config")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	if fs.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	if err := cfg.validate(); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func scenarioHelp() string {
	var result strings.Builder
	result.WriteString("Scenario to run; may be repeated; scenarios marked [default] run when the flag is omitted:\n")
	for _, name := range allScenarioNames {
		defaultMark := ""
		if slices.Contains(defaultScenarioNames, name) {
			defaultMark = " [default]"
		}
		fmt.Fprintf(&result, "  %s%s - %s\n", name, defaultMark, scenarioDescriptions[name])
	}
	return strings.TrimSuffix(result.String(), "\n")
}

func (c *config) validate() error {
	c.host = strings.TrimSpace(c.host)
	if c.host == "" {
		return errors.New("-host is required")
	}
	if c.port < 1 || c.port > 65535 {
		return fmt.Errorf("-port must be between 1 and 65535, got %d", c.port)
	}
	if c.timeout <= 0 {
		return fmt.Errorf("-timeout must be positive, got %s", c.timeout)
	}
	if c.readTimeout == 0 {
		c.readTimeout = c.timeout
	}
	if c.readTimeout < 0 {
		return fmt.Errorf("-read-timeout must be positive, got %s", c.readTimeout)
	}
	if c.duration <= 0 {
		return fmt.Errorf("-duration must be positive, got %s", c.duration)
	}
	if c.extraWait <= 0 {
		return fmt.Errorf("-extra-wait must be positive, got %s", c.extraWait)
	}
	if c.chunkSize <= 0 {
		return fmt.Errorf("-chunk-size must be positive, got %d", c.chunkSize)
	}
	if c.parallel < 0 {
		return fmt.Errorf("-parallel must be non-negative, got %d", c.parallel)
	}
	if !validSpeed(c.speed) {
		return fmt.Errorf("unsupported -speed %d", c.speed)
	}
	if c.useSSHConfig && c.jumpHost == "" {
		return errors.New("-use-ssh-config requires -J")
	}
	if c.sshPassphrase != "" && !c.useSSHConfig {
		return errors.New("-ssh-config-passphrase requires -use-ssh-config")
	}
	if c.jumpHost != "" {
		if _, _, err := splitJumpTarget(c.jumpHost); err != nil {
			return err
		}
	}
	if err := c.resolveScenarios(); err != nil {
		return err
	}
	requiresPairs := false
	for _, scenario := range c.scenarios {
		if scenario != "test_discovery_all_ports" {
			requiresPairs = true
		}
	}
	if requiresPairs && len(c.pairValues) == 0 {
		return errors.New("at least one -t left=right pair is required for the selected scenarios")
	}

	usedPorts := make(map[string]string)
	c.pairs = make([]portPair, 0, len(c.pairValues))
	for _, value := range c.pairValues {
		if strings.Count(value, "=") != 1 {
			return fmt.Errorf("invalid pair %q: expected left=right", value)
		}
		parts := strings.SplitN(value, "=", 2)
		pair := portPair{left: strings.TrimSpace(parts[0]), right: strings.TrimSpace(parts[1])}
		if pair.left == "" || pair.right == "" {
			return fmt.Errorf("invalid pair %q: both port names are required", value)
		}
		if pair.left == pair.right {
			return fmt.Errorf("invalid pair %q: ports must differ", value)
		}
		for _, port := range []string{pair.left, pair.right} {
			if previous, ok := usedPorts[port]; ok {
				return fmt.Errorf("port %q is used by both %s and %s", port, previous, pair.String())
			}
			usedPorts[port] = pair.String()
		}
		c.pairs = append(c.pairs, pair)
	}

	return nil
}

func (c *config) resolveScenarios() error {
	requestedScenarios := c.scenarioValues
	if len(requestedScenarios) == 0 {
		requestedScenarios = defaultScenarioNames
	}
	known := make(map[string]struct{}, len(allScenarioNames))
	for _, name := range allScenarioNames {
		known[name] = struct{}{}
	}
	seen := make(map[string]struct{}, len(requestedScenarios))
	for _, name := range requestedScenarios {
		if _, ok := known[name]; !ok {
			return fmt.Errorf("unknown scenario %q; available: %s", name, strings.Join(allScenarioNames, ", "))
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		c.scenarios = append(c.scenarios, name)
	}
	return nil
}

func validSpeed(speed int) bool {
	switch speed {
	case 0, 9600, 19200, 38400, 57600, 115200:
		return true
	default:
		return false
	}
}
