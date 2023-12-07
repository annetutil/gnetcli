### New device
This is an example how to make a config for a new vendor. See full documentation [here](architecture.md).

Here we are playing with qfx in docker: 

```shell
docker run -it -p 2222:22 --privileged aninchat/vr-vqfx:19.4R1.10
```

Let's start with an empty config:

```yaml
# gnetcli_conf.yaml
devices:
  - name: myvendor
    prompt_expression: '$.^' # just stub that will never match
    error_expression: '$.^'
```

Run any command to get debug output with read data:

```shell
cli -dev-conf gnetcli_conf.yaml -devtype 'myvendor' -command 'show system uptime' -port 2222 -hostname 127.0.0.1 -login vrnetlab -password VR-netlab9 -debug
```

Output:

```go
read	{"data": "Last login: Mon Dec  4 22:22:25 2023 from 10.0.0.2\r\r\n--- JUNOS 19.4R1.10 built 2019-12-19 03:54:05 UTC\r\n"}
read	{"data": "{master:0}\r\n"}
read	{"data": "vrnetlab@vr-vqfx> "}
```

In the output we see prompt `vrnetlab@vr-vqfx> ` for which we must write regular expression.
Keep in mind that expressions must be as specific as possible. https://regex101.com/ is very instrumental for testing. Expression
`\r\n(?P<user>[\w]{1,10})@(?P<hostname>[\w-]{1,10})> $` will go well. Also, we can add test data in `test` section.

```yaml
# gnetcli_conf.yaml
devices:
  - name: myvendor
    prompt_expression: `\r\n(?P<user>[\w]{1,10})@(?P<hostname>[\w-]{1,10})> $`
    error_expression: '$.^'
    tests:
      prompt_expression_variants:
        - "\r\nvrnetlab@vr-vqfx> "
```

Next run:

```shell
cli -dev-conf gnetcli_conf.yaml -devtype 'myvendor' -command 'show system uptime' -port 2222 -hostname 127.0.0.1 -login vrnetlab -password VR-netlab9 -debug
```

Output:
```text
read	{"data": "Last login: Mon Dec  4 23:17:37 2023 from 10.0.0.2\r\r\n--- JUNOS 19.4R1.10 built 2019-12-19 03:54:05 UTC\r\n"}
read	{"data": "{master:0}\r\n"}
read	{"data": "vrnetlab@vr-vqfx> "}
write	{"text": "show system uptime", "written": 18}
write	{"text": "\n", "written": 1}
read to	{"expr": "show system uptime(\\r\\n|\\n),\\n(?P<user>[\\w]{1,10})@(?P<hostname>[\\w-]{1,10})> $"}
read	{"data": "show system uptime "}
read	{"data": "\r\n"}
read	{"data": "fpc0:\r\n"}
read	{"data": "--------------------------------------------------------------------------\r\n"}
read	{"data": "Current time: 2023-12-04 23:18:12 UTC\r\n"}
read	{"data": "Time Source:  LOCAL CLOCK \r\n"}
read	{"data": "System booted: 2023-12-04 20:49:37 UTC (02:28:35 ago)\r\n"}
read	{"data": "Protocols started: 2023-12-04 20:52:13 UTC (02:25:59 ago)\r\n"}
read	{"data": "Last configured: 2023-12-04 20:54:17 UTC (02:23:55 ago) by root\r\n"}
read	{"data": "11:18PM  up 2:29, 2 users, load averages: 0.28, 0.18, 0.11\r\n"}
read	{"data": "\r\n{master:0}\r\n"}
read	{"data": "vrnetlab@vr-vqfx> "}
```

Here we see a quirk - CLI added white space in echo. This behaviour brakes Gnetcli's echo reading algorith.
Luckily there is feature called `spaces_after_echo`, which modifies expression for echo. 

```yaml
devices:
  - name: myvendor
    prompt_expression: '\n(?P<user>[\w]{1,10})@(?P<hostname>[\w-]{1,10})> $'
    error_expression: '$.^'
    features: [ spaces_after_echo ]
```

With current config is it possible to run commands, but without error detection. Let's add them.

#### Error prompt

Run:

```shell
cli -dev-conf gnetcli_conf.yaml -devtype 'myvendor' -command 'show123' -port 2222 -hostname 127.0.0.1 -login vrnetlab -password VR-netlab9 -debug
```

Output:

```text
read	{"data": "Last login: Mon Dec  4 23:43:47 2023 from 10.0.0.2\r\r\n--- JUNOS 19.4R1.10 built 2019-12-19 03:54:05 UTC\r\n"}
read	{"data": "{master:0}\r\n"}
read	{"data": "vrnetlab@vr-vqfx> "}
write	{"text": "show123", "written": 7}
write	{"text": "\n", "written": 1}
read to	{"expr": "show123 *\\r\\n,\\n(?P<user>[\\w]{1,10})@(?P<hostname>[\\w-]{1,10})> $"}
read	{"data": "show123\r\n"}
read to	{"expr": "\\n(?P<user>[\\w]{1,10})@(?P<hostname>[\\w-]{1,10})> $"}
read	{"data": "                  ^\r\nunknown command.\r\n\r\n"}
read	{"data": "{master:0}\r\nvrnetlab@vr-vqfx> "}

```

Update config with `error_expression` and test data for it.

```yaml
devices:
  - name: myvendor
    prompt_expression: '\n(?P<user>[\w]{1,10})@(?P<hostname>[\w-]{1,10})> $'
    error_expression: ' *\^\r\nunknown command.\r\n'
    features: 
      - spaces_after_echo
    tests:
      prompt_expression_variants:
        - "\r\nvrnetlab@vr-vqfx> "
      error_expression_variants:
        - "                  ^\r\nunknown command\.\r\n"
```

#### Pager

What if a device use pagination for long output? 

```text
write	{"text": "show interfaces", "written": 15}
write	{"text": "\n", "written": 1}
read to	{"expr": "show interfaces *\\r\\n,\\n(?P<user>[\\w]{1,10})@(?P<hostname>[\\w-]{1,10})> $"}
read	{"data": "show interfaces \r\n"}
read to	{"expr": "\\n(?P<user>[\\w]{1,10})@(?P<hostname>[\\w-]{1,10})> $"}
read	{"data": "Physical interface: gr-0/0/0, Enabled, Physical link is Up\r\n"}
read	{"data": "  Interface index: 646, SNMP ifIndex: 504\r\n"}
read	{"data": "  Type: GRE, Link-level type: GRE, MTU: Unlimited, Speed: 800mbps\r\n"}
read	{"data": "  Device flags   : Present Running\r\n"}
read	{"data": "  Interface flags: Point-To-Point SNMP-Traps\r\n"}
read	{"data": "  Input rate     : 0 bps (0 pps)\r\n"}
read	{"data": "  Output rate    : 0 bps (0 pps)\r\n"}
read	{"data": "\r\n"}
read	{"data": "Physical interface: pfe-0/0/0, Enabled, Physical link is Up\r\n  Interface index: 649, SNMP ifIndex: 511\r\n  Speed: 800mbps\r\n  Device flags   : Present Running\r\n  Link flags     : None\r\n  Last flapped   : Never\r\n    Input packets : 0\r\n    Output packets: 0\r\n"}
read	{"data": "\r\n"}
read	{"data": "  Logical interface pfe-0/0/0.16383 (Index 552) (SNMP ifIndex 512)\r\n    Flags: Up SNMP-Traps Encapsulation: ENET2\r\n    Bandwidth: 0\r\n    Input packets : 0\r\n    Output packets: 0\r\n"}
read	{"data": "    Protocol inet, MTU: Unlimited\r\n"}
read	{"data": "---(more)---"}
error	{"error": "read timeout error...
```
Also, percent may be written in pager like this: `---(more 76%)---`.

Let's add pager expression and test cases.

```yaml
devices:
  - name: myvendor
    prompt_expression: '\n(?P<user>[\w]{1,10})@(?P<hostname>[\w-]{1,10})> $'
    error_expression: ' *\^\r\nunknown command.\r\n'
    pager_expression: '---\(more( \d{1,2}%)?\)---'
    features: 
      - spaces_after_echo
    tests:
      prompt_expression_variants:
        - "\r\nvrnetlab@vr-vqfx> "
      error_expression_variants:
        - "                  ^\r\nunknown command\.\r\n"
      pager_expression_variants:
        - "---(more)---"
        - "---(more 76%)---"
```

#### Questions

```bash
cli -dev-conf myvendor.yaml -devtype 'myvendor' -command 'request system reboot' -port 2222 -hostname 127.0.0.1 -login vrnetlab -password VR-netlab9 -debug 2>&1
```

Output:

```text
write	{"text": "request system reboot", "written": 21}
write	{"text": "\n", "written": 1}
read to	{"expr": "request system reboot *\\r\\n,\\n(?P<user>[\\w]{1,10})@(?P<hostname>[\\w-]{1,10})> $,---\\(more( \\d{1,2}%)?\\)---"}
read	{"data": "request system reboot "}
read	{"data": "\r\n"}
read to	{"expr": "\\n(?P<user>[\\w]{1,10})@(?P<hostname>[\\w-]{1,10})> $,---\\(more( \\d{1,2}%)?\\)---"}
read	{"data": "Reboot the system ? [yes,no] (no) "}
error	{"error": "read timeout error...
```

The command didn't return prompt, that is why it timed out.
First of all, we can add expression `question_expression` for the question.
With this the expression we will see more descriptive error: `no answer for question`.

```yaml
devices:
  - name: myvendor
    prompt_expression: '\n(?P<user>[\w]{1,10})@(?P<hostname>[\w-]{1,10})> $'
    error_expression: ' *\^\r\nunknown command.\r\n'
    pager_expression: '---\(more( \d{1,2}%)?\)---'
    question_expression: '\n.+\? \[yes,no\] \(no\) $'
```

Even without `question_expression` we can specify question and answer using `-question` arg:

```bash
cli -dev-conf myvendor.yaml -devtype 'myvendor' -command 'request system reboot' -port 2222 -hostname 127.0.0.1 -login vrnetlab -password VR-netlab9 -debug -question 'Reboot the system ? [yes,no] (no) :::yes'
```

#### Auto commands

Sometimes it is needed to run some commands to set up CLI, like disable paging, set terminal width, etc.
`autocmd` feature solves it:

```yaml
devices:
  - name: myvendor
    features: 
      - spaces_after_echo 
      - autocmd: 
        - set cli complete-on-space off 
        - set cli screen-length 0
```

#### Final config
```yaml
devices:
  - name: myvendor
    prompt_expression: '\n(?P<user>[\w]{1,10})@(?P<hostname>[\w-]{1,10})> $'
    error_expression: ' *\^\r\nunknown command\.\r\n'
    pager_expression: '---\(more( \d{1,2}%)?\)---'
    question_expression: '\n.+\? \[yes,no\] \(no\) $'
    features: [spaces_after_echo, {autocmd: [test, test]}]
    tests:
      prompt_expression_variants:
          - "\r\nvrnetlab@vr-vqfx> "
      error_expression_variants:
          - "                  ^\r\nunknown command.\r\n"
```
