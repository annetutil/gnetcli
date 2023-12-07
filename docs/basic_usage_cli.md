Gnetcli 'cli' is a tool for executing commands on a device.
It is useful for using in automation and device regular expression debuging.

For example:

```shell
cli -hostname myhost -devtype huawei -command $'dis clock\ndis ver0' -password $password -json
```

```json
[
  {
    "output": "2023-10-29 10:00:00\nSunday\nTime Zone(UTC) : UTC\n",
    "error": "",
    "status": 0,
    "cmd": "dis clock"
  },
  {
    "output": "",
    "error": "              ^\nError: Unrecognized command found at '^' position.\n",
    "status": 1,
    "cmd": "dis ver0"
  }
]
```

### Help

```
Usage of cli:
  -command string
    	Command
  -debug
    	Set debug log level
  -dev-conf string
    	Path to yaml with device types
  -devtype string
    	Device type from dev-conf file or from predifined: juniper, huawei, cisco, nxos, pc, netconf
  -hostname string
    	Hostname
  -json
    	Output in JSON
  -login string
    	Login
  -password string
    	Password
  -port int
    	Port (default 22)
```
