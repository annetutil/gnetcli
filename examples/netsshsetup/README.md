## Description

This script was created for enabling SSH on Network Devices. How to use it:

```
./netsshsetup -a 192.168.0.1 -v cisco -b ios -l test -p test -P telnet --ipdomain example.com
```

```
./netsshsetup --help
Enable SSH on the network device

Usage:
  netsshsetup [flags]

Flags:
  -a, --address string    set up ip address
  -b, --breed string      set up breed from list: ios
  -h, --help              help for netsshsetup
      --hostname string   set up hostname
      --ipdomain string   set up ipdomain
  -l, --login string      set up login
  -p, --password string   set up password
  -P, --protocol string   set up ip protocol from list: ssh, telnet
  -v, --vendor string     set up vendor from list: cisco
```

How to build for linux: `env GOOS=linux GOARCH=arm go build`
