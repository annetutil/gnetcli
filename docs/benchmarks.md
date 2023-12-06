### Benchmarks

Command `cmd/gvendor` provides SSH-server with predefined scenarios to test clients like gnetcli, scrapligo etc.
Usage:

```text
Usage of /tmp/linux:
  -debug
    	Set debug log level
  -host string
    	Server host (default "localhost")
  -port int
    	Server port (default 2222)
  -scenario string
    	Scenario to play. Available: unicode, smalldata, smalldata_with_binary, hugedata_10000, hugedata_chunk_100_20000, bunch_cmd_1000
```

Tests must be done across network, not on localhost. 
Client must run infinite loop there it must send `next` command, read result and use as a command.
Last command will quit, after which server will close connection.
