### scrapligo

See [github.com/scrapli/scrapligo](https://github.com/scrapli/scrapligo).

- Uses `ssh` external binary to communicate with a device.
  It is less portable solution because it relies on external program, which may be absent or change its args.
- Lack of upload/download support.
- Do not have GRPC-server.
- Do not have builtin pager support.
- scrapligo has notion of PrivilegeLevel, gnetcli does not - just commands.

Scrapligo implements configuration mode and package for parsing of output.

#### Benchmarks

See benchmarks docs.

bunch_cmd_1000 - consecutive execution of 1000 cmds.\
hugedata_chunk_100_20000 - 1 command with 20000 lines.

| -         | bunch_cmd_1000 | hugedata_chunk_100_20000 |
|-----------|----------------|--------------------------|
| Gnetcli   | 20.93s         | 0.753071s                |
| Scrapligo | 21.33s         | 0.737026s                |
