# Streamer Types

`gnetcli` supports different connection types (streamers) for connecting to network equipment: SSH, Telnet.

## Supported Types

### Unknown (StreamerType_unknown)
- **Value**: `0`
- **Description**: Unspecified connection type, server will determine based on port or default to SSH
- **Usage**: When not explicitly set

### SSH (StreamerType_ssh)
- **Value**: `1`
- **Description**: Connection via SSH protocol (default when unknown)
- **Default port**: 22
- **Features**:
  - SSH tunnel support (ProxyJump)
  - SSH Control Files support
  - SSH Agent support
  - Private key authentication
  - SFTP for file transfers

### Telnet (StreamerType_telnet)
- **Value**: `2`
- **Description**: Connection via Telnet protocol
- **Default port**: 23
- **Features**:
  - Plain text connection
  - Username/password authentication
  - Custom port support

## API Usage

### Via gRPC
The streamer type is specified in host parameters:

```protobuf
message HostParams {
  string host = 1;
  Credentials credentials = 2;
  int32 port = 3;
  string device = 4;
  string ip = 5;
  StreamerType streamer_type = 6;  // SSH or Telnet
}
```

### Example Request
```json
{
  "host": "192.168.1.1",
  "cmd": "show version",
  "host_params": {
    "streamer_type": 2,
    "port": 23,
    "credentials": {
      "login": "admin",
      "password": "password"
    }
  }
}
```
Note: `streamer_type: 2` for Telnet, `streamer_type: 1` for SSH, `streamer_type: 0` for unknown/auto-detect.

## Choosing Streamer Type

### SSH is recommended for:
- Modern network equipment
- Production environments where security is important
- Devices supporting cryptographic authentication
- Cases requiring file transfers

### Telnet is suitable for:
- Legacy equipment without SSH support
- Lab and test environments
- Devices with limited computational resources
- Connection debugging and diagnostics

## Default Configuration

If `streamer_type` is not explicitly specified, SSH is used as the more secure default option.
