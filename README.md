# Go SOCKS5 Proxy Server

A complete SOCKS5 proxy server implementation in Go following RFC 1928 specifications.

## Features

- **RFC 1928 Compliant**: Full implementation of SOCKS Protocol Version 5
- **Authentication Methods**:
  - No authentication (0x00)
  - GSSAPI authentication (0x01) - framework implemented
  - Username/Password authentication (0x02)
- **Commands**:
  - CONNECT (0x01) - TCP connection relay
  - BIND (0x02) - Reverse connection support for FTP-like protocols
  - UDP ASSOCIATE (0x03) - UDP packet relay
- **Address Types**:
  - IPv4 addresses (0x01)
  - IPv6 addresses (0x04)  
  - Domain names (0x03)
- **Advanced Features**:
  - Access control system (whitelist/blacklist)
  - Enhanced error handling with proper RFC reply codes
  - Connection timeout management (RFC-compliant 10-second cleanup)
  - UDP packet fragmentation handling
- **Go Best Practices**: Clean, idiomatic Go code with proper error handling

## Usage

### Basic Usage (No Authentication)

```bash
go run main.go
```

This starts a SOCKS5 server on port 1080 with no authentication required.

### With Username/Password Authentication

```bash
go run main.go -user myuser -pass mypass
```

### Custom Port

```bash
go run main.go -addr :8080
```

## Testing

Test the server using curl:

```bash
# Test with no auth
curl --socks5 localhost:1080 https://httpbin.org/ip

# Test with username/password
curl --socks5-hostname myuser:mypass@localhost:1080 https://httpbin.org/ip
```

## Advanced Configuration

### Access Control

```go
// Blacklist specific hosts/networks
blacklist := socks5.BlacklistAccess{
    BlacklistedHosts: []string{"malicious.com", "blocked.net"},
    BlacklistedNets: []*net.IPNet{
        // Block private networks
        mustParseCIDR("10.0.0.0/8"),
        mustParseCIDR("192.168.0.0/16"),
    },
}

config := &socks5.Config{
    AccessControl: blacklist,
}
```

### Custom Authentication

```go
// Enable GSSAPI authentication (requires additional setup)
gssapi := socks5.GSSAPIAuthenticator{AcceptAll: true}
config := &socks5.Config{
    AuthMethods: []socks5.Authenticator{gssapi},
}
```

## Implementation Details

### Protocol Flow

1. **Version/Method Negotiation**: Client sends supported authentication methods
2. **Authentication**: Server selects and performs authentication if required
3. **Request**: Client sends connection request (CONNECT/BIND/UDP ASSOCIATE)
4. **Reply**: Server responds with success/failure and bound address
5. **Relay**: Bidirectional data forwarding or UDP packet relay

### Package Structure

- `main.go`: Server entry point with command-line interface
- `socks5/server.go`: Core server implementation and command handlers
- `socks5/auth.go`: Authentication methods (NoAuth, UserPass, GSSAPI)
- `socks5/request.go`: Request parsing for all address types
- `socks5/reply.go`: RFC-compliant reply generation
- `socks5/udp.go`: UDP ASSOCIATE command implementation
- `socks5/access.go`: Access control system
- `socks5/constants.go`: Protocol constants and reply codes

### Key Components

- **Server**: Manages connections and orchestrates the SOCKS5 protocol
- **Authenticator Interface**: Pluggable authentication system
- **Request/Reply**: RFC-compliant message parsing and generation
- **Address Handling**: Support for IPv4, IPv6, and domain names
- **Command Handlers**: CONNECT, BIND, and UDP ASSOCIATE implementations
- **Access Control**: Configurable connection filtering
- **Error Mapping**: Network errors to proper SOCKS5 reply codes

## Configuration

The server supports these configuration options:

- **Address**: Listen address (default: `:1080`)
- **Authentication**: Optional username/password credentials
- **Logging**: Configurable logger
- **Dialer**: Custom connection dialer with timeout

## Security Considerations

- Implements proper authentication validation
- Includes connection timeouts to prevent resource exhaustion
- Validates all protocol fields according to RFC 1928
- Graceful error handling without information leakage

## License

MIT License