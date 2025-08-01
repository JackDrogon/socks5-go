# Go SOCKS5 Proxy Server & Client

A complete SOCKS5 proxy server and client implementation in Go following RFC 1928 specifications.

## Quick Start

```bash
# Build everything
make all

# Start the server
make dev-server

# In another terminal, run client examples
make run-examples
```

## Features

### Server
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

### Client
- **Full RFC 1928 Support**: Complete SOCKS5 client implementation
- **Authentication Methods**:
  - No authentication (0x00)
  - Username/Password authentication (0x02)
- **Connection Types**:
  - TCP connections via CONNECT command
  - UDP connections via UDP ASSOCIATE command
- **Address Types**: IPv4, IPv6, and domain name resolution
- **Integration-Friendly**: Easy integration with HTTP clients and custom applications
- **Go Best Practices**: Clean, idiomatic Go code with proper error handling

## Usage

### Server Usage

#### Building the Server

```bash
# Build using Makefile
make server

# Or build manually
go build -o build/socks5-server bin/socks5-server.go
```

#### Basic Usage (No Authentication)

```bash
# Run the built binary
./build/socks5-server

# Or use Makefile
make dev-server
```

This starts a SOCKS5 server on port 1080 with no authentication required.

#### With Username/Password Authentication

```bash
# Run with authentication
./build/socks5-server -user myuser -pass mypass

# Or use Makefile
make dev-server-auth
```

#### Custom Port

```bash
./build/socks5-server -addr :8080
```

#### Testing the Server

Test the server using curl:

```bash
# Test with no auth
curl --socks5 localhost:1080 https://httpbin.org/ip

# Test with username/password
curl --socks5-hostname myuser:mypass@localhost:1080 https://httpbin.org/ip
```

### Client Usage

#### Building and Running Examples

```bash
# Build all examples
make examples

# Or build specific example
go build -o build/examples/http_client examples/http_client.go

# Run examples (requires server to be running)
make run-examples
```

#### Available Examples

1. **HTTP Client** (`examples/http_client.go`)
   ```bash
   go run examples/http_client.go
   ```

2. **HTTP Client with Authentication** (`examples/http_client_auth.go`)
   ```bash
   go run examples/http_client_auth.go
   ```

3. **Direct TCP Connection** (`examples/tcp_client.go`)
   ```bash
   go run examples/tcp_client.go
   ```

4. **UDP Connection** (`examples/udp_client.go`)
   ```bash
   go run examples/udp_client.go
   ```

#### Library Usage

##### Basic HTTP Client

```go
package main

import (
    "fmt"
    "io"
    "net/http"
    "time"
    "github.com/JackDrogon/socks5-go/socks5"
)

func main() {
    config := &socks5.ClientConfig{
        ServerAddr: "localhost:1080",
        Timeout:    30 * time.Second,
    }
    
    client, err := socks5.NewClient(config)
    if err != nil {
        panic(err)
    }
    
    httpClient := &http.Client{
        Transport: &http.Transport{
            Dial: client.Dial,
        },
        Timeout: 30 * time.Second,
    }
    
    resp, err := httpClient.Get("https://httpbin.org/ip")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    
    body, _ := io.ReadAll(resp.Body)
    fmt.Printf("Response: %s\n", body)
}
```

##### With Authentication

```go
config := &socks5.ClientConfig{
    ServerAddr: "localhost:1080",
    Credentials: &socks5.UserPassCredentials{
        Username: "myuser",
        Password: "mypass",
    },
    Timeout: 30 * time.Second,
}
```

See the `examples/` directory for complete working examples.

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

```
socks5-go/
├── bin/                     # Server executables
│   └── socks5-server.go    # SOCKS5 server main
├── build/                   # Build output (created by Makefile)
│   ├── socks5-server       # Server binary
│   └── examples/           # Client example binaries
├── examples/               # Client usage examples
│   ├── http_client.go      # HTTP client example
│   ├── http_client_auth.go # HTTP client with auth
│   ├── tcp_client.go       # Direct TCP connection
│   ├── udp_client.go       # UDP connection example
│   └── README.md           # Examples documentation
├── socks5/                 # Core library
│   ├── server.go           # Server implementation
│   ├── client.go           # Client implementation
│   ├── udp_client.go       # UDP client wrapper
│   ├── auth.go             # Authentication methods
│   ├── request.go          # Request parsing
│   ├── reply.go            # Reply generation
│   ├── udp.go              # UDP ASSOCIATE support
│   ├── access.go           # Access control
│   └── constants.go        # Protocol constants
├── tests/                  # Integration tests
├── Makefile               # Build and development scripts
├── go.mod                 # Go module definition
└── README.md              # This file
```

### Key Components

#### Server
- **Server**: Manages connections and orchestrates the SOCKS5 protocol
- **Authenticator Interface**: Pluggable authentication system
- **Request/Reply**: RFC-compliant message parsing and generation
- **Address Handling**: Support for IPv4, IPv6, and domain names
- **Command Handlers**: CONNECT, BIND, and UDP ASSOCIATE implementations
- **Access Control**: Configurable connection filtering
- **Error Mapping**: Network errors to proper SOCKS5 reply codes

#### Client
- **Client**: SOCKS5 proxy client with full RFC 1928 support
- **Connection Management**: TCP and UDP connection handling through proxy
- **Authentication**: Support for No Auth and Username/Password methods
- **Address Resolution**: IPv4, IPv6, and domain name support
- **Error Handling**: Comprehensive SOCKS5 reply code mapping
- **net.Conn Interface**: Standard Go network interface compatibility

## Build and Development

### Using the Makefile

The project includes a comprehensive Makefile for building, testing, and development:

```bash
# Build everything
make all

# Build only the server
make server

# Build only the client examples
make examples

# Clean build artifacts
make clean

# Run tests
make test

# Run tests with coverage
make test-coverage

# Format code
make fmt

# Start development server
make dev-server

# Start server with authentication
make dev-server-auth

# Run all examples (requires server running)
make run-examples

# Build release binaries for multiple platforms
make release

# Show all available targets
make help
```

### Manual Building

```bash
# Build server manually
go build -o build/socks5-server bin/socks5-server.go

# Build specific example
go build -o build/examples/http_client examples/http_client.go

# Build with optimizations
go build -ldflags "-w -s" -o build/socks5-server bin/socks5-server.go
```

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