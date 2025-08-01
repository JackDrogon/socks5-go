package socks5

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// Client represents a SOCKS5 proxy client
type Client struct {
	server      string
	credentials *UserPassCredentials
	timeout     time.Duration
}

// UserPassCredentials holds username/password authentication credentials
type UserPassCredentials struct {
	Username string
	Password string
}

// ClientConfig holds client configuration options
type ClientConfig struct {
	ServerAddr  string
	Credentials *UserPassCredentials
	Timeout     time.Duration
}

// NewClient creates a new SOCKS5 client with the given configuration
func NewClient(config *ClientConfig) (*Client, error) {
	if config == nil {
		return nil, errors.New("client config cannot be nil")
	}

	if config.ServerAddr == "" {
		return nil, errors.New("server address cannot be empty")
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	return &Client{
		server:      config.ServerAddr,
		credentials: config.Credentials,
		timeout:     timeout,
	}, nil
}

// Dial establishes a connection through the SOCKS5 proxy
func (c *Client) Dial(network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return c.dialTCP(addr)
	case "udp", "udp4", "udp6":
		return c.dialUDP(addr)
	default:
		return nil, fmt.Errorf("unsupported network type: %s", network)
	}
}

// dialTCP handles TCP connections through SOCKS5 CONNECT
func (c *Client) dialTCP(addr string) (net.Conn, error) {
	// Connect to SOCKS5 server
	conn, err := net.DialTimeout("tcp", c.server, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 server: %w", err)
	}

	// Perform SOCKS5 handshake
	if err := c.handshake(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake failed: %w", err)
	}

	// Send CONNECT request
	if err := c.sendConnectRequest(conn, addr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("CONNECT request failed: %w", err)
	}

	return conn, nil
}

// dialUDP handles UDP connections through SOCKS5 UDP ASSOCIATE
func (c *Client) dialUDP(addr string) (net.Conn, error) {
	// Connect to SOCKS5 server
	tcpConn, err := net.DialTimeout("tcp", c.server, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 server for UDP: %w", err)
	}

	// Perform SOCKS5 handshake
	if err := c.handshake(tcpConn); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("SOCKS5 handshake failed: %w", err)
	}

	// Send UDP ASSOCIATE request
	udpRelayAddr, err := c.sendUDPAssociateRequest(tcpConn, addr)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE request failed: %w", err)
	}

	// Create UDP connection wrapper
	udpWrapper := &UDPConnection{
		tcpConn:      tcpConn,
		udpRelayAddr: udpRelayAddr,
		targetAddr:   addr,
	}

	return udpWrapper, nil
}

// handshake performs the SOCKS5 authentication handshake
func (c *Client) handshake(conn net.Conn) error {
	// Step 1: Send version identifier/method selection message
	var authMethods []byte
	if c.credentials != nil {
		// Support both NO AUTH and USERNAME/PASSWORD
		authMethods = []byte{AuthMethodNoAuth, AuthMethodUserPass}
	} else {
		// Only support NO AUTH
		authMethods = []byte{AuthMethodNoAuth}
	}

	// Build request: VER | NMETHODS | METHODS
	request := []byte{SOCKS5Version, byte(len(authMethods))}
	request = append(request, authMethods...)

	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("failed to send auth methods: %w", err)
	}

	// Step 2: Read server's method selection response
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("failed to read auth method response: %w", err)
	}

	if response[0] != SOCKS5Version {
		return fmt.Errorf("unexpected protocol version: %d", response[0])
	}

	selectedMethod := response[1]
	if selectedMethod == AuthMethodNoAcceptable {
		return errors.New("no acceptable authentication methods")
	}

	// Step 3: Perform method-specific authentication
	switch selectedMethod {
	case AuthMethodNoAuth:
		// No additional authentication required
		return nil
	case AuthMethodUserPass:
		return c.authenticateUserPass(conn)
	default:
		return fmt.Errorf("unsupported authentication method: %d", selectedMethod)
	}
}

// authenticateUserPass performs username/password authentication
func (c *Client) authenticateUserPass(conn net.Conn) error {
	if c.credentials == nil {
		return errors.New("credentials required for username/password authentication")
	}

	username := c.credentials.Username
	password := c.credentials.Password

	// Build authentication request
	// Format: VERSION | ULEN | UNAME | PLEN | PASSWD
	request := []byte{0x01} // Username/password authentication version
	request = append(request, byte(len(username)))
	request = append(request, []byte(username)...)
	request = append(request, byte(len(password)))
	request = append(request, []byte(password)...)

	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("failed to send credentials: %w", err)
	}

	// Read authentication response
	response := make([]byte, 2)
	if _, err := io.ReadFull(conn, response); err != nil {
		return fmt.Errorf("failed to read auth response: %w", err)
	}

	if response[0] != 0x01 {
		return fmt.Errorf("unexpected auth response version: %d", response[0])
	}

	if response[1] != 0x00 {
		return errors.New("authentication failed")
	}

	return nil
}

// sendConnectRequest sends a CONNECT request and processes the response
func (c *Client) sendConnectRequest(conn net.Conn, addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	// Build CONNECT request
	request := []byte{SOCKS5Version, CmdConnect, 0x00} // VER | CMD | RSV

	// Add address type and address
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4 address
			request = append(request, AtypeIPv4)
			request = append(request, ip4...)
		} else {
			// IPv6 address
			request = append(request, AtypeIPv6)
			request = append(request, ip.To16()...)
		}
	} else {
		// Domain name
		if len(host) > 255 {
			return errors.New("domain name too long")
		}
		request = append(request, AtypeDomain)
		request = append(request, byte(len(host)))
		request = append(request, []byte(host)...)
	}

	// Add port (2 bytes, network byte order)
	request = append(request, byte(port>>8), byte(port&0xff))

	// Send request
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	// Read and process response
	return c.readConnectResponse(conn)
}

// readConnectResponse reads and validates the CONNECT response
func (c *Client) readConnectResponse(conn net.Conn) error {
	// Read fixed part of response: VER | REP | RSV | ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read response header: %w", err)
	}

	if header[0] != SOCKS5Version {
		return fmt.Errorf("unexpected protocol version: %d", header[0])
	}

	replyCode := header[1]
	if replyCode != RepSuccess {
		return c.mapReplyError(replyCode)
	}

	// Read bound address based on address type
	addrType := header[3]
	switch addrType {
	case AtypeIPv4:
		// 4 bytes for IPv4 + 2 bytes for port
		if _, err := io.ReadFull(conn, make([]byte, 6)); err != nil {
			return fmt.Errorf("failed to read IPv4 bound address: %w", err)
		}
	case AtypeIPv6:
		// 16 bytes for IPv6 + 2 bytes for port
		if _, err := io.ReadFull(conn, make([]byte, 18)); err != nil {
			return fmt.Errorf("failed to read IPv6 bound address: %w", err)
		}
	case AtypeDomain:
		// Read domain length
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return fmt.Errorf("failed to read domain length: %w", err)
		}
		domainLen := int(lenBuf[0])
		// Read domain + 2 bytes for port
		if _, err := io.ReadFull(conn, make([]byte, domainLen+2)); err != nil {
			return fmt.Errorf("failed to read domain bound address: %w", err)
		}
	default:
		return fmt.Errorf("unsupported address type: %d", addrType)
	}

	return nil
}

// sendUDPAssociateRequest sends a UDP ASSOCIATE request and returns the UDP relay address
func (c *Client) sendUDPAssociateRequest(conn net.Conn, addr string) (string, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid address format: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("invalid port: %w", err)
	}

	// Build UDP ASSOCIATE request
	request := []byte{SOCKS5Version, CmdUDPAssociate, 0x00} // VER | CMD | RSV

	// Add address type and address
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4 address
			request = append(request, AtypeIPv4)
			request = append(request, ip4...)
		} else {
			// IPv6 address
			request = append(request, AtypeIPv6)
			request = append(request, ip.To16()...)
		}
	} else {
		// Domain name
		if len(host) > 255 {
			return "", errors.New("domain name too long")
		}
		request = append(request, AtypeDomain)
		request = append(request, byte(len(host)))
		request = append(request, []byte(host)...)
	}

	// Add port (2 bytes, network byte order)
	request = append(request, byte(port>>8), byte(port&0xff))

	// Send request
	if _, err := conn.Write(request); err != nil {
		return "", fmt.Errorf("failed to send UDP ASSOCIATE request: %w", err)
	}

	// Read and process response
	return c.readUDPAssociateResponse(conn)
}

// readUDPAssociateResponse reads the UDP ASSOCIATE response and returns the relay address
func (c *Client) readUDPAssociateResponse(conn net.Conn) (string, error) {
	// Read fixed part of response: VER | REP | RSV | ATYP
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("failed to read response header: %w", err)
	}

	if header[0] != SOCKS5Version {
		return "", fmt.Errorf("unexpected protocol version: %d", header[0])
	}

	replyCode := header[1]
	if replyCode != RepSuccess {
		return "", c.mapReplyError(replyCode)
	}

	// Read bound address based on address type
	addrType := header[3]
	var relayAddr string

	switch addrType {
	case AtypeIPv4:
		// 4 bytes for IPv4 + 2 bytes for port
		addrBuf := make([]byte, 6)
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return "", fmt.Errorf("failed to read IPv4 bound address: %w", err)
		}
		ip := net.IP(addrBuf[:4])
		port := int(addrBuf[4])<<8 | int(addrBuf[5])
		relayAddr = net.JoinHostPort(ip.String(), strconv.Itoa(port))

	case AtypeIPv6:
		// 16 bytes for IPv6 + 2 bytes for port
		addrBuf := make([]byte, 18)
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return "", fmt.Errorf("failed to read IPv6 bound address: %w", err)
		}
		ip := net.IP(addrBuf[:16])
		port := int(addrBuf[16])<<8 | int(addrBuf[17])
		relayAddr = net.JoinHostPort(ip.String(), strconv.Itoa(port))

	case AtypeDomain:
		// Read domain length
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("failed to read domain length: %w", err)
		}
		domainLen := int(lenBuf[0])
		// Read domain + 2 bytes for port
		addrBuf := make([]byte, domainLen+2)
		if _, err := io.ReadFull(conn, addrBuf); err != nil {
			return "", fmt.Errorf("failed to read domain bound address: %w", err)
		}
		domain := string(addrBuf[:domainLen])
		port := int(addrBuf[domainLen])<<8 | int(addrBuf[domainLen+1])
		relayAddr = net.JoinHostPort(domain, strconv.Itoa(port))

	default:
		return "", fmt.Errorf("unsupported address type: %d", addrType)
	}

	return relayAddr, nil
}

// mapReplyError maps SOCKS5 reply codes to descriptive errors
func (c *Client) mapReplyError(code uint8) error {
	switch code {
	case RepSuccess:
		return nil
	case RepServerFailure:
		return errors.New("general SOCKS server failure")
	case RepNotAllowed:
		return errors.New("connection not allowed by ruleset")
	case RepNetworkUnreachable:
		return errors.New("network unreachable")
	case RepHostUnreachable:
		return errors.New("host unreachable")
	case RepConnectionRefused:
		return errors.New("connection refused")
	case RepTTLExpired:
		return errors.New("TTL expired")
	case RepCommandNotSupported:
		return errors.New("command not supported")
	case RepAddressNotSupported:
		return errors.New("address type not supported")
	default:
		return fmt.Errorf("unknown reply code: %d", code)
	}
}
