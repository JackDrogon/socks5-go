package socks5

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

type Config struct {
	AuthMethods   []Authenticator
	Logger        *log.Logger
	Dial          func(network, addr string) (net.Conn, error)
	AccessControl AccessControl
}

type Server struct {
	config      *Config
	authMethods map[uint8]Authenticator
}

func New(config *Config) (*Server, error) {
	if config == nil {
		config = &Config{}
	}

	if len(config.AuthMethods) == 0 {
		config.AuthMethods = []Authenticator{NoAuthAuthenticator{}}
	}

	if config.Dial == nil {
		config.Dial = func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, 10*time.Second)
		}
	}

	if config.AccessControl == nil {
		config.AccessControl = AllowAllAccess{}
	}

	server := &Server{
		config:      config,
		authMethods: make(map[uint8]Authenticator),
	}

	for _, auth := range config.AuthMethods {
		server.authMethods[auth.GetCode()] = auth
	}

	return server, nil
}

func (s *Server) Serve(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("failed to accept connection: %w", err)
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	authenticator, err := s.authenticate(conn)
	if err != nil {
		s.logf("Authentication failed: %v", err)
		return
	}

	request, err := NewRequest(conn)
	if err != nil {
		s.logf("Failed to parse request: %v", err)

		// Map specific errors to appropriate reply codes
		replyCode := s.mapRequestError(err)
		sendReply(conn, replyCode, nil)
		return
	}

	switch request.Command {
	case cmdConnect:
		s.handleConnect(conn, request, authenticator)
	case cmdBind:
		s.handleBind(conn, request, authenticator)
	case cmdUDPAssociate:
		s.handleUDPAssociate(conn, request, authenticator)
	default:
		sendReply(conn, repCommandNotSupported, nil)
	}
}

func (s *Server) authenticate(conn net.Conn) (Authenticator, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("failed to read auth header: %w", err)
	}

	if header[0] != socks5Version {
		return nil, fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	numMethods := int(header[1])
	// RFC 1928: NMETHODS must be 1-255
	if numMethods < 1 || numMethods > 255 {
		return nil, fmt.Errorf("invalid NMETHODS value: %d (must be 1-255)", numMethods)
	}

	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, fmt.Errorf("failed to read auth methods: %w", err)
	}

	for _, method := range methods {
		if authenticator, ok := s.authMethods[method]; ok {
			if _, err := conn.Write([]byte{socks5Version, method}); err != nil {
				return nil, fmt.Errorf("failed to write auth response: %w", err)
			}
			if err := authenticator.Authenticate(conn); err != nil {
				return nil, err
			}
			return authenticator, nil
		}
	}

	if _, err := conn.Write([]byte{socks5Version, authMethodNoAcceptable}); err != nil {
		return nil, fmt.Errorf("failed to write no acceptable methods: %w", err)
	}
	return nil, fmt.Errorf("no acceptable authentication methods")
}

func (s *Server) handleConnect(conn net.Conn, req *Request, auth Authenticator) {
	// Check access control
	if !s.config.AccessControl.Allow(conn.RemoteAddr(), req.RealDest) {
		s.logf("Connection to %s denied by access control from %s", req.RealDest, conn.RemoteAddr())
		sendReply(conn, repNotAllowed, nil)
		time.AfterFunc(10*time.Second, func() {
			conn.Close()
		})
		return
	}

	target, err := s.config.Dial("tcp", req.RealDest)
	if err != nil {
		s.logf("Failed to connect to %s: %v", req.RealDest, err)

		// Map network errors to appropriate SOCKS5 reply codes
		replyCode := s.mapNetworkError(err)
		sendReply(conn, replyCode, nil)

		// RFC 1928: close connection within 10 seconds of failure
		time.AfterFunc(10*time.Second, func() {
			conn.Close()
		})
		return
	}
	defer target.Close()

	if err := sendReply(conn, repSuccess, target.LocalAddr()); err != nil {
		s.logf("Failed to send reply: %v", err)
		return
	}

	s.logf("Connected to %s", req.RealDest)
	s.relayWithEncapsulation(conn, target, auth)
}

// mapNetworkError maps Go network errors to SOCKS5 reply codes
func (s *Server) mapNetworkError(err error) uint8 {
	if err == nil {
		return repSuccess
	}

	errStr := err.Error()

	// Check for specific error types
	errStrLower := strings.ToLower(errStr)
	switch {
	case strings.Contains(errStrLower, "network is unreachable"):
		return repNetworkUnreachable
	case strings.Contains(errStrLower, "no such host"):
		return repHostUnreachable
	case strings.Contains(errStrLower, "connection refused"):
		return repConnectionRefused
	case strings.Contains(errStrLower, "timeout"):
		return repTTLExpired
	case strings.Contains(errStrLower, "permission denied"):
		return repNotAllowed
	default:
		return repServerFailure
	}
}

// mapRequestError maps request parsing errors to SOCKS5 reply codes
func (s *Server) mapRequestError(err error) uint8 {
	if err == nil {
		return repSuccess
	}

	errStr := strings.ToLower(err.Error())
	switch {
	case strings.Contains(errStr, "unsupported command"):
		return repCommandNotSupported
	case strings.Contains(errStr, "unsupported address type"):
		return repAddressNotSupported
	case strings.Contains(errStr, "unsupported socks version"):
		return repServerFailure
	case strings.Contains(errStr, "invalid reserved field"):
		return repServerFailure
	default:
		return repServerFailure
	}
}

func (s *Server) handleBind(conn net.Conn, req *Request, auth Authenticator) {
	// RFC 1928: Use DST.ADDR and DST.PORT in evaluating the BIND request
	s.logf("BIND request for destination %s", req.RealDest)

	// Check access control for BIND request
	if !s.config.AccessControl.Allow(conn.RemoteAddr(), req.RealDest) {
		s.logf("BIND to %s denied by access control from %s", req.RealDest, conn.RemoteAddr())
		sendReply(conn, repNotAllowed, nil)
		return
	}

	// Create a listener for incoming connections
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		s.logf("Failed to create bind listener: %v", err)
		sendReply(conn, repServerFailure, nil)
		return
	}
	defer listener.Close()

	// Send first reply with bind address
	if err := sendReply(conn, repSuccess, listener.Addr()); err != nil {
		s.logf("Failed to send bind reply: %v", err)
		return
	}

	s.logf("BIND listening on %s for target %s", listener.Addr(), req.RealDest)

	// Set accept timeout
	if tcpListener, ok := listener.(*net.TCPListener); ok {
		tcpListener.SetDeadline(time.Now().Add(60 * time.Second))
	}

	// Accept incoming connection
	target, err := listener.Accept()
	if err != nil {
		s.logf("Failed to accept bind connection: %v", err)
		sendReply(conn, repConnectionRefused, nil)
		return
	}
	defer target.Close()

	// Send second reply with actual connection info
	if err := sendReply(conn, repSuccess, target.RemoteAddr()); err != nil {
		s.logf("Failed to send second bind reply: %v", err)
		return
	}

	s.logf("BIND connection established from %s", target.RemoteAddr())

	// Start relaying data with encapsulation support
	s.relayWithEncapsulation(conn, target, auth)
}

func (s *Server) handleUDPAssociate(conn net.Conn, req *Request, auth Authenticator) {
	// RFC 1928: Use DST.ADDR and DST.PORT to evaluate UDP ASSOCIATE request
	s.logf("UDP ASSOCIATE request for destination %s", req.RealDest)

	// Check access control for UDP ASSOCIATE request
	if !s.config.AccessControl.Allow(conn.RemoteAddr(), req.RealDest) {
		s.logf("UDP ASSOCIATE to %s denied by access control from %s", req.RealDest, conn.RemoteAddr())
		sendReply(conn, repNotAllowed, nil)
		return
	}

	// Create UDP socket for relaying
	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		s.logf("Failed to resolve UDP address: %v", err)
		sendReply(conn, repServerFailure, nil)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		s.logf("Failed to create UDP socket: %v", err)
		sendReply(conn, repServerFailure, nil)
		return
	}
	defer udpConn.Close()

	// Send reply with UDP relay address
	if err := sendReply(conn, repSuccess, udpConn.LocalAddr()); err != nil {
		s.logf("Failed to send UDP associate reply: %v", err)
		return
	}

	s.logf("UDP ASSOCIATE established, relay on %s", udpConn.LocalAddr())

	// Start UDP relay goroutine with encapsulation support
	go s.handleUDPRelayWithEncapsulation(udpConn, conn.RemoteAddr(), auth)

	// Keep TCP connection alive to maintain UDP association
	// UDP association terminates when TCP connection closes
	buffer := make([]byte, 1)
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, err := conn.Read(buffer)
		if err != nil {
			s.logf("UDP ASSOCIATE TCP connection closed: %v", err)
			break
		}
	}
}

func (s *Server) relay(conn1, conn2 net.Conn) {
	done := make(chan struct{}, 2)

	go func() {
		io.Copy(conn1, conn2)
		done <- struct{}{}
	}()

	go func() {
		io.Copy(conn2, conn1)
		done <- struct{}{}
	}()

	<-done
}

// relayWithEncapsulation handles data relay with method-dependent encapsulation
func (s *Server) relayWithEncapsulation(clientConn, targetConn net.Conn, auth Authenticator) {
	if !auth.SupportsEncapsulation() {
		// No encapsulation needed, use regular relay
		s.relay(clientConn, targetConn)
		return
	}

	s.logf("Using method-dependent encapsulation for data relay")
	done := make(chan struct{}, 2)

	// Client -> Target (unwrap then forward)
	go func() {
		defer func() { done <- struct{}{} }()

		buffer := make([]byte, 32*1024)
		for {
			n, err := clientConn.Read(buffer)
			if err != nil {
				return
			}

			// Unwrap data received from client
			unwrappedData, err := auth.UnwrapData(buffer[:n])
			if err != nil {
				s.logf("Failed to unwrap client data: %v", err)
				return
			}

			// Forward unwrapped data to target
			if _, err := targetConn.Write(unwrappedData); err != nil {
				return
			}
		}
	}()

	// Target -> Client (wrap then forward)
	go func() {
		defer func() { done <- struct{}{} }()

		buffer := make([]byte, 32*1024)
		for {
			n, err := targetConn.Read(buffer)
			if err != nil {
				return
			}

			// Wrap data from target
			wrappedData, err := auth.WrapData(buffer[:n])
			if err != nil {
				s.logf("Failed to wrap target data: %v", err)
				return
			}

			// Forward wrapped data to client
			if _, err := clientConn.Write(wrappedData); err != nil {
				return
			}
		}
	}()

	<-done
}

func (s *Server) logf(format string, args ...interface{}) {
	if s.config.Logger != nil {
		s.config.Logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}
