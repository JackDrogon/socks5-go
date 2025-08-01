package socks5

import (
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

type Config struct {
	AuthMethods []Authenticator
	Logger      *log.Logger
	Dial        func(network, addr string) (net.Conn, error)
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

	if err := s.authenticate(conn); err != nil {
		s.logf("Authentication failed: %v", err)
		return
	}

	request, err := NewRequest(conn)
	if err != nil {
		s.logf("Failed to parse request: %v", err)
		sendReply(conn, repServerFailure, nil)
		return
	}

	switch request.Command {
	case cmdConnect:
		s.handleConnect(conn, request)
	default:
		sendReply(conn, repCommandNotSupported, nil)
	}
}

func (s *Server) authenticate(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read auth header: %w", err)
	}

	if header[0] != socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("failed to read auth methods: %w", err)
	}

	for _, method := range methods {
		if authenticator, ok := s.authMethods[method]; ok {
			if _, err := conn.Write([]byte{socks5Version, method}); err != nil {
				return fmt.Errorf("failed to write auth response: %w", err)
			}
			return authenticator.Authenticate(conn)
		}
	}

	if _, err := conn.Write([]byte{socks5Version, authMethodNoAcceptable}); err != nil {
		return fmt.Errorf("failed to write no acceptable methods: %w", err)
	}
	return fmt.Errorf("no acceptable authentication methods")
}

func (s *Server) handleConnect(conn net.Conn, req *Request) {
	target, err := s.config.Dial("tcp", req.RealDest)
	if err != nil {
		s.logf("Failed to connect to %s: %v", req.RealDest, err)
		sendReply(conn, repHostUnreachable, nil)
		return
	}
	defer target.Close()

	if err := sendReply(conn, repSuccess, target.LocalAddr()); err != nil {
		s.logf("Failed to send reply: %v", err)
		return
	}

	s.logf("Connected to %s", req.RealDest)
	s.relay(conn, target)
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

func (s *Server) logf(format string, args ...interface{}) {
	if s.config.Logger != nil {
		s.config.Logger.Printf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}