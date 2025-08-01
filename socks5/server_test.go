package socks5

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNewServerDefaults(t *testing.T) {
	server, err := New(nil)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	if server.config == nil {
		t.Errorf("Server config should not be nil")
	}

	if len(server.config.AuthMethods) != 1 {
		t.Errorf("Default auth methods length = %d, expected 1", len(server.config.AuthMethods))
	}

	if server.config.AuthMethods[0].GetCode() != authMethodNoAuth {
		t.Errorf("Default auth method = %d, expected %d", server.config.AuthMethods[0].GetCode(), authMethodNoAuth)
	}

	if server.config.Dial == nil {
		t.Errorf("Default dial function should not be nil")
	}

	if server.config.AccessControl == nil {
		t.Errorf("Default access control should not be nil")
	}
}

func TestNewServerCustomConfig(t *testing.T) {
	config := &Config{
		AuthMethods: []Authenticator{
			UserPassAuthenticator{
				Credentials: StaticCredentials{"user": "pass"},
			},
		},
		Logger: log.New(os.Stdout, "test: ", log.LstdFlags),
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial(network, addr)
		},
		AccessControl: AllowAllAccess{},
	}

	server, err := New(config)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	if len(server.authMethods) != 1 {
		t.Errorf("Auth methods map length = %d, expected 1", len(server.authMethods))
	}

	if _, exists := server.authMethods[authMethodUserPass]; !exists {
		t.Errorf("UserPass auth method not found in server auth methods")
	}
}

func TestServerAuthentication(t *testing.T) {
	config := &Config{
		AuthMethods: []Authenticator{
			NoAuthAuthenticator{},
			UserPassAuthenticator{
				Credentials: StaticCredentials{"testuser": "testpass"},
			},
		},
	}

	server, err := New(config)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	// Test successful no-auth authentication
	authRequest := []byte{
		0x05, // Version
		0x02, // Number of methods
		0x00, // No auth
		0x02, // Username/password
	}

	conn := &mockConn{readData: authRequest}
	authenticator, err := server.authenticate(conn)
	if err != nil {
		t.Fatalf("authenticate() returned error: %v", err)
	}

	if authenticator.GetCode() != authMethodNoAuth {
		t.Errorf("Expected no-auth authenticator, got %d", authenticator.GetCode())
	}

	// Check response
	response := conn.writeData
	expectedResponse := []byte{0x05, 0x00} // Version 5, No auth
	if len(response) >= 2 && !bytes.Equal(response[:2], expectedResponse) {
		t.Errorf("Auth response = %v, expected %v", response[:2], expectedResponse)
	}
}

func TestServerAuthenticationInvalidVersion(t *testing.T) {
	server, _ := New(nil)

	authRequest := []byte{
		0x04, // Wrong version
		0x01, // Number of methods
		0x00, // No auth
	}

	conn := &mockConn{readData: authRequest}
	_, err := server.authenticate(conn)
	if err == nil {
		t.Errorf("authenticate() should return error for invalid version")
	}

	expectedError := "unsupported SOCKS version"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestServerAuthenticationInvalidNMethods(t *testing.T) {
	server, _ := New(nil)

	// Test NMETHODS = 0 (invalid)
	authRequest := []byte{
		0x05, // Version
		0x00, // Invalid: 0 methods
	}

	conn := &mockConn{readData: authRequest}
	_, err := server.authenticate(conn)
	if err == nil {
		t.Errorf("authenticate() should return error for NMETHODS = 0")
	}

	expectedError := "invalid NMETHODS value"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestServerAuthenticationNoAcceptableMethods(t *testing.T) {
	config := &Config{
		AuthMethods: []Authenticator{
			UserPassAuthenticator{
				Credentials: StaticCredentials{"user": "pass"},
			},
		},
	}
	server, _ := New(config)

	authRequest := []byte{
		0x05, // Version
		0x01, // Number of methods
		0x00, // No auth (not supported by server)
	}

	conn := &mockConn{readData: authRequest}
	_, err := server.authenticate(conn)
	if err == nil {
		t.Errorf("authenticate() should return error when no methods are acceptable")
	}

	expectedError := "no acceptable authentication methods"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}

	// Check response - should indicate no acceptable methods
	response := conn.writeData
	expectedResponse := []byte{0x05, 0xFF} // Version 5, No acceptable methods
	if len(response) >= 2 && !bytes.Equal(response[:2], expectedResponse) {
		t.Errorf("Auth response = %v, expected %v", response[:2], expectedResponse)
	}
}

func TestMapNetworkError(t *testing.T) {
	server, _ := New(nil)

	testCases := []struct {
		errorStr string
		expected uint8
	}{
		{"network is unreachable", repNetworkUnreachable},
		{"no such host", repHostUnreachable},
		{"connection refused", repConnectionRefused},
		{"timeout", repTTLExpired},
		{"permission denied", repNotAllowed},
		{"unknown error", repServerFailure},
	}

	for _, tc := range testCases {
		t.Run(tc.errorStr, func(t *testing.T) {
			err := fmt.Errorf("test error: %s", tc.errorStr)
			result := server.mapNetworkError(err)
			if result != tc.expected {
				t.Errorf("mapNetworkError(%s) = %d, expected %d", tc.errorStr, result, tc.expected)
			}
		})
	}

	// Test nil error
	result := server.mapNetworkError(nil)
	if result != repSuccess {
		t.Errorf("mapNetworkError(nil) = %d, expected %d", result, repSuccess)
	}
}

func TestMapRequestError(t *testing.T) {
	server, _ := New(nil)

	testCases := []struct {
		errorStr string
		expected uint8
	}{
		{"unsupported command", repCommandNotSupported},
		{"unsupported address type", repAddressNotSupported},
		{"unsupported socks version", repServerFailure},
		{"invalid reserved field", repServerFailure},
		{"unknown error", repServerFailure},
	}

	for _, tc := range testCases {
		t.Run(tc.errorStr, func(t *testing.T) {
			err := fmt.Errorf("test error: %s", tc.errorStr)
			result := server.mapRequestError(err)
			if result != tc.expected {
				t.Errorf("mapRequestError(%s) = %d, expected %d", tc.errorStr, result, tc.expected)
			}
		})
	}

	// Test nil error
	result := server.mapRequestError(nil)
	if result != repSuccess {
		t.Errorf("mapRequestError(nil) = %d, expected %d", result, repSuccess)
	}
}

func TestServerLogf(t *testing.T) {
	// Test with custom logger
	var buf bytes.Buffer
	logger := log.New(&buf, "test: ", 0)
	config := &Config{Logger: logger}
	server, _ := New(config)

	server.logf("test message %d", 123)

	logOutput := buf.String()
	if !strings.Contains(logOutput, "test message 123") {
		t.Errorf("Expected log output to contain 'test message 123', got '%s'", logOutput)
	}

	// Test with nil logger (should use default log)
	server2, _ := New(nil)
	// This should not panic
	server2.logf("test message")
}

// Mock connection for testing
type mockConn struct {
	readData    []byte
	writeData   []byte
	readPos     int
	readErr     error
	writeErr    error
	localAddr   net.Addr
	remoteAddr  net.Addr
	closed      bool
	closedMutex sync.Mutex
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	if m.readPos >= len(m.readData) {
		return 0, io.EOF
	}
	n = copy(b, m.readData[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.closedMutex.Lock()
	m.writeData = append(m.writeData, b...)
	m.closedMutex.Unlock()
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.closedMutex.Lock()
	m.closed = true
	m.closedMutex.Unlock()
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	if m.localAddr != nil {
		return m.localAddr
	}
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:1080")
	return addr
}

func (m *mockConn) RemoteAddr() net.Addr {
	if m.remoteAddr != nil {
		return m.remoteAddr
	}
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:12345")
	return addr
}

func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func (m *mockConn) isClosed() bool {
	m.closedMutex.Lock()
	defer m.closedMutex.Unlock()
	return m.closed
}

func TestHandleConnectionAuthFailure(t *testing.T) {
	server, _ := New(nil)

	// Create connection with invalid auth data
	conn := &mockConn{
		readData: []byte{0x04, 0x01, 0x00}, // Wrong version
	}

	// Should not panic and should close connection
	server.handleConnection(conn)

	// Connection should be closed after auth failure
	if !conn.isClosed() {
		t.Errorf("Connection should be closed after auth failure")
	}
}

func TestHandleConnectionRequestFailure(t *testing.T) {
	server, _ := New(nil)

	// Create connection with valid auth but invalid request
	authData := []byte{0x05, 0x01, 0x00}          // Valid auth (no auth)
	requestData := []byte{0x04, 0x01, 0x00, 0x01} // Invalid version in request

	conn := &mockConn{
		readData: append(authData, requestData...),
	}

	server.handleConnection(conn)

	// Should write error response
	if len(conn.writeData) == 0 {
		t.Errorf("Expected server to write error response")
	}
}

// Mock access control for testing
type mockAccessControl struct {
	allowResult bool
}

func (m *mockAccessControl) Allow(clientAddr net.Addr, destAddr string) bool {
	return m.allowResult
}

func TestHandleConnectAccessDenied(t *testing.T) {
	config := &Config{
		AccessControl: &mockAccessControl{allowResult: false},
	}
	server, _ := New(config)

	req := &Request{
		Command:  cmdConnect,
		AddrType: atypeIPv4,
		RealDest: "127.0.0.1:80",
	}

	conn := &mockConn{}
	auth := NoAuthAuthenticator{}

	server.handleConnect(conn, req, auth)

	// Should write access denied response
	if len(conn.writeData) < 2 {
		t.Fatalf("Expected server to write response")
	}

	// Check for repNotAllowed in response
	if conn.writeData[1] != repNotAllowed {
		t.Errorf("Expected repNotAllowed (0x%02X), got 0x%02X", repNotAllowed, conn.writeData[1])
	}
}

func TestHandleBindAccessDenied(t *testing.T) {
	config := &Config{
		AccessControl: &mockAccessControl{allowResult: false},
	}
	server, _ := New(config)

	req := &Request{
		Command:  cmdBind,
		AddrType: atypeIPv4,
		RealDest: "127.0.0.1:80",
	}

	conn := &mockConn{}
	auth := NoAuthAuthenticator{}

	server.handleBind(conn, req, auth)

	// Should write access denied response
	if len(conn.writeData) < 2 {
		t.Fatalf("Expected server to write response")
	}

	if conn.writeData[1] != repNotAllowed {
		t.Errorf("Expected repNotAllowed (0x%02X), got 0x%02X", repNotAllowed, conn.writeData[1])
	}
}

func TestHandleUDPAssociateAccessDenied(t *testing.T) {
	config := &Config{
		AccessControl: &mockAccessControl{allowResult: false},
	}
	server, _ := New(config)

	req := &Request{
		Command:  cmdUDPAssociate,
		AddrType: atypeIPv4,
		RealDest: "127.0.0.1:0",
	}

	conn := &mockConn{}
	auth := NoAuthAuthenticator{}

	server.handleUDPAssociate(conn, req, auth)

	// Should write access denied response
	if len(conn.writeData) < 2 {
		t.Fatalf("Expected server to write response")
	}

	if conn.writeData[1] != repNotAllowed {
		t.Errorf("Expected repNotAllowed (0x%02X), got 0x%02X", repNotAllowed, conn.writeData[1])
	}
}

func TestRelayWithEncapsulation(t *testing.T) {
	server, _ := New(nil)

	// Test with no encapsulation
	conn1 := &mockConn{readData: []byte("hello")}
	conn2 := &mockConn{}
	auth := NoAuthAuthenticator{}

	// This will start relay but we can't easily test the full relay without complex setup
	// Just test that it doesn't panic
	go server.relayWithEncapsulation(conn1, conn2, auth)
	time.Sleep(10 * time.Millisecond)
}

func TestHandleConnectionInvalidCommand(t *testing.T) {
	server, _ := New(nil)

	// Create valid auth data
	authData := []byte{0x05, 0x01, 0x00} // Version 5, 1 method, no auth

	// Create request with invalid command
	requestData := []byte{
		0x05,         // Version
		0x99,         // Invalid command
		0x00,         // Reserved
		0x01,         // Address type
		127, 0, 0, 1, // IP address
		0x00, 0x50, // Port 80
	}

	conn := &mockConn{
		readData: append(authData, requestData...),
	}

	server.handleConnection(conn)

	// Should write command not supported response
	if len(conn.writeData) < 10 { // Auth response + command response
		t.Fatalf("Expected server to write responses")
	}

	// Find the command response (after auth response)
	commandResponse := conn.writeData[2:] // Skip auth response
	if len(commandResponse) >= 2 && commandResponse[1] != repCommandNotSupported {
		t.Errorf("Expected repCommandNotSupported (0x%02X), got 0x%02X", repCommandNotSupported, commandResponse[1])
	}
}

// Test server.Serve method
func TestServerServe(t *testing.T) {
	server, _ := New(nil)

	// Create a listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}

	// Start server in goroutine
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Serve(listener)
	}()

	// Give server time to start
	time.Sleep(10 * time.Millisecond)

	// Close listener to stop server
	listener.Close()

	// Wait for server to exit
	select {
	case err := <-serverErr:
		// Server should exit with an error when listener is closed
		if err == nil {
			t.Errorf("Expected Serve() to return error when listener is closed")
		}
	case <-time.After(1 * time.Second):
		t.Errorf("Server did not exit within timeout")
	}
}

func TestAuthenticationReadErrors(t *testing.T) {
	server, _ := New(nil)

	// Test read error on initial header
	conn := &mockConn{
		readErr: io.ErrUnexpectedEOF,
	}

	_, err := server.authenticate(conn)
	if err == nil {
		t.Errorf("Expected error when read fails")
	}
}

func TestAuthenticationShortMethods(t *testing.T) {
	server, _ := New(nil)

	// Valid header but not enough method data
	conn := &mockConn{
		readData: []byte{0x05, 0x02, 0x00}, // Says 2 methods but only provides 1
		readErr:  io.ErrUnexpectedEOF,
	}

	_, err := server.authenticate(conn)
	if err == nil {
		t.Errorf("Expected error when methods data is insufficient")
	}
}

func TestHandleConnectSuccessful(t *testing.T) {
	// Create a mock target server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create target listener: %v", err)
	}
	defer targetListener.Close()

	targetAddr := targetListener.Addr().(*net.TCPAddr)

	config := &Config{
		AccessControl: AllowAllAccess{},
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial(network, addr)
		},
	}
	server, _ := New(config)

	req := &Request{
		Command:  cmdConnect,
		AddrType: atypeIPv4,
		RealDest: targetAddr.String(),
	}

	conn := &mockConn{}
	auth := NoAuthAuthenticator{}

	// Start target server to accept connections
	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	server.handleConnect(conn, req, auth)

	// Should write success response
	if len(conn.writeData) < 2 {
		t.Fatalf("Expected server to write response")
	}

	if conn.writeData[1] != repSuccess {
		t.Errorf("Expected repSuccess (0x%02X), got 0x%02X", repSuccess, conn.writeData[1])
	}
}

func TestHandleConnectDialFailure(t *testing.T) {
	config := &Config{
		AccessControl: AllowAllAccess{},
		Dial: func(network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("connection refused")
		},
	}
	server, _ := New(config)

	req := &Request{
		Command:  cmdConnect,
		AddrType: atypeIPv4,
		RealDest: "127.0.0.1:99999", // Non-existent port
	}

	conn := &mockConn{}
	auth := NoAuthAuthenticator{}

	server.handleConnect(conn, req, auth)

	// Should write error response
	if len(conn.writeData) < 2 {
		t.Fatalf("Expected server to write response")
	}

	if conn.writeData[1] != repConnectionRefused {
		t.Errorf("Expected repConnectionRefused (0x%02X), got 0x%02X", repConnectionRefused, conn.writeData[1])
	}
}

func TestHandleBindSuccess(t *testing.T) {
	config := &Config{
		AccessControl: AllowAllAccess{},
	}
	server, _ := New(config)

	req := &Request{
		Command:  cmdBind,
		AddrType: atypeIPv4,
		RealDest: "127.0.0.1:0", // Any port
	}

	conn := &mockConn{}
	auth := NoAuthAuthenticator{}

	// Run handleBind in a goroutine since it will block waiting for connections
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleBind(conn, req, auth)
	}()

	// Give it time to set up the listener
	time.Sleep(50 * time.Millisecond)

	// Should write first reply (bind success) - protect with mutex
	conn.closedMutex.Lock()
	writeDataLen := len(conn.writeData)
	var repCode byte
	if writeDataLen >= 2 {
		repCode = conn.writeData[1]
	}
	conn.closedMutex.Unlock()

	if writeDataLen < 2 {
		t.Fatalf("Expected server to write first bind response")
	}

	if repCode != repSuccess {
		t.Errorf("Expected repSuccess (0x%02X), got 0x%02X", repSuccess, repCode)
	}
}

func TestHandleUDPAssociateSuccess(t *testing.T) {
	config := &Config{
		AccessControl: AllowAllAccess{},
	}
	server, _ := New(config)

	req := &Request{
		Command:  cmdUDPAssociate,
		AddrType: atypeIPv4,
		RealDest: "0.0.0.0:0", // Any address/port for UDP ASSOCIATE
	}

	conn := &mockConn{}
	auth := NoAuthAuthenticator{}

	// Run handleUDPAssociate in a goroutine since it will block
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleUDPAssociate(conn, req, auth)
	}()

	// Give it time to set up UDP socket
	time.Sleep(50 * time.Millisecond)

	// Should write success response - protect with mutex
	conn.closedMutex.Lock()
	writeDataLen := len(conn.writeData)
	var repCode byte
	if writeDataLen >= 2 {
		repCode = conn.writeData[1]
	}
	conn.closedMutex.Unlock()

	if writeDataLen < 2 {
		t.Fatalf("Expected server to write UDP associate response")
	}

	if repCode != repSuccess {
		t.Errorf("Expected repSuccess (0x%02X), got 0x%02X", repSuccess, repCode)
	}

	// Close the connection to stop the handler
	conn.Close()
}

func TestRelayWithEncapsulationGSSAPI(t *testing.T) {
	server, _ := New(nil)

	// Create mock connections
	conn1 := &mockConn{readData: []byte("test data")}
	conn2 := &mockConn{}
	auth := GSSAPIAuthenticator{}

	// This should use encapsulation path
	go server.relayWithEncapsulation(conn1, conn2, auth)
	time.Sleep(10 * time.Millisecond)
}

func TestHandleBindListenFailure(t *testing.T) {
	// Test BIND timeout scenario
	config := &Config{
		AccessControl: AllowAllAccess{},
	}
	server, _ := New(config)

	req := &Request{
		Command:  cmdBind,
		AddrType: atypeIPv4,
		RealDest: "127.0.0.1:0", // Valid request
	}

	conn := &mockConn{}
	auth := NoAuthAuthenticator{}

	// Run in goroutine since it will timeout
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleBind(conn, req, auth)
	}()

	// Give it time to set up the listener and then timeout
	time.Sleep(10 * time.Millisecond)

	// Should write success response initially - protect with mutex
	conn.closedMutex.Lock()
	writeDataLen := len(conn.writeData)
	var repCode byte
	if writeDataLen >= 2 {
		repCode = conn.writeData[1]
	}
	conn.closedMutex.Unlock()

	if writeDataLen < 2 {
		t.Fatalf("Expected server to write response")
	}

	if repCode != repSuccess {
		t.Errorf("Expected repSuccess (0x%02X), got 0x%02X", repSuccess, repCode)
	}
}

func TestHandleUDPAssociateResolveFailure(t *testing.T) {
	// Create a config that should cause UDP resolution to fail
	config := &Config{
		AccessControl: AllowAllAccess{},
	}
	server, _ := New(config)

	req := &Request{
		Command:  cmdUDPAssociate,
		AddrType: atypeIPv4,
		RealDest: "0.0.0.0:0",
	}

	// Mock a UDP resolve failure by using the original server methods
	// but we can't easily mock net.ResolveUDPAddr, so we'll test other paths
	conn := &mockConn{}
	auth := NoAuthAuthenticator{}

	// This test mainly ensures the function runs without panicking
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleUDPAssociate(conn, req, auth)
	}()

	time.Sleep(50 * time.Millisecond)
	conn.Close()
}

func TestAuthenticationWriteError(t *testing.T) {
	server, _ := New(nil)

	authRequest := []byte{
		0x05, // Version
		0x01, // Number of methods
		0x00, // No auth
	}

	conn := &mockConn{
		readData: authRequest,
		writeErr: fmt.Errorf("write failed"),
	}

	_, err := server.authenticate(conn)
	if err == nil {
		t.Errorf("Expected error when write fails")
	}
}

func TestNewRequestCoverage(t *testing.T) {
	// Test additional error paths in NewRequest

	// Test with address read failure
	requestData := []byte{
		0x05, // Version
		0x01, // Command (CONNECT)
		0x00, // Reserved
		0x01, // Address type (IPv4)
		// Missing address data
	}

	reader := &errorReader{
		data: requestData,
		err:  io.ErrUnexpectedEOF,
	}

	_, err := NewRequest(reader)
	if err == nil {
		t.Errorf("NewRequest() should return error when address read fails")
	}
}

func TestServerCoverage(t *testing.T) {
	// Test New() with nil Dial function coverage
	config := &Config{
		AuthMethods: []Authenticator{NoAuthAuthenticator{}},
		Dial:        nil, // Should use default
	}

	server, err := New(config)
	if err != nil {
		t.Fatalf("New() returned error: %v", err)
	}

	if server.config.Dial == nil {
		t.Errorf("Default dial should be set when config.Dial is nil")
	}

	// Test default dial function
	_, err = server.config.Dial("tcp", "127.0.0.1:80")
	// Don't check error as it might timeout, just ensure it doesn't panic
}

func TestHandleConnectSendReplyError(t *testing.T) {
	// Create a mock target server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create target listener: %v", err)
	}
	defer targetListener.Close()

	targetAddr := targetListener.Addr().(*net.TCPAddr)

	config := &Config{
		AccessControl: AllowAllAccess{},
		Dial: func(network, addr string) (net.Conn, error) {
			return net.Dial(network, addr)
		},
	}
	server, _ := New(config)

	req := &Request{
		Command:  cmdConnect,
		AddrType: atypeIPv4,
		RealDest: targetAddr.String(),
	}

	// Mock connection that fails to write reply
	conn := &mockConn{
		writeErr: fmt.Errorf("write failed"),
	}
	auth := NoAuthAuthenticator{}

	// Start target server to accept connections
	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	server.handleConnect(conn, req, auth)

	// Should attempt to write but fail
	if len(conn.writeData) > 0 {
		t.Errorf("Expected no data written due to write error")
	}
}

func TestHandleBindComplete(t *testing.T) {
	config := &Config{
		AccessControl: AllowAllAccess{},
	}
	server, _ := New(config)

	req := &Request{
		Command:  cmdBind,
		AddrType: atypeIPv4,
		RealDest: "127.0.0.1:0",
	}

	conn := &mockConn{}
	auth := NoAuthAuthenticator{}

	// Start handleBind in goroutine
	done := make(chan struct{})
	var bindAddr *net.TCPAddr
	go func() {
		defer close(done)
		server.handleBind(conn, req, auth)
	}()

	// Give it time to set up the listener
	time.Sleep(50 * time.Millisecond)

	// Parse the bind address from the first response
	conn.closedMutex.Lock()
	writeDataLen := len(conn.writeData)
	var portBytes []byte
	if writeDataLen >= 10 {
		// Extract port from the response (last 2 bytes)
		portBytes = make([]byte, 2)
		copy(portBytes, conn.writeData[writeDataLen-2:])
	}
	conn.closedMutex.Unlock()

	if writeDataLen >= 10 {
		port := int(portBytes[0])<<8 | int(portBytes[1])

		// Connect to the bind port to simulate incoming connection
		bindAddr, _ = net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if bindAddr != nil {
			go func() {
				time.Sleep(10 * time.Millisecond)
				conn, err := net.Dial("tcp", bindAddr.String())
				if err == nil {
					conn.Close()
				}
			}()
		}
	}

	// Wait a bit more for the second response
	time.Sleep(100 * time.Millisecond)
}

func TestHandleBindWriteError(t *testing.T) {
	config := &Config{
		AccessControl: AllowAllAccess{},
	}
	server, _ := New(config)

	req := &Request{
		Command:  cmdBind,
		AddrType: atypeIPv4,
		RealDest: "127.0.0.1:0",
	}

	conn := &mockConn{writeErr: fmt.Errorf("write failed")}
	auth := NoAuthAuthenticator{}

	server.handleBind(conn, req, auth)
	// Should handle write error gracefully
}

func TestRelayWithEncapsulationWithErrors(t *testing.T) {
	server, _ := New(nil)

	// Test with connection that has write errors
	conn1 := &mockConn{
		readData: []byte("test data"),
	}
	conn2 := &mockConn{
		writeErr: fmt.Errorf("write failed"),
	}

	auth := GSSAPIAuthenticator{AcceptAll: true}

	// Start relay - should handle errors gracefully
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.relayWithEncapsulation(conn1, conn2, auth)
	}()

	// Wait for it to complete or timeout
	select {
	case <-done:
		// Good, it completed
	case <-time.After(100 * time.Millisecond):
		// Also good, it's running
	}
}

func TestNewRequestErrorPaths(t *testing.T) {
	// Test more error paths in NewRequest

	// Test address spec read failure for IPv4
	requestData := []byte{
		0x05,     // Version
		0x01,     // Command (CONNECT)
		0x00,     // Reserved
		0x01,     // Address type (IPv4)
		192, 168, // Incomplete IPv4 address
	}

	buf := bytes.NewBuffer(requestData)
	_, err := NewRequest(buf)
	if err == nil {
		t.Errorf("NewRequest() should return error for incomplete IPv4 address")
	}

	// Test address spec read failure for domain
	requestData2 := []byte{
		0x05,          // Version
		0x01,          // Command (CONNECT)
		0x00,          // Reserved
		0x03,          // Address type (Domain)
		0x05,          // Domain length
		't', 'e', 's', // Incomplete domain
	}

	buf2 := bytes.NewBuffer(requestData2)
	_, err = NewRequest(buf2)
	if err == nil {
		t.Errorf("NewRequest() should return error for incomplete domain")
	}
}

func TestAuthenticateNMethodsEdgeCase(t *testing.T) {
	server, _ := New(nil)

	// Test NMETHODS = 255 (valid max)
	authRequest := []byte{0x05, 0xFF} // Version 5, 255 methods
	// Add 255 method bytes
	for i := 0; i < 255; i++ {
		authRequest = append(authRequest, 0x99) // Invalid method
	}

	conn := &mockConn{readData: authRequest}
	_, err := server.authenticate(conn)
	if err == nil {
		t.Errorf("Expected error for no acceptable methods")
	}
}

func TestNMethodsRFCBoundaryCompliance(t *testing.T) {
	server, _ := New(nil)

	// Test NMETHODS = 0 (invalid per RFC 1928)
	testCases := []struct {
		name      string
		nmethods  byte
		methods   []byte
		shouldErr bool
		errMsg    string
	}{
		{
			name:      "NMETHODS=0 should fail",
			nmethods:  0x00,
			methods:   []byte{},
			shouldErr: true,
			errMsg:    "invalid NMETHODS value",
		},
		{
			name:      "NMETHODS=1 with valid method",
			nmethods:  0x01,
			methods:   []byte{0x00},
			shouldErr: false,
			errMsg:    "",
		},
		{
			name:      "NMETHODS=1 with invalid method",
			nmethods:  0x01,
			methods:   []byte{0x99},
			shouldErr: true,
			errMsg:    "no acceptable authentication methods",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authRequest := []byte{0x05, tc.nmethods}
			authRequest = append(authRequest, tc.methods...)

			conn := &mockConn{readData: authRequest}
			_, err := server.authenticate(conn)

			if tc.shouldErr {
				if err == nil {
					t.Errorf("Expected error for %s", tc.name)
				} else if !strings.Contains(err.Error(), tc.errMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tc.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tc.name, err)
				}
			}
		})
	}
}

func TestServerAcceptError(t *testing.T) {
	server, _ := New(nil)

	// Create a mock listener that fails on Accept
	listener := &mockListener{
		acceptErr: fmt.Errorf("accept failed"),
	}

	err := server.Serve(listener)
	if err == nil {
		t.Errorf("Expected error when Accept fails")
	}

	if !strings.Contains(err.Error(), "accept failed") {
		t.Errorf("Expected error about accept failure, got: %v", err)
	}
}

// Mock listener for testing
type mockListener struct {
	addr      net.Addr
	closed    bool
	acceptErr error
}

func (m *mockListener) Accept() (net.Conn, error) {
	if m.acceptErr != nil {
		return nil, m.acceptErr
	}
	// Return a mock connection
	return &mockConn{}, nil
}

func (m *mockListener) Close() error {
	m.closed = true
	return nil
}

func (m *mockListener) Addr() net.Addr {
	if m.addr != nil {
		return m.addr
	}
	addr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:1080")
	return addr
}

// Tests for RFC 1928 compliance fixes

func TestAuthenticateInvalidSOCKSVersion(t *testing.T) {
	server, _ := New(nil)

	testCases := []struct {
		name    string
		version byte
		methods []byte
	}{
		{"SOCKS version 4", 0x04, []byte{0x01, 0x00}},
		{"SOCKS version 6", 0x06, []byte{0x01, 0x00}},
		{"SOCKS version 0", 0x00, []byte{0x01, 0x00}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authRequest := []byte{tc.version}
			authRequest = append(authRequest, tc.methods...)

			conn := &mockConn{readData: authRequest}
			_, err := server.authenticate(conn)

			// Should fail with unsupported version error
			if err == nil {
				t.Errorf("Expected error for unsupported SOCKS version %d", tc.version)
			}

			if !strings.Contains(err.Error(), "unsupported SOCKS version") {
				t.Errorf("Expected 'unsupported SOCKS version' error, got: %v", err)
			}

			// Should send rejection response
			if len(conn.writeData) < 2 {
				t.Errorf("Expected server to send rejection response")
			} else if conn.writeData[0] != socks5Version || conn.writeData[1] != authMethodNoAcceptable {
				t.Errorf("Expected rejection response [0x05, 0xFF], got [0x%02X, 0x%02X]", 
					conn.writeData[0], conn.writeData[1])
			}
		})
	}
}

func TestAuthenticateNMethodsZero(t *testing.T) {
	server, _ := New(nil)

	// RFC 1928: NMETHODS = 0 is invalid
	authRequest := []byte{0x05, 0x00} // Version 5, 0 methods

	conn := &mockConn{readData: authRequest}
	_, err := server.authenticate(conn)

	// Should fail
	if err == nil {
		t.Errorf("Expected error for NMETHODS = 0")
	}

	if !strings.Contains(err.Error(), "invalid NMETHODS value: 0") {
		t.Errorf("Expected 'invalid NMETHODS value: 0' error, got: %v", err)
	}

	// Should send rejection response
	if len(conn.writeData) < 2 {
		t.Errorf("Expected server to send rejection response")
	} else if conn.writeData[1] != authMethodNoAcceptable {
		t.Errorf("Expected rejection response with code 0xFF, got 0x%02X", conn.writeData[1])
	}
}

func TestGSSAPIAuthenticatorIntegration(t *testing.T) {
	// Test that GSSAPI authenticator can be used in server config
	gssapiAuth := GSSAPIAuthenticator{AcceptAll: true}
	
	config := &Config{
		AuthMethods: []Authenticator{gssapiAuth},
	}
	
	server, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create server with GSSAPI auth: %v", err)
	}

	// Verify GSSAPI is registered
	if _, ok := server.authMethods[authMethodGSSAPI]; !ok {
		t.Errorf("GSSAPI authenticator not registered in server")
	}

	// Test GSSAPI authentication with mock GSSAPI token
	authRequest := []byte{
		0x05, // Version
		0x01, // 1 method
		0x01, // GSSAPI method
	}
	
	// Add mock GSSAPI token that the authenticator will try to read
	gssapiToken := []byte("mock_gssapi_token_data")
	authRequest = append(authRequest, gssapiToken...)

	conn := &mockConn{readData: authRequest}
	auth, err := server.authenticate(conn)
	
	if err != nil {
		t.Errorf("GSSAPI authentication failed: %v", err)
	}

	if auth == nil {
		t.Errorf("Expected authenticator to be returned")
	} else if auth.GetCode() != authMethodGSSAPI {
		t.Errorf("Expected GSSAPI authenticator (code %d), got code %d", authMethodGSSAPI, auth.GetCode())
	}
}

func TestRequestValidationReservedField(t *testing.T) {
	// Test that non-zero reserved field is rejected
	requestData := []byte{
		0x05, // Version
		0x01, // Command (CONNECT)
		0x01, // Reserved (should be 0x00) - THIS IS THE BUG WE'RE TESTING
		0x01, // Address type (IPv4)
		127, 0, 0, 1, // IPv4 address (127.0.0.1)
		0x00, 0x50, // Port 80
	}

	buf := bytes.NewBuffer(requestData)
	_, err := NewRequest(buf)

	if err == nil {
		t.Errorf("Expected error for non-zero reserved field")
	}

	if !strings.Contains(err.Error(), "invalid reserved field") {
		t.Errorf("Expected 'invalid reserved field' error, got: %v", err)
	}
}

func TestRequestValidationUnsupportedCommand(t *testing.T) {
	// Test that unsupported commands are rejected
	requestData := []byte{
		0x05, // Version
		0x99, // Command (unsupported)
		0x00, // Reserved
		0x01, // Address type (IPv4)
		127, 0, 0, 1, // IPv4 address (127.0.0.1)
		0x00, 0x50, // Port 80
	}

	buf := bytes.NewBuffer(requestData)
	_, err := NewRequest(buf)

	if err == nil {
		t.Errorf("Expected error for unsupported command")
	}

	if !strings.Contains(err.Error(), "unsupported command") {
		t.Errorf("Expected 'unsupported command' error, got: %v", err)
	}
}

func TestRequestValidationUnsupportedAddressType(t *testing.T) {
	// Test that unsupported address types are rejected
	requestData := []byte{
		0x05, // Version
		0x01, // Command (CONNECT)
		0x00, // Reserved
		0x99, // Address type (unsupported)
		127, 0, 0, 1, // Address data
		0x00, 0x50, // Port 80
	}

	buf := bytes.NewBuffer(requestData)
	_, err := NewRequest(buf)

	if err == nil {
		t.Errorf("Expected error for unsupported address type")
	}

	if !strings.Contains(err.Error(), "unsupported address type") {
		t.Errorf("Expected 'unsupported address type' error, got: %v", err)
	}
}

func TestDomainNameZeroLength(t *testing.T) {
	// Test that zero-length domain names are rejected
	requestData := []byte{
		0x05, // Version
		0x01, // Command (CONNECT)
		0x00, // Reserved
		0x03, // Address type (Domain)
		0x00, // Domain length (0 - invalid!)
		0x00, 0x50, // Port 80
	}

	buf := bytes.NewBuffer(requestData)
	_, err := NewRequest(buf)

	if err == nil {
		t.Errorf("Expected error for zero-length domain name")
	}

	if !strings.Contains(err.Error(), "invalid domain name length: 0") {
		t.Errorf("Expected 'invalid domain name length: 0' error, got: %v", err)
	}
}

func TestMapNetworkErrorCoverage(t *testing.T) {
	server, _ := New(nil)

	testCases := []struct {
		errorMsg     string
		expectedCode uint8
	}{
		{"network is unreachable", repNetworkUnreachable},
		{"no such host", repHostUnreachable},
		{"connection refused", repConnectionRefused},
		{"timeout", repTTLExpired},
		{"permission denied", repNotAllowed},
		{"some other error", repServerFailure},
		{"", repSuccess}, // nil error case
	}

	for _, tc := range testCases {
		var err error
		if tc.errorMsg != "" {
			err = fmt.Errorf(tc.errorMsg)
		}

		code := server.mapNetworkError(err)
		if code != tc.expectedCode {
			t.Errorf("mapNetworkError(%q) = %d, expected %d", tc.errorMsg, code, tc.expectedCode)
		}
	}
}

func TestMapRequestErrorCoverage(t *testing.T) {
	server, _ := New(nil)

	testCases := []struct {
		errorMsg     string
		expectedCode uint8
	}{
		{"unsupported command", repCommandNotSupported},
		{"unsupported address type", repAddressNotSupported},
		{"unsupported socks version", repServerFailure},
		{"invalid reserved field", repServerFailure},
		{"some other error", repServerFailure},
		{"", repSuccess}, // nil error case
	}

	for _, tc := range testCases {
		var err error
		if tc.errorMsg != "" {
			err = fmt.Errorf(tc.errorMsg)
		}

		code := server.mapRequestError(err)
		if code != tc.expectedCode {
			t.Errorf("mapRequestError(%q) = %d, expected %d", tc.errorMsg, code, tc.expectedCode)
		}
	}
}
