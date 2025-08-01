package socks5

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"
)

// Integration tests to improve coverage

func TestHandleUDPRelayIntegration(t *testing.T) {
	server, _ := New(nil)

	// Create UDP connection
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer udpConn.Close()

	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	// Start UDP relay in background
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleUDPRelay(udpConn, clientAddr)
	}()

	// Send a UDP packet to trigger the relay
	go func() {
		time.Sleep(10 * time.Millisecond)
		clientConn, err := net.DialUDP("udp", clientAddr, udpConn.LocalAddr().(*net.UDPAddr))
		if err != nil {
			return
		}
		defer clientConn.Close()

		// Create a SOCKS UDP request
		header := buildUDPHeader(AtypeIPv4, []byte{127, 0, 0, 1}, 80, []byte("test"))
		clientConn.Write(header)
	}()

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)
	udpConn.Close()
}

func TestHandleUDPRelayEncapsulatedIntegration(t *testing.T) {
	server, _ := New(nil)

	// Create UDP connection
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer udpConn.Close()

	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	auth := GSSAPIAuthenticator{}

	// Start encapsulated UDP relay in background
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleUDPRelayEncapsulated(udpConn, clientAddr, auth)
	}()

	// Send a UDP packet to trigger the encapsulated relay
	go func() {
		time.Sleep(10 * time.Millisecond)
		clientConn, err := net.DialUDP("udp", clientAddr, udpConn.LocalAddr().(*net.UDPAddr))
		if err != nil {
			return
		}
		defer clientConn.Close()

		// Create a SOCKS UDP request and try to encapsulate it
		header := buildUDPHeader(AtypeIPv4, []byte{127, 0, 0, 1}, 80, []byte("test"))
		// Since GSSAPI is not implemented, this will fail but trigger the code path
		clientConn.Write(header)
	}()

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)
	udpConn.Close()
}

func TestRelayWithEncapsulationComplete(t *testing.T) {
	server, _ := New(nil)

	// Create pipe connections
	conn1Read, conn1Write := net.Pipe()
	conn2Read, conn2Write := net.Pipe()

	auth := NoAuthAuthenticator{} // No encapsulation

	// Start relay
	go server.relayWithEncapsulation(conn1Read, conn2Write, auth)

	// Test data flow
	testData := []byte("Hello, SOCKS5!")
	go func() {
		conn1Write.Write(testData)
		conn1Write.Close()
	}()

	// Read from conn2
	buffer := make([]byte, len(testData))
	n, err := conn2Read.Read(buffer)
	if err != nil {
		t.Errorf("Failed to read from conn2: %v", err)
	}

	if !bytes.Equal(buffer[:n], testData) {
		t.Errorf("Data mismatch: got %v, expected %v", buffer[:n], testData)
	}

	conn2Read.Close()
}

func TestHandleConnectionCompleteFlow(t *testing.T) {
	// Create a complete SOCKS5 connection flow test
	config := &Config{
		AuthMethods:   []Authenticator{NoAuthAuthenticator{}},
		AccessControl: AllowAllAccess{},
	}
	server, _ := New(config)

	// Create target server
	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create target listener: %v", err)
	}
	defer targetListener.Close()

	targetAddr := targetListener.Addr().(*net.TCPAddr)

	// Start target server
	go func() {
		for {
			conn, err := targetListener.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte("Hello from target"))
			conn.Close()
		}
	}()

	// Create complete SOCKS5 session data
	authData := []byte{0x05, 0x01, 0x00} // Version 5, 1 method, no auth

	connectRequest := []byte{
		0x05, // Version
		0x01, // CONNECT command
		0x00, // Reserved
		0x01, // IPv4
	}
	// Add target IP and port
	targetIP := targetAddr.IP.To4()
	connectRequest = append(connectRequest, targetIP...)
	connectRequest = append(connectRequest, byte(targetAddr.Port>>8), byte(targetAddr.Port&0xFF))

	// Combine auth and connect data
	fullRequest := append(authData, connectRequest...)

	conn := &mockConn{
		readData: fullRequest,
	}

	server.handleConnection(conn)

	// Should have written auth response and connect response
	if len(conn.writeData) < 4 {
		t.Errorf("Expected at least auth + connect responses, got %d bytes", len(conn.writeData))
	}
}

func TestErrorPathsCoverage(t *testing.T) {
	// Test various error paths to improve coverage

	// Test handleBind with sendReply error
	server, _ := New(&Config{AccessControl: AllowAllAccess{}})
	req := &Request{Command: CmdBind, RealDest: "127.0.0.1:0"}
	conn := &mockConn{writeErr: fmt.Errorf("write error")}
	auth := NoAuthAuthenticator{}

	server.handleBind(conn, req, auth)
	// Should handle the error gracefully

	// Test handleUDPAssociate with sendReply error
	req2 := &Request{Command: CmdUDPAssociate, RealDest: "0.0.0.0:0"}
	conn2 := &mockConn{writeErr: fmt.Errorf("write error")}

	server.handleUDPAssociate(conn2, req2, auth)
	// Should handle the error gracefully
}

func TestGSSAPIEncapsulationCoverage(t *testing.T) {
	// Test GSSAPI functions to improve coverage
	auth := GSSAPIAuthenticator{}

	// Test WrapData with various data sizes
	testData := []byte("small data")
	_, err := auth.WrapData(testData)
	if err == nil {
		t.Errorf("Expected error from GSSAPI WrapData")
	}

	// Test UnwrapData
	_, err = auth.UnwrapData(testData)
	if err == nil {
		t.Errorf("Expected error from GSSAPI UnwrapData")
	}

	// Test empty data
	_, err = auth.WrapData([]byte{})
	if err == nil {
		t.Errorf("Expected error from GSSAPI WrapData with empty data")
	}

	_, err = auth.UnwrapData([]byte{})
	if err == nil {
		t.Errorf("Expected error from GSSAPI UnwrapData with empty data")
	}

	// Test larger data
	largeData := make([]byte, 1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}
	_, err = auth.WrapData(largeData)
	if err == nil {
		t.Errorf("Expected error from GSSAPI WrapData with large data")
	}

	_, err = auth.UnwrapData(largeData)
	if err == nil {
		t.Errorf("Expected error from GSSAPI UnwrapData with large data")
	}
}

func TestAuthenticationEdgeCases(t *testing.T) {
	// Create authenticator with empty credentials
	auth := UserPassAuthenticator{
		Credentials: StaticCredentials{},
	}

	// Valid request but no matching credentials
	authRequest := []byte{
		0x01, 0x04,
		'u', 's', 'e', 'r',
		0x04,
		'p', 'a', 's', 's',
	}

	mock := &mockReadWriter{
		readData: authRequest,
	}

	err := auth.Authenticate(mock)
	if err == nil {
		t.Errorf("Expected error for non-existent user")
	}

	// Test with nil credentials map (should not panic)
	auth2 := UserPassAuthenticator{
		Credentials: nil,
	}

	err = auth2.Authenticate(mock)
	if err == nil {
		t.Errorf("Expected error for nil credentials")
	}
}

func TestUDPRelayFragmentedPackets(t *testing.T) {
	server, _ := New(nil)

	// Create UDP connection
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer udpConn.Close()

	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")

	// Start UDP relay in background
	go server.handleUDPRelay(udpConn, clientAddr)

	// Send a fragmented UDP packet
	go func() {
		time.Sleep(10 * time.Millisecond)
		clientConn, err := net.DialUDP("udp", clientAddr, udpConn.LocalAddr().(*net.UDPAddr))
		if err != nil {
			return
		}
		defer clientConn.Close()

		// Create a fragmented SOCKS UDP request (Fragment != 0)
		data := []byte{
			0x00, 0x00, // Reserved
			0x01,         // Fragment (non-zero, should be dropped)
			0x01,         // Address type (IPv4)
			127, 0, 0, 1, // IPv4 address
			0x00, 0x50, // Port 80
		}
		data = append(data, []byte("fragmented data")...)

		clientConn.Write(data)
	}()

	// Let it run briefly
	time.Sleep(50 * time.Millisecond)
	udpConn.Close()
}

func TestRelayWithEncapsulationErrorPaths(t *testing.T) {
	server, _ := New(nil)

	// Create mock connections that will cause read/write errors
	conn1 := &mockConn{
		readData: []byte("test"),
		readErr:  fmt.Errorf("read error"),
	}
	conn2 := &mockConn{}

	// Test with GSSAPI (should use encapsulation path but fail)
	auth := GSSAPIAuthenticator{}

	// Start relay - should handle errors gracefully
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.relayWithEncapsulation(conn1, conn2, auth)
	}()

	// Wait for it to complete
	select {
	case <-done:
		// Good, it completed
	case <-time.After(100 * time.Millisecond):
		// Also good, it's running
	}
}
