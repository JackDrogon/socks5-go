package socks5

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseUDPHeaderIPv4(t *testing.T) {
	// Create UDP header with IPv4 address
	data := []byte{
		0x00, 0x00, // Reserved
		0x00,           // Fragment
		0x01,           // Address type (IPv4)
		192, 168, 1, 1, // IPv4 address
		0x00, 0x50, // Port 80
		't', 'e', 's', 't', // Data
	}

	header, err := parseUDPHeader(data)
	if err != nil {
		t.Fatalf("parseUDPHeader() returned error: %v", err)
	}

	if header.Reserved != 0x0000 {
		t.Errorf("Reserved = 0x%04X, expected 0x0000", header.Reserved)
	}
	if header.Fragment != 0x00 {
		t.Errorf("Fragment = 0x%02X, expected 0x00", header.Fragment)
	}
	if header.AddrType != atypeIPv4 {
		t.Errorf("AddrType = 0x%02X, expected 0x%02X", header.AddrType, atypeIPv4)
	}
	if header.DstPort != 80 {
		t.Errorf("DstPort = %d, expected 80", header.DstPort)
	}
	expectedData := []byte{'t', 'e', 's', 't'}
	if !bytes.Equal(header.Data, expectedData) {
		t.Errorf("Data = %v, expected %v", header.Data, expectedData)
	}

	expectedDest := "192.168.1.1:80"
	if header.getDestinationAddress() != expectedDest {
		t.Errorf("getDestinationAddress() = %s, expected %s", header.getDestinationAddress(), expectedDest)
	}
}

func TestParseUDPHeaderIPv6(t *testing.T) {
	// Create UDP header with IPv6 address
	data := []byte{
		0x00, 0x00, // Reserved
		0x00, // Fragment
		0x04, // Address type (IPv6)
		// IPv6 address ::1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x01, 0xBB, // Port 443
		'd', 'a', 't', 'a', // Data
	}

	header, err := parseUDPHeader(data)
	if err != nil {
		t.Fatalf("parseUDPHeader() returned error: %v", err)
	}

	if header.AddrType != atypeIPv6 {
		t.Errorf("AddrType = 0x%02X, expected 0x%02X", header.AddrType, atypeIPv6)
	}
	if header.DstPort != 443 {
		t.Errorf("DstPort = %d, expected 443", header.DstPort)
	}

	expectedDest := "[::1]:443"
	if header.getDestinationAddress() != expectedDest {
		t.Errorf("getDestinationAddress() = %s, expected %s", header.getDestinationAddress(), expectedDest)
	}
}

func TestParseUDPHeaderDomain(t *testing.T) {
	domain := "example.com"
	// Create UDP header with domain name
	data := []byte{
		0x00, 0x00, // Reserved
		0x00,              // Fragment
		0x03,              // Address type (Domain)
		byte(len(domain)), // Domain length
	}
	data = append(data, []byte(domain)...)
	data = append(data, 0x00, 0x50) // Port 80
	data = append(data, []byte("payload")...)

	header, err := parseUDPHeader(data)
	if err != nil {
		t.Fatalf("parseUDPHeader() returned error: %v", err)
	}

	if header.AddrType != atypeDomain {
		t.Errorf("AddrType = 0x%02X, expected 0x%02X", header.AddrType, atypeDomain)
	}
	if header.DstPort != 80 {
		t.Errorf("DstPort = %d, expected 80", header.DstPort)
	}

	expectedDest := "example.com:80"
	if header.getDestinationAddress() != expectedDest {
		t.Errorf("getDestinationAddress() = %s, expected %s", header.getDestinationAddress(), expectedDest)
	}

	expectedData := []byte("payload")
	if !bytes.Equal(header.Data, expectedData) {
		t.Errorf("Data = %v, expected %v", header.Data, expectedData)
	}
}

func TestParseUDPHeaderTooShort(t *testing.T) {
	data := []byte{0x00, 0x00} // Too short

	_, err := parseUDPHeader(data)
	if err == nil {
		t.Errorf("parseUDPHeader() should return error for short data")
	}

	expectedError := "UDP header too short"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestParseUDPHeaderUnsupportedAddrType(t *testing.T) {
	data := []byte{
		0x00, 0x00, // Reserved
		0x00,           // Fragment
		0x99,           // Invalid address type
		192, 168, 1, 1, // Data
		0x00, 0x50, // Port
	}

	_, err := parseUDPHeader(data)
	if err == nil {
		t.Errorf("parseUDPHeader() should return error for unsupported address type")
	}

	expectedError := "unsupported address type"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestParseUDPHeaderDomainTooShort(t *testing.T) {
	data := []byte{
		0x00, 0x00, // Reserved
		0x00, // Fragment
		0x03, // Address type (Domain)
		// Missing domain length
	}

	_, err := parseUDPHeader(data)
	if err == nil {
		t.Errorf("parseUDPHeader() should return error for missing domain length")
	}

	expectedError := "invalid domain length"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestParseUDPHeaderInsufficientData(t *testing.T) {
	data := []byte{
		0x00, 0x00, // Reserved
		0x00,     // Fragment
		0x01,     // Address type (IPv4)
		192, 168, // Incomplete IPv4 address
	}

	_, err := parseUDPHeader(data)
	if err == nil {
		t.Errorf("parseUDPHeader() should return error for insufficient data")
	}

	expectedError := "UDP datagram too short"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestBuildUDPHeaderIPv4(t *testing.T) {
	addr := []byte{192, 168, 1, 1}
	port := uint16(80)
	data := []byte("test data")

	packet := buildUDPHeader(atypeIPv4, addr, port, data)

	expectedHeader := []byte{
		0x00, 0x00, // Reserved
		0x00,           // Fragment
		0x01,           // Address type (IPv4)
		192, 168, 1, 1, // IPv4 address
		0x00, 0x50, // Port 80
	}
	expectedHeader = append(expectedHeader, data...)

	if !bytes.Equal(packet, expectedHeader) {
		t.Errorf("buildUDPHeader() = %v, expected %v", packet, expectedHeader)
	}
}

func TestBuildUDPHeaderIPv6(t *testing.T) {
	addr := []byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	port := uint16(443)
	data := []byte("test")

	packet := buildUDPHeader(atypeIPv6, addr, port, data)

	expectedHeader := []byte{
		0x00, 0x00, // Reserved
		0x00, // Fragment
		0x04, // Address type (IPv6)
	}
	expectedHeader = append(expectedHeader, addr...)
	expectedHeader = append(expectedHeader, 0x01, 0xBB) // Port 443
	expectedHeader = append(expectedHeader, data...)

	if !bytes.Equal(packet, expectedHeader) {
		t.Errorf("buildUDPHeader() length = %d, expected %d", len(packet), len(expectedHeader))
		t.Errorf("buildUDPHeader() = %v", packet)
		t.Errorf("expected = %v", expectedHeader)
	}
}

func TestBuildUDPHeaderDomain(t *testing.T) {
	domain := "example.com"
	addr := []byte(domain)
	port := uint16(80)
	data := []byte("payload")

	packet := buildUDPHeader(atypeDomain, addr, port, data)

	expectedHeader := []byte{
		0x00, 0x00, // Reserved
		0x00,              // Fragment
		0x03,              // Address type (Domain)
		byte(len(domain)), // Domain length
	}
	expectedHeader = append(expectedHeader, []byte(domain)...)
	expectedHeader = append(expectedHeader, 0x00, 0x50) // Port 80
	expectedHeader = append(expectedHeader, data...)

	if !bytes.Equal(packet, expectedHeader) {
		t.Errorf("buildUDPHeader() = %v, expected %v", packet, expectedHeader)
	}
}

func TestUDPHeaderGetDestinationAddress(t *testing.T) {
	testCases := []struct {
		name     string
		addrType uint8
		dstAddr  []byte
		dstPort  uint16
		expected string
	}{
		{
			"IPv4",
			atypeIPv4,
			[]byte{192, 168, 1, 1},
			80,
			"192.168.1.1:80",
		},
		{
			"IPv6",
			atypeIPv6,
			[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			443,
			"[::1]:443",
		},
		{
			"Domain",
			atypeDomain,
			[]byte("example.com"),
			8080,
			"example.com:8080",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			header := &UDPHeader{
				AddrType: tc.addrType,
				DstAddr:  tc.dstAddr,
				DstPort:  tc.dstPort,
			}

			result := header.getDestinationAddress()
			if result != tc.expected {
				t.Errorf("getDestinationAddress() = %s, expected %s", result, tc.expected)
			}
		})
	}
}

func TestUDPAssociation(t *testing.T) {
	clientAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:1234")
	assoc := &UDPAssociation{
		clientAddr: clientAddr,
		lastSeen:   time.Now(),
	}

	// Test basic fields
	if assoc.clientAddr != clientAddr {
		t.Errorf("clientAddr = %v, expected %v", assoc.clientAddr, clientAddr)
	}

	// Test mutex operations (basic check)
	assoc.mutex.Lock()
	assoc.lastSeen = time.Now()
	assoc.mutex.Unlock()

	assoc.mutex.RLock()
	_ = assoc.lastSeen
	assoc.mutex.RUnlock()
}

func TestParseUDPHeaderFragment(t *testing.T) {
	// Test with fragment field set
	data := []byte{
		0x00, 0x00, // Reserved
		0x05,           // Fragment (non-zero)
		0x01,           // Address type (IPv4)
		192, 168, 1, 1, // IPv4 address
		0x00, 0x50, // Port 80
		't', 'e', 's', 't', // Data
	}

	header, err := parseUDPHeader(data)
	if err != nil {
		t.Fatalf("parseUDPHeader() returned error: %v", err)
	}

	if header.Fragment != 0x05 {
		t.Errorf("Fragment = 0x%02X, expected 0x05", header.Fragment)
	}
}

func TestParseUDPHeaderReservedField(t *testing.T) {
	// Test with non-zero reserved field - should fail per RFC 1928
	data := []byte{
		0x12, 0x34, // Non-zero reserved field
		0x00,           // Fragment
		0x01,           // Address type (IPv4)
		192, 168, 1, 1, // IPv4 address
		0x00, 0x50, // Port 80
		'd', 'a', 't', 'a', // Data
	}

	_, err := parseUDPHeader(data)
	if err == nil {
		t.Errorf("parseUDPHeader() should return error for non-zero RSV field")
	}

	expectedError := "invalid UDP RSV field"
	if err != nil && !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestBuildUDPHeaderPortEncoding(t *testing.T) {
	testPorts := []struct {
		port     uint16
		expected []byte
	}{
		{0, []byte{0x00, 0x00}},
		{1, []byte{0x00, 0x01}},
		{80, []byte{0x00, 0x50}},
		{443, []byte{0x01, 0xBB}},
		{8080, []byte{0x1F, 0x90}},
		{65535, []byte{0xFF, 0xFF}},
	}

	for _, tc := range testPorts {
		addr := []byte{127, 0, 0, 1}
		data := []byte("test")
		packet := buildUDPHeader(atypeIPv4, addr, tc.port, data)

		// Port is at bytes 8-9 for IPv4
		portBytes := packet[8:10]
		if !bytes.Equal(portBytes, tc.expected) {
			t.Errorf("Port %d encoding = %v, expected %v", tc.port, portBytes, tc.expected)
		}
	}
}

func TestHandleUDPRelayWithEncapsulation(t *testing.T) {
	server, _ := New(nil)

	// Create UDP connection
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer udpConn.Close()

	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	auth := NoAuthAuthenticator{}

	// Test with no encapsulation
	go server.handleUDPRelayWithEncapsulation(udpConn, clientAddr, auth)
	time.Sleep(10 * time.Millisecond)
}

func TestHandleUDPRelayWithEncapsulationGSSAPI(t *testing.T) {
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

	// Test with encapsulation
	go server.handleUDPRelayWithEncapsulation(udpConn, clientAddr, auth)
	time.Sleep(10 * time.Millisecond)
}

func TestHandleUDPRelayDetailedPaths(t *testing.T) {
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

	// Test various scenarios
	go func() {
		time.Sleep(10 * time.Millisecond)
		clientConn, err := net.DialUDP("udp", clientAddr, udpConn.LocalAddr().(*net.UDPAddr))
		if err != nil {
			return
		}
		defer clientConn.Close()

		// Scenario 1: Valid UDP packet
		validHeader := buildUDPHeader(atypeIPv4, []byte{127, 0, 0, 1}, 80, []byte("test data"))
		clientConn.Write(validHeader)
		time.Sleep(5 * time.Millisecond)

		// Scenario 2: Invalid header (malformed)
		invalidHeader := []byte{0x00, 0x00, 0x00, 0x01, 127} // Too short
		clientConn.Write(invalidHeader)
		time.Sleep(5 * time.Millisecond)

		// Scenario 3: Fragmented packet (Fragment != 0)
		fragmentedHeader := []byte{
			0x00, 0x00, // Reserved
			0x01,         // Fragment (non-zero)
			0x01,         // Address type (IPv4)
			127, 0, 0, 1, // IPv4 address
			0x00, 0x50, // Port 80
		}
		fragmentedHeader = append(fragmentedHeader, []byte("fragmented")...)
		clientConn.Write(fragmentedHeader)
		time.Sleep(5 * time.Millisecond)

		// Scenario 4: Invalid destination address
		invalidDestHeader := buildUDPHeader(atypeIPv4, []byte{255, 255, 255, 255}, 80, []byte("bad dest"))
		clientConn.Write(invalidDestHeader)
		time.Sleep(5 * time.Millisecond)

		// Scenario 5: Send multiple packets to create associations
		for i := 0; i < 3; i++ {
			header := buildUDPHeader(atypeIPv4, []byte{127, 0, 0, 1}, uint16(8080+i), []byte(fmt.Sprintf("packet %d", i)))
			clientConn.Write(header)
			time.Sleep(2 * time.Millisecond)
		}
	}()

	// Let it run briefly then close
	time.Sleep(100 * time.Millisecond)
	udpConn.Close()

	// Wait for completion
	select {
	case <-done:
		// Good
	case <-time.After(1 * time.Second):
		// Timeout, but that's OK
	}
}

func TestHandleUDPRelayEncapsulatedPaths(t *testing.T) {
	server, _ := New(nil)

	// Create UDP connection
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("Failed to create UDP connection: %v", err)
	}
	defer udpConn.Close()

	clientAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:12345")
	auth := GSSAPIAuthenticator{AcceptAll: true}

	// Start encapsulated UDP relay in background
	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleUDPRelayEncapsulated(udpConn, clientAddr, auth)
	}()

	// Test encapsulated scenarios
	go func() {
		time.Sleep(10 * time.Millisecond)
		clientConn, err := net.DialUDP("udp", clientAddr, udpConn.LocalAddr().(*net.UDPAddr))
		if err != nil {
			return
		}
		defer clientConn.Close()

		// Create a proper SOCKS UDP header and encapsulate it
		udpHeader := buildUDPHeader(atypeIPv4, []byte{127, 0, 0, 1}, 80, []byte("encapsulated data"))

		// Wrap the UDP header using GSSAPI
		wrappedData, err := auth.WrapData(udpHeader)
		if err != nil {
			return
		}

		// Send the wrapped data
		clientConn.Write(wrappedData)
		time.Sleep(5 * time.Millisecond)

		// Test with invalid wrapped data
		invalidWrapped := []byte{0x00, 0x00, 0x00, 0x10} // Claims 16 bytes but no data
		clientConn.Write(invalidWrapped)
		time.Sleep(5 * time.Millisecond)

		// Test with data that fails to unwrap
		badWrapped := []byte{0xFF, 0xFF, 0xFF, 0x02, 0x01, 0x02} // Invalid length
		clientConn.Write(badWrapped)
		time.Sleep(5 * time.Millisecond)
	}()

	// Let it run briefly then close
	time.Sleep(100 * time.Millisecond)
	udpConn.Close()

	// Wait for completion
	select {
	case <-done:
		// Good
	case <-time.After(1 * time.Second):
		// Timeout, but that's OK
	}
}

func TestUDPRelayFromNonClient(t *testing.T) {
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

	// Send packet from different address (not the client)
	go func() {
		time.Sleep(10 * time.Millisecond)
		unknownAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:54321")
		unknownConn, err := net.DialUDP("udp", unknownAddr, udpConn.LocalAddr().(*net.UDPAddr))
		if err != nil {
			return
		}
		defer unknownConn.Close()

		// This should be logged as "unknown source"
		unknownConn.Write([]byte("packet from unknown source"))
		time.Sleep(10 * time.Millisecond)
	}()

	// Let it run briefly then close
	time.Sleep(50 * time.Millisecond)
	udpConn.Close()

	// Wait for completion
	select {
	case <-done:
		// Good
	case <-time.After(1 * time.Second):
		// Timeout, but that's OK
	}
}

func TestUDPHeaderRFCCompliance(t *testing.T) {
	// RFC 1928: UDP Request Header format validation
	// +----+------+------+----------+----------+----------+
	// |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
	// +----+------+------+----------+----------+----------+
	// | 2  |  1   |  1   | Variable |    2     | Variable |
	// +----+------+------+----------+----------+----------+

	testCases := []struct {
		name        string
		headerData  []byte
		shouldError bool
		errorMsg    string
	}{
		{
			name: "Valid header with RSV=0x0000",
			headerData: []byte{
				0x00, 0x00, // RSV must be 0x0000
				0x00,         // FRAG
				0x01,         // ATYP (IPv4)
				127, 0, 0, 1, // DST.ADDR
				0x00, 0x50, // DST.PORT (80)
				't', 'e', 's', 't', // DATA
			},
			shouldError: false,
		},
		{
			name: "Invalid RSV field (non-zero)",
			headerData: []byte{
				0x00, 0x01, // RSV should be 0x0000, but is 0x0001
				0x00,         // FRAG
				0x01,         // ATYP (IPv4)
				127, 0, 0, 1, // DST.ADDR
				0x00, 0x50, // DST.PORT (80)
				't', 'e', 's', 't', // DATA
			},
			shouldError: true,
			errorMsg:    "invalid UDP RSV field",
		},
		{
			name: "Test fragmentation field",
			headerData: []byte{
				0x00, 0x00, // RSV
				0x01,         // FRAG (fragment)
				0x01,         // ATYP (IPv4)
				127, 0, 0, 1, // DST.ADDR
				0x00, 0x50, // DST.PORT (80)
				't', 'e', 's', 't', // DATA
			},
			shouldError: false,
		},
		{
			name: "Invalid address type",
			headerData: []byte{
				0x00, 0x00, // RSV
				0x00,         // FRAG
				0x99,         // ATYP (invalid)
				127, 0, 0, 1, // DST.ADDR
				0x00, 0x50, // DST.PORT (80)
			},
			shouldError: true,
			errorMsg:    "unsupported address type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			header, err := parseUDPHeader(tc.headerData)

			if tc.shouldError {
				if err == nil {
					t.Errorf("Expected error for %s", tc.name)
				} else if !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tc.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for %s: %v", tc.name, err)
				} else {
					// Verify header parsing
					if len(tc.headerData) >= 4 {
						expectedRSV := uint16(tc.headerData[0])<<8 | uint16(tc.headerData[1])
						if header.Reserved != expectedRSV {
							t.Errorf("RSV mismatch: got 0x%04X, expected 0x%04X", header.Reserved, expectedRSV)
						}

						expectedFRAG := tc.headerData[2]
						if header.Fragment != expectedFRAG {
							t.Errorf("FRAG mismatch: got 0x%02X, expected 0x%02X", header.Fragment, expectedFRAG)
						}

						expectedATYP := tc.headerData[3]
						if header.AddrType != expectedATYP {
							t.Errorf("ATYP mismatch: got 0x%02X, expected 0x%02X", header.AddrType, expectedATYP)
						}
					}
				}
			}
		})
	}
}

func TestUDPFragmentationRFCCompliance(t *testing.T) {
	// RFC 1928: Fragment field handling
	// 0x00 = standalone datagram
	// Non-zero = fragment sequence

	testCases := []struct {
		name          string
		fragment      byte
		expectHandled bool
	}{
		{"Standalone datagram", 0x00, true},
		{"Fragment 1", 0x01, false}, // Should be dropped in current implementation
		{"Fragment 127", 0x7F, false},
		{"End fragment marker", 0x80, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			headerData := []byte{
				0x00, 0x00, // RSV
				tc.fragment,  // FRAG
				0x01,         // ATYP (IPv4)
				127, 0, 0, 1, // DST.ADDR
				0x00, 0x50, // DST.PORT (80)
				't', 'e', 's', 't', // DATA
			}

			header, err := parseUDPHeader(headerData)
			if err != nil {
				t.Fatalf("parseUDPHeader() failed: %v", err)
			}

			if header.Fragment != tc.fragment {
				t.Errorf("Fragment field mismatch: got 0x%02X, expected 0x%02X", header.Fragment, tc.fragment)
			}

			// Test that non-zero fragments are properly identified
			isStandalone := header.Fragment == 0x00
			if isStandalone != tc.expectHandled {
				t.Errorf("Fragment handling expectation mismatch for 0x%02X", tc.fragment)
			}
		})
	}
}

func TestUDPAddressTypesRFCCompliance(t *testing.T) {
	// Test all RFC 1928 address types in UDP context
	testCases := []struct {
		name         string
		addrType     byte
		addrData     []byte
		valid        bool
		expectedAddr string
	}{
		{
			name:         "IPv4 address",
			addrType:     atypeIPv4,
			addrData:     []byte{192, 168, 1, 1, 0x00, 0x50},
			valid:        true,
			expectedAddr: "192.168.1.1:80",
		},
		{
			name:         "IPv6 address",
			addrType:     atypeIPv6,
			addrData:     append([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, []byte{0x01, 0xBB}...),
			valid:        true,
			expectedAddr: "[::1]:443",
		},
		{
			name:         "Domain name",
			addrType:     atypeDomain,
			addrData:     append([]byte{0x0B}, append([]byte("example.com"), []byte{0x00, 0x50}...)...),
			valid:        true,
			expectedAddr: "example.com:80",
		},
		{
			name:     "Invalid address type 0x00",
			addrType: 0x00,
			addrData: []byte{192, 168, 1, 1, 0x00, 0x50},
			valid:    false,
		},
		{
			name:     "Invalid address type 0x02",
			addrType: 0x02,
			addrData: []byte{192, 168, 1, 1, 0x00, 0x50},
			valid:    false,
		},
		{
			name:     "Invalid address type 0x05",
			addrType: 0x05,
			addrData: []byte{192, 168, 1, 1, 0x00, 0x50},
			valid:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			headerData := []byte{0x00, 0x00, 0x00, tc.addrType}
			headerData = append(headerData, tc.addrData...)

			header, err := parseUDPHeader(headerData)

			if tc.valid {
				if err != nil {
					t.Errorf("Unexpected error for valid address type 0x%02X: %v", tc.addrType, err)
				} else {
					if header.AddrType != tc.addrType {
						t.Errorf("Address type mismatch: got 0x%02X, expected 0x%02X", header.AddrType, tc.addrType)
					}
					actualAddr := header.getDestinationAddress()
					if actualAddr != tc.expectedAddr {
						t.Errorf("Address mismatch: got %s, expected %s", actualAddr, tc.expectedAddr)
					}
				}
			} else {
				if err == nil {
					t.Errorf("Expected error for invalid address type 0x%02X", tc.addrType)
				}
			}
		})
	}
}

func TestUDPRSVFieldRFCCompliance(t *testing.T) {
	// RFC 1928: RSV field MUST be X'0000' - comprehensive validation
	testCases := []struct {
		name        string
		rsvBytes    []byte
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "Valid RSV=0x0000",
			rsvBytes:    []byte{0x00, 0x00},
			shouldError: false,
		},
		{
			name:        "Invalid RSV=0x0001",
			rsvBytes:    []byte{0x00, 0x01},
			shouldError: true,
			errorMsg:    "invalid UDP RSV field",
		},
		{
			name:        "Invalid RSV=0x0100",
			rsvBytes:    []byte{0x01, 0x00},
			shouldError: true,
			errorMsg:    "invalid UDP RSV field",
		},
		{
			name:        "Invalid RSV=0xFFFF",
			rsvBytes:    []byte{0xFF, 0xFF},
			shouldError: true,
			errorMsg:    "invalid UDP RSV field",
		},
		{
			name:        "Invalid RSV=0x1234",
			rsvBytes:    []byte{0x12, 0x34},
			shouldError: true,
			errorMsg:    "invalid UDP RSV field",
		},
		{
			name:        "Invalid RSV=0x8000",
			rsvBytes:    []byte{0x80, 0x00},
			shouldError: true,
			errorMsg:    "invalid UDP RSV field",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			headerData := append(tc.rsvBytes, []byte{
				0x00,         // FRAG
				0x01,         // ATYP (IPv4)
				127, 0, 0, 1, // DST.ADDR
				0x00, 0x50, // DST.PORT (80)
				't', 'e', 's', 't', // DATA
			}...)

			_, err := parseUDPHeader(headerData)

			if tc.shouldError {
				if err == nil {
					t.Errorf("Expected error for RSV=0x%02X%02X", tc.rsvBytes[0], tc.rsvBytes[1])
				} else if !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tc.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for valid RSV=0x%02X%02X: %v", tc.rsvBytes[0], tc.rsvBytes[1], err)
				}
			}
		})
	}
}
