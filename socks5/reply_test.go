package socks5

import (
	"bytes"
	"fmt"
	"net"
	"testing"
)

func TestSendReplyWithTCPAddr(t *testing.T) {
	var buf bytes.Buffer

	// Test with IPv4 TCP address
	tcpAddr, _ := net.ResolveTCPAddr("tcp", "192.168.1.1:8080")
	err := sendReply(&buf, repSuccess, tcpAddr)
	if err != nil {
		t.Fatalf("sendReply() returned error: %v", err)
	}

	reply := buf.Bytes()
	expectedReply := []byte{
		0x05,           // Version
		0x00,           // Success
		0x00,           // Reserved
		0x01,           // IPv4 address type
		192, 168, 1, 1, // IPv4 address
		0x1F, 0x90, // Port 8080
	}

	if !bytes.Equal(reply, expectedReply) {
		t.Errorf("Reply = %v, expected %v", reply, expectedReply)
	}
}

func TestSendReplyWithTCPAddrIPv6(t *testing.T) {
	var buf bytes.Buffer

	// Test with IPv6 TCP address
	tcpAddr, _ := net.ResolveTCPAddr("tcp", "[::1]:8080")
	err := sendReply(&buf, repSuccess, tcpAddr)
	if err != nil {
		t.Fatalf("sendReply() returned error: %v", err)
	}

	reply := buf.Bytes()
	expected := []byte{
		0x05, // Version
		0x00, // Success
		0x00, // Reserved
		0x04, // IPv6 address type
		// IPv6 address ::1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x1F, 0x90, // Port 8080
	}

	if !bytes.Equal(reply, expected) {
		t.Errorf("Reply length = %d, expected %d", len(reply), len(expected))
		t.Errorf("Reply = %v", reply)
		t.Errorf("Expected = %v", expected)
	}
}

func TestSendReplyWithUDPAddr(t *testing.T) {
	var buf bytes.Buffer

	// Test with IPv4 UDP address
	udpAddr, _ := net.ResolveUDPAddr("udp", "10.0.0.1:53")
	err := sendReply(&buf, repSuccess, udpAddr)
	if err != nil {
		t.Fatalf("sendReply() returned error: %v", err)
	}

	reply := buf.Bytes()
	expectedReply := []byte{
		0x05,        // Version
		0x00,        // Success
		0x00,        // Reserved
		0x01,        // IPv4 address type
		10, 0, 0, 1, // IPv4 address
		0x00, 0x35, // Port 53
	}

	if !bytes.Equal(reply, expectedReply) {
		t.Errorf("Reply = %v, expected %v", reply, expectedReply)
	}
}

func TestSendReplyWithUDPAddrIPv6(t *testing.T) {
	var buf bytes.Buffer

	// Test with IPv6 UDP address
	udpAddr, _ := net.ResolveUDPAddr("udp", "[::1]:53")
	err := sendReply(&buf, repSuccess, udpAddr)
	if err != nil {
		t.Fatalf("sendReply() returned error: %v", err)
	}

	reply := buf.Bytes()
	expected := []byte{
		0x05, // Version
		0x00, // Success
		0x00, // Reserved
		0x04, // IPv6 address type
		// IPv6 address ::1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x35, // Port 53
	}

	if !bytes.Equal(reply, expected) {
		t.Errorf("Reply = %v, expected %v", reply, expected)
	}
}

func TestSendReplyWithNilAddr(t *testing.T) {
	var buf bytes.Buffer

	err := sendReply(&buf, repServerFailure, nil)
	if err != nil {
		t.Fatalf("sendReply() returned error: %v", err)
	}

	reply := buf.Bytes()
	expectedReply := []byte{
		0x05,       // Version
		0x01,       // Server failure
		0x00,       // Reserved
		0x01,       // IPv4 address type (default)
		0, 0, 0, 0, // Zero IPv4 address
		0x00, 0x00, // Zero port
	}

	if !bytes.Equal(reply, expectedReply) {
		t.Errorf("Reply = %v, expected %v", reply, expectedReply)
	}
}

func TestSendReplyAllReplyCodes(t *testing.T) {
	testCases := []struct {
		name     string
		repCode  uint8
		expected uint8
	}{
		{"Success", repSuccess, 0x00},
		{"Server Failure", repServerFailure, 0x01},
		{"Not Allowed", repNotAllowed, 0x02},
		{"Network Unreachable", repNetworkUnreachable, 0x03},
		{"Host Unreachable", repHostUnreachable, 0x04},
		{"Connection Refused", repConnectionRefused, 0x05},
		{"TTL Expired", repTTLExpired, 0x06},
		{"Command Not Supported", repCommandNotSupported, 0x07},
		{"Address Not Supported", repAddressNotSupported, 0x08},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tcpAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:1080")

			err := sendReply(&buf, tc.repCode, tcpAddr)
			if err != nil {
				t.Fatalf("sendReply() returned error: %v", err)
			}

			reply := buf.Bytes()
			if len(reply) < 2 {
				t.Fatalf("Reply too short: %d bytes", len(reply))
			}

			if reply[0] != socks5Version {
				t.Errorf("Version = 0x%02X, expected 0x%02X", reply[0], socks5Version)
			}
			if reply[1] != tc.expected {
				t.Errorf("Reply code = 0x%02X, expected 0x%02X", reply[1], tc.expected)
			}
			if reply[2] != 0x00 {
				t.Errorf("Reserved field = 0x%02X, expected 0x00", reply[2])
			}
		})
	}
}

// unsupportedAddr is a mock address type that's not supported
type unsupportedAddr struct{}

func (u unsupportedAddr) Network() string { return "unknown" }
func (u unsupportedAddr) String() string  { return "unknown:0" }

func TestSendReplyUnsupportedAddrType(t *testing.T) {
	var buf bytes.Buffer

	addr := unsupportedAddr{}
	err := sendReply(&buf, repSuccess, addr)
	if err == nil {
		t.Errorf("sendReply() should return error for unsupported address type")
	}

	if err.Error() != "unsupported address type: socks5.unsupportedAddr" {
		t.Errorf("Expected error about unsupported address type, got: %s", err.Error())
	}
}

func TestSendReplyPortEncoding(t *testing.T) {
	testPorts := []struct {
		port     int
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
		t.Run(fmt.Sprintf("Port %d", tc.port), func(t *testing.T) {
			var buf bytes.Buffer
			tcpAddr, _ := net.ResolveTCPAddr("tcp", fmt.Sprintf("127.0.0.1:%d", tc.port))
			tcpAddr.Port = tc.port // Set port directly

			err := sendReply(&buf, repSuccess, tcpAddr)
			if err != nil {
				t.Fatalf("sendReply() returned error: %v", err)
			}

			reply := buf.Bytes()
			if len(reply) < 8 {
				t.Fatalf("Reply too short: %d bytes", len(reply))
			}

			portBytes := reply[len(reply)-2:]
			if !bytes.Equal(portBytes, tc.expected) {
				t.Errorf("Port encoding = %v, expected %v", portBytes, tc.expected)
			}
		})
	}
}

func TestSendReplyIPv4Localhost(t *testing.T) {
	var buf bytes.Buffer
	tcpAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:1080")

	err := sendReply(&buf, repSuccess, tcpAddr)
	if err != nil {
		t.Fatalf("sendReply() returned error: %v", err)
	}

	reply := buf.Bytes()
	expectedAddr := []byte{127, 0, 0, 1}
	actualAddr := reply[4:8]

	if !bytes.Equal(actualAddr, expectedAddr) {
		t.Errorf("IPv4 address = %v, expected %v", actualAddr, expectedAddr)
	}
}

// Test writer that returns error
type errorWriter struct {
	shouldError bool
}

func (w *errorWriter) Write(p []byte) (int, error) {
	if w.shouldError {
		return 0, net.ErrWriteToConnected
	}
	return len(p), nil
}

func TestSendReplyWriteError(t *testing.T) {
	writer := &errorWriter{shouldError: true}
	tcpAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:1080")

	err := sendReply(writer, repSuccess, tcpAddr)
	if err == nil {
		t.Errorf("sendReply() should return error when writer fails")
	}
}
