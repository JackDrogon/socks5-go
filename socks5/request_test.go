package socks5

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestNewRequestValidConnect(t *testing.T) {
	// Create a valid CONNECT request for IPv4
	requestData := []byte{
		0x05,           // Version
		0x01,           // Command (CONNECT)
		0x00,           // Reserved
		0x01,           // Address type (IPv4)
		192, 168, 1, 1, // IPv4 address
		0x00, 0x50, // Port 80
	}

	buf := bytes.NewBuffer(requestData)
	req, err := NewRequest(buf)
	if err != nil {
		t.Fatalf("NewRequest() returned error: %v", err)
	}

	if req.Version != socks5Version {
		t.Errorf("Version = %d, expected %d", req.Version, socks5Version)
	}
	if req.Command != cmdConnect {
		t.Errorf("Command = %d, expected %d", req.Command, cmdConnect)
	}
	if req.Reserved != 0x00 {
		t.Errorf("Reserved = %d, expected 0", req.Reserved)
	}
	if req.AddrType != atypeIPv4 {
		t.Errorf("AddrType = %d, expected %d", req.AddrType, atypeIPv4)
	}
	if req.DestPort != 80 {
		t.Errorf("DestPort = %d, expected 80", req.DestPort)
	}
	expectedAddr := "192.168.1.1:80"
	if req.RealDest != expectedAddr {
		t.Errorf("RealDest = %s, expected %s", req.RealDest, expectedAddr)
	}
}

func TestNewRequestValidBind(t *testing.T) {
	// Create a valid BIND request for IPv6
	requestData := []byte{
		0x05, // Version
		0x02, // Command (BIND)
		0x00, // Reserved
		0x04, // Address type (IPv6)
		// IPv6 address ::1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x01, 0xBB, // Port 443
	}

	buf := bytes.NewBuffer(requestData)
	req, err := NewRequest(buf)
	if err != nil {
		t.Fatalf("NewRequest() returned error: %v", err)
	}

	if req.Command != cmdBind {
		t.Errorf("Command = %d, expected %d", req.Command, cmdBind)
	}
	if req.AddrType != atypeIPv6 {
		t.Errorf("AddrType = %d, expected %d", req.AddrType, atypeIPv6)
	}
	if req.DestPort != 443 {
		t.Errorf("DestPort = %d, expected 443", req.DestPort)
	}
	expectedAddr := "[::1]:443"
	if req.RealDest != expectedAddr {
		t.Errorf("RealDest = %s, expected %s", req.RealDest, expectedAddr)
	}
}

func TestNewRequestValidUDPAssociate(t *testing.T) {
	// Create a valid UDP ASSOCIATE request for domain
	domain := "example.com"
	requestData := []byte{
		0x05,              // Version
		0x03,              // Command (UDP ASSOCIATE)
		0x00,              // Reserved
		0x03,              // Address type (Domain)
		byte(len(domain)), // Domain length
	}
	requestData = append(requestData, []byte(domain)...)
	requestData = append(requestData, 0x00, 0x50) // Port 80

	buf := bytes.NewBuffer(requestData)
	req, err := NewRequest(buf)
	if err != nil {
		t.Fatalf("NewRequest() returned error: %v", err)
	}

	if req.Command != cmdUDPAssociate {
		t.Errorf("Command = %d, expected %d", req.Command, cmdUDPAssociate)
	}
	if req.AddrType != atypeDomain {
		t.Errorf("AddrType = %d, expected %d", req.AddrType, atypeDomain)
	}
	if req.DestPort != 80 {
		t.Errorf("DestPort = %d, expected 80", req.DestPort)
	}
	expectedAddr := "example.com:80"
	if req.RealDest != expectedAddr {
		t.Errorf("RealDest = %s, expected %s", req.RealDest, expectedAddr)
	}
}

func TestNewRequestInvalidVersion(t *testing.T) {
	requestData := []byte{
		0x04,           // Wrong version
		0x01,           // Command
		0x00,           // Reserved
		0x01,           // Address type
		192, 168, 1, 1, // IPv4
		0x00, 0x50, // Port
	}

	buf := bytes.NewBuffer(requestData)
	_, err := NewRequest(buf)
	if err == nil {
		t.Errorf("NewRequest() should return error for invalid version")
	}

	expectedError := "unsupported SOCKS version"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestNewRequestInvalidReserved(t *testing.T) {
	requestData := []byte{
		0x05,           // Version
		0x01,           // Command
		0x01,           // Invalid reserved field (should be 0x00)
		0x01,           // Address type
		192, 168, 1, 1, // IPv4
		0x00, 0x50, // Port
	}

	buf := bytes.NewBuffer(requestData)
	_, err := NewRequest(buf)
	if err == nil {
		t.Errorf("NewRequest() should return error for invalid reserved field")
	}

	expectedError := "invalid reserved field"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestNewRequestInvalidCommand(t *testing.T) {
	requestData := []byte{
		0x05,           // Version
		0x99,           // Invalid command
		0x00,           // Reserved
		0x01,           // Address type
		192, 168, 1, 1, // IPv4
		0x00, 0x50, // Port
	}

	buf := bytes.NewBuffer(requestData)
	_, err := NewRequest(buf)
	if err == nil {
		t.Errorf("NewRequest() should return error for invalid command")
	}

	expectedError := "unsupported command"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestNewRequestShortHeader(t *testing.T) {
	requestData := []byte{0x05, 0x01} // Too short

	buf := bytes.NewBuffer(requestData)
	_, err := NewRequest(buf)
	if err == nil {
		t.Errorf("NewRequest() should return error for short header")
	}
}

func TestReadAddrSpecIPv4(t *testing.T) {
	addrData := []byte{
		192, 168, 1, 1, // IPv4 address
		0x00, 0x50, // Port 80
	}

	buf := bytes.NewBuffer(addrData)
	spec, err := readAddrSpec(buf, atypeIPv4)
	if err != nil {
		t.Fatalf("readAddrSpec() returned error: %v", err)
	}

	if len(spec.IP) != 4 {
		t.Errorf("IPv4 address length = %d, expected 4", len(spec.IP))
	}
	if spec.Port != 80 {
		t.Errorf("Port = %d, expected 80", spec.Port)
	}
	expectedAddr := "192.168.1.1:80"
	if spec.Address != expectedAddr {
		t.Errorf("Address = %s, expected %s", spec.Address, expectedAddr)
	}
}

func TestReadAddrSpecIPv6(t *testing.T) {
	addrData := []byte{
		// IPv6 address ::1
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x01, 0xBB, // Port 443
	}

	buf := bytes.NewBuffer(addrData)
	spec, err := readAddrSpec(buf, atypeIPv6)
	if err != nil {
		t.Fatalf("readAddrSpec() returned error: %v", err)
	}

	if len(spec.IP) != 16 {
		t.Errorf("IPv6 address length = %d, expected 16", len(spec.IP))
	}
	if spec.Port != 443 {
		t.Errorf("Port = %d, expected 443", spec.Port)
	}
	expectedAddr := "[::1]:443"
	if spec.Address != expectedAddr {
		t.Errorf("Address = %s, expected %s", spec.Address, expectedAddr)
	}
}

func TestReadAddrSpecDomain(t *testing.T) {
	domain := "example.com"
	addrData := []byte{byte(len(domain))}
	addrData = append(addrData, []byte(domain)...)
	addrData = append(addrData, 0x00, 0x50) // Port 80

	buf := bytes.NewBuffer(addrData)
	spec, err := readAddrSpec(buf, atypeDomain)
	if err != nil {
		t.Fatalf("readAddrSpec() returned error: %v", err)
	}

	if len(spec.IP) != len(domain) {
		t.Errorf("Domain length = %d, expected %d", len(spec.IP), len(domain))
	}
	if spec.Port != 80 {
		t.Errorf("Port = %d, expected 80", spec.Port)
	}
	expectedAddr := "example.com:80"
	if spec.Address != expectedAddr {
		t.Errorf("Address = %s, expected %s", spec.Address, expectedAddr)
	}
}

func TestReadAddrSpecDomainZeroLength(t *testing.T) {
	addrData := []byte{
		0x00,       // Zero domain length (invalid)
		0x00, 0x50, // Port 80
	}

	buf := bytes.NewBuffer(addrData)
	_, err := readAddrSpec(buf, atypeDomain)
	if err == nil {
		t.Errorf("readAddrSpec() should return error for zero domain length")
	}

	expectedError := "invalid domain name length"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestReadAddrSpecUnsupportedType(t *testing.T) {
	addrData := []byte{0x00, 0x50} // Port only

	buf := bytes.NewBuffer(addrData)
	_, err := readAddrSpec(buf, 0x99) // Invalid address type
	if err == nil {
		t.Errorf("readAddrSpec() should return error for unsupported address type")
	}

	expectedError := "unsupported address type"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestReadAddrSpecShortIPv4(t *testing.T) {
	addrData := []byte{192, 168} // Too short for IPv4

	buf := bytes.NewBuffer(addrData)
	_, err := readAddrSpec(buf, atypeIPv4)
	if err == nil {
		t.Errorf("readAddrSpec() should return error for short IPv4 address")
	}
}

func TestReadAddrSpecShortIPv6(t *testing.T) {
	addrData := []byte{0x00, 0x00, 0x00, 0x00} // Too short for IPv6

	buf := bytes.NewBuffer(addrData)
	_, err := readAddrSpec(buf, atypeIPv6)
	if err == nil {
		t.Errorf("readAddrSpec() should return error for short IPv6 address")
	}
}

func TestReadAddrSpecShortDomain(t *testing.T) {
	addrData := []byte{0x05, 't', 'e', 's'} // Domain length 5, but only 3 chars

	buf := bytes.NewBuffer(addrData)
	_, err := readAddrSpec(buf, atypeDomain)
	if err == nil {
		t.Errorf("readAddrSpec() should return error for short domain")
	}
}

func TestReadAddrSpecShortPort(t *testing.T) {
	addrData := []byte{
		192, 168, 1, 1, // IPv4 address
		0x00, // Only 1 byte of port
	}

	buf := bytes.NewBuffer(addrData)
	_, err := readAddrSpec(buf, atypeIPv4)
	if err == nil {
		t.Errorf("readAddrSpec() should return error for short port")
	}
}

func TestReadAddrSpecNoDomainLength(t *testing.T) {
	addrData := []byte{} // Empty buffer

	buf := bytes.NewBuffer(addrData)
	_, err := readAddrSpec(buf, atypeDomain)
	if err == nil {
		t.Errorf("readAddrSpec() should return error for missing domain length")
	}
}

// Test edge cases with mock reader that returns errors
type errorReader struct {
	data []byte
	pos  int
	err  error
}

func (r *errorReader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func (r *errorReader) Write(p []byte) (int, error) {
	return len(p), nil
}

func TestNewRequestReadError(t *testing.T) {
	reader := &errorReader{
		err: io.ErrUnexpectedEOF,
	}

	_, err := NewRequest(reader)
	if err == nil {
		t.Errorf("NewRequest() should return error when reader fails")
	}
}

func TestNewRequestRFCReservedFieldValidation(t *testing.T) {
	// RFC 1928: RSV field MUST be X'00'
	testCases := []struct {
		name         string
		reservedByte byte
		shouldError  bool
	}{
		{"Valid RSV=0x00", 0x00, false},
		{"Invalid RSV=0x01", 0x01, true},
		{"Invalid RSV=0xFF", 0xFF, true},
		{"Invalid RSV=0x80", 0x80, true},
		{"Invalid RSV=0x7F", 0x7F, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte{
				0x05,            // Version
				0x01,            // Command (CONNECT)
				tc.reservedByte, // Reserved field - testing different values
				0x01,            // Address type (IPv4)
				127, 0, 0, 1,    // IP address
				0x00, 0x50, // Port 80
			}

			buf := bytes.NewBuffer(data)
			_, err := NewRequest(buf)

			if tc.shouldError {
				if err == nil {
					t.Errorf("Expected error for RSV=0x%02X", tc.reservedByte)
				} else if !strings.Contains(err.Error(), "invalid reserved field") {
					t.Errorf("Expected 'invalid reserved field' error, got: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for RSV=0x%02X: %v", tc.reservedByte, err)
				}
			}
		})
	}
}

func TestAllCommandTypesRFCCompliance(t *testing.T) {
	// Test all valid command types per RFC 1928
	testCases := []struct {
		name    string
		command byte
		valid   bool
	}{
		{"CONNECT", cmdConnect, true},
		{"BIND", cmdBind, true},
		{"UDP_ASSOCIATE", cmdUDPAssociate, true},
		{"Invalid_0x00", 0x00, false},
		{"Invalid_0x04", 0x04, false},
		{"Invalid_0xFF", 0xFF, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte{
				0x05,         // Version
				tc.command,   // Command
				0x00,         // Reserved
				0x01,         // Address type (IPv4)
				127, 0, 0, 1, // IP address
				0x00, 0x50, // Port 80
			}

			buf := bytes.NewBuffer(data)
			req, err := NewRequest(buf)

			if tc.valid {
				if err != nil {
					t.Errorf("Unexpected error for valid command 0x%02X: %v", tc.command, err)
				} else if req.Command != tc.command {
					t.Errorf("Command mismatch: got 0x%02X, expected 0x%02X", req.Command, tc.command)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error for invalid command 0x%02X", tc.command)
				} else if !strings.Contains(err.Error(), "unsupported command") {
					t.Errorf("Expected 'unsupported command' error, got: %v", err)
				}
			}
		})
	}
}

func TestAllAddressTypesRFCCompliance(t *testing.T) {
	// Test all valid address types per RFC 1928
	testCases := []struct {
		name         string
		addrType     byte
		addrData     []byte
		port         []byte
		valid        bool
		expectedAddr string
	}{
		{
			name:         "IPv4",
			addrType:     atypeIPv4,
			addrData:     []byte{192, 168, 1, 1},
			port:         []byte{0x00, 0x50},
			valid:        true,
			expectedAddr: "192.168.1.1:80",
		},
		{
			name:         "IPv6",
			addrType:     atypeIPv6,
			addrData:     []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			port:         []byte{0x01, 0xBB},
			valid:        true,
			expectedAddr: "[::1]:443",
		},
		{
			name:         "Domain",
			addrType:     atypeDomain,
			addrData:     append([]byte{0x0B}, []byte("example.com")...),
			port:         []byte{0x00, 0x50},
			valid:        true,
			expectedAddr: "example.com:80",
		},
		{
			name:     "Invalid_0x00",
			addrType: 0x00,
			addrData: []byte{192, 168, 1, 1},
			port:     []byte{0x00, 0x50},
			valid:    false,
		},
		{
			name:     "Invalid_0x02",
			addrType: 0x02,
			addrData: []byte{192, 168, 1, 1},
			port:     []byte{0x00, 0x50},
			valid:    false,
		},
		{
			name:     "Invalid_0x05",
			addrType: 0x05,
			addrData: []byte{192, 168, 1, 1},
			port:     []byte{0x00, 0x50},
			valid:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte{
				0x05,        // Version
				0x01,        // Command (CONNECT)
				0x00,        // Reserved
				tc.addrType, // Address type
			}
			data = append(data, tc.addrData...)
			data = append(data, tc.port...)

			buf := bytes.NewBuffer(data)
			req, err := NewRequest(buf)

			if tc.valid {
				if err != nil {
					t.Errorf("Unexpected error for valid address type 0x%02X: %v", tc.addrType, err)
				} else {
					if req.AddrType != tc.addrType {
						t.Errorf("Address type mismatch: got 0x%02X, expected 0x%02X", req.AddrType, tc.addrType)
					}
					if req.RealDest != tc.expectedAddr {
						t.Errorf("Address mismatch: got %s, expected %s", req.RealDest, tc.expectedAddr)
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

func TestDomainNameBoundaryConditionsRFCCompliance(t *testing.T) {
	// RFC 1928: Test domain name length boundary conditions
	testCases := []struct {
		name        string
		domainLen   byte
		domain      []byte
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "Valid 1-byte domain",
			domainLen:   1,
			domain:      []byte("a"),
			shouldError: false,
		},
		{
			name:        "Valid max length domain (255 bytes)",
			domainLen:   255,
			domain:      make([]byte, 255), // Fill with 'a'
			shouldError: false,
		},
		{
			name:        "Invalid zero-length domain",
			domainLen:   0,
			domain:      []byte{},
			shouldError: true,
			errorMsg:    "invalid domain name length",
		},
		{
			name:        "Length mismatch - claimed longer than actual",
			domainLen:   10,
			domain:      []byte("short"),
			shouldError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Fill the max length domain with 'a' characters
			if len(tc.domain) == 255 {
				for i := range tc.domain {
					tc.domain[i] = 'a'
				}
			}

			data := []byte{
				0x05,         // Version
				0x01,         // Command (CONNECT)
				0x00,         // Reserved
				atypeDomain,  // Address type (Domain)
				tc.domainLen, // Domain length
			}
			data = append(data, tc.domain...)
			data = append(data, 0x00, 0x50) // Port 80

			buf := bytes.NewBuffer(data)
			_, err := NewRequest(buf)

			if tc.shouldError {
				if err == nil {
					t.Errorf("Expected error for domain length test: %s", tc.name)
				} else if tc.errorMsg != "" && !strings.Contains(err.Error(), tc.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tc.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for valid domain test '%s': %v", tc.name, err)
				}
			}
		})
	}
}
