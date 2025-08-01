package socks5

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

func TestNoAuthAuthenticator(t *testing.T) {
	auth := NoAuthAuthenticator{}

	// Test GetCode
	if auth.GetCode() != authMethodNoAuth {
		t.Errorf("NoAuthAuthenticator.GetCode() = %d, expected %d", auth.GetCode(), authMethodNoAuth)
	}

	// Test Authenticate
	var buf bytes.Buffer
	err := auth.Authenticate(&buf)
	if err != nil {
		t.Errorf("NoAuthAuthenticator.Authenticate() returned error: %v", err)
	}

	// Test SupportsEncapsulation
	if auth.SupportsEncapsulation() {
		t.Errorf("NoAuthAuthenticator.SupportsEncapsulation() = true, expected false")
	}

	// Test WrapData
	testData := []byte("test data")
	wrapped, err := auth.WrapData(testData)
	if err != nil {
		t.Errorf("NoAuthAuthenticator.WrapData() returned error: %v", err)
	}
	if !bytes.Equal(wrapped, testData) {
		t.Errorf("NoAuthAuthenticator.WrapData() = %v, expected %v", wrapped, testData)
	}

	// Test UnwrapData
	unwrapped, err := auth.UnwrapData(testData)
	if err != nil {
		t.Errorf("NoAuthAuthenticator.UnwrapData() returned error: %v", err)
	}
	if !bytes.Equal(unwrapped, testData) {
		t.Errorf("NoAuthAuthenticator.UnwrapData() = %v, expected %v", unwrapped, testData)
	}
}

func TestUserPassAuthenticator(t *testing.T) {
	auth := UserPassAuthenticator{
		Credentials: StaticCredentials{
			"testuser": "testpass",
		},
	}

	// Test GetCode
	if auth.GetCode() != authMethodUserPass {
		t.Errorf("UserPassAuthenticator.GetCode() = %d, expected %d", auth.GetCode(), authMethodUserPass)
	}

	// Test SupportsEncapsulation
	if auth.SupportsEncapsulation() {
		t.Errorf("UserPassAuthenticator.SupportsEncapsulation() = true, expected false")
	}

	// Test WrapData
	testData := []byte("test data")
	wrapped, err := auth.WrapData(testData)
	if err != nil {
		t.Errorf("UserPassAuthenticator.WrapData() returned error: %v", err)
	}
	if !bytes.Equal(wrapped, testData) {
		t.Errorf("UserPassAuthenticator.WrapData() = %v, expected %v", wrapped, testData)
	}

	// Test UnwrapData
	unwrapped, err := auth.UnwrapData(testData)
	if err != nil {
		t.Errorf("UserPassAuthenticator.UnwrapData() returned error: %v", err)
	}
	if !bytes.Equal(unwrapped, testData) {
		t.Errorf("UserPassAuthenticator.UnwrapData() = %v, expected %v", unwrapped, testData)
	}
}

func TestUserPassAuthenticatorValidAuth(t *testing.T) {
	auth := UserPassAuthenticator{
		Credentials: StaticCredentials{
			"testuser": "testpass",
		},
	}

	// Create valid authentication request
	// Version(1) + Username length(1) + Username + Password length(1) + Password
	authRequest := []byte{
		0x01,                                   // Version
		0x08,                                   // Username length
		't', 'e', 's', 't', 'u', 's', 'e', 'r', // Username
		0x08,                                   // Password length
		't', 'e', 's', 't', 'p', 'a', 's', 's', // Password
	}

	buf := bytes.NewBuffer(authRequest)
	err := auth.Authenticate(buf)
	if err != nil {
		t.Errorf("UserPassAuthenticator.Authenticate() with valid credentials returned error: %v", err)
	}

	// Check response
	response := make([]byte, 2)
	_, err = buf.Read(response)
	if err != nil {
		t.Errorf("Failed to read auth response: %v", err)
	}

	expectedResponse := []byte{0x01, 0x00} // Version 1, Success
	if !bytes.Equal(response, expectedResponse) {
		t.Errorf("Auth response = %v, expected %v", response, expectedResponse)
	}
}

func TestUserPassAuthenticatorInvalidAuth(t *testing.T) {
	auth := UserPassAuthenticator{
		Credentials: StaticCredentials{
			"testuser": "testpass",
		},
	}

	// Create invalid authentication request (wrong password)
	authRequest := []byte{
		0x01,                                   // Version
		0x08,                                   // Username length
		't', 'e', 's', 't', 'u', 's', 'e', 'r', // Username
		0x09,                                        // Password length
		'w', 'r', 'o', 'n', 'g', 'p', 'a', 's', 's', // Wrong password
	}

	buf := bytes.NewBuffer(authRequest)
	err := auth.Authenticate(buf)
	if err == nil {
		t.Errorf("UserPassAuthenticator.Authenticate() with invalid credentials should return error")
	}

	expectedError := "authentication failed"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestUserPassAuthenticatorInvalidVersion(t *testing.T) {
	auth := UserPassAuthenticator{
		Credentials: StaticCredentials{
			"testuser": "testpass",
		},
	}

	// Create authentication request with wrong version
	authRequest := []byte{
		0x02,                                   // Wrong version
		0x08,                                   // Username length
		't', 'e', 's', 't', 'u', 's', 'e', 'r', // Username
		0x08,                                   // Password length
		't', 'e', 's', 't', 'p', 'a', 's', 's', // Password
	}

	buf := bytes.NewBuffer(authRequest)
	err := auth.Authenticate(buf)
	if err == nil {
		t.Errorf("UserPassAuthenticator.Authenticate() with invalid version should return error")
	}

	expectedError := "unsupported auth version"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestUserPassAuthenticatorShortRequest(t *testing.T) {
	auth := UserPassAuthenticator{
		Credentials: StaticCredentials{
			"testuser": "testpass",
		},
	}

	// Test with too short request
	authRequest := []byte{0x01} // Only version

	buf := bytes.NewBuffer(authRequest)
	err := auth.Authenticate(buf)
	if err == nil {
		t.Errorf("UserPassAuthenticator.Authenticate() with short request should return error")
	}
}

func TestGSSAPIAuthenticator(t *testing.T) {
	auth := GSSAPIAuthenticator{}

	// Test GetCode
	if auth.GetCode() != authMethodGSSAPI {
		t.Errorf("GSSAPIAuthenticator.GetCode() = %d, expected %d", auth.GetCode(), authMethodGSSAPI)
	}

	// Test SupportsEncapsulation
	if !auth.SupportsEncapsulation() {
		t.Errorf("GSSAPIAuthenticator.SupportsEncapsulation() = false, expected true")
	}

	// Test Authenticate (should fail as not implemented)
	var buf bytes.Buffer
	err := auth.Authenticate(&buf)
	if err == nil {
		t.Errorf("GSSAPIAuthenticator.Authenticate() should return error (not implemented)")
	}

	expectedError := "GSSAPI authentication not"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}

	// Test WrapData
	testData := []byte("test data")
	_, err = auth.WrapData(testData)
	if err == nil {
		t.Errorf("GSSAPIAuthenticator.WrapData() should return error (not implemented)")
	}

	// Test UnwrapData
	_, err = auth.UnwrapData(testData)
	if err == nil {
		t.Errorf("GSSAPIAuthenticator.UnwrapData() should return error (not implemented)")
	}
}

func TestGSSAPIAuthenticatorAcceptAll(t *testing.T) {
	auth := GSSAPIAuthenticator{AcceptAll: true}

	// Test Authenticate with AcceptAll=true
	authData := []byte("fake GSSAPI token")
	buf := bytes.NewBuffer(authData)

	err := auth.Authenticate(buf)
	if err != nil {
		t.Errorf("GSSAPIAuthenticator.Authenticate() with AcceptAll=true should succeed, got: %v", err)
	}

	// Check response was written
	allData := buf.Bytes()
	if len(allData) >= 2 {
		// Response should be at the end of the buffer
		response := allData[len(allData)-2:]
		expectedResponse := []byte{0x01, 0x00} // Version 1, Success
		if !bytes.Equal(response, expectedResponse) {
			t.Errorf("GSSAPI auth response = %v, expected %v", response, expectedResponse)
		}
	}

	// Test WrapData with AcceptAll=true
	testData := []byte("test data for wrapping")
	wrappedData, err := auth.WrapData(testData)
	if err != nil {
		t.Errorf("GSSAPIAuthenticator.WrapData() with AcceptAll=true should succeed, got: %v", err)
	}

	if len(wrappedData) != 4+len(testData) {
		t.Errorf("Wrapped data length = %d, expected %d", len(wrappedData), 4+len(testData))
	}

	// Test UnwrapData with AcceptAll=true
	unwrappedData, err := auth.UnwrapData(wrappedData)
	if err != nil {
		t.Errorf("GSSAPIAuthenticator.UnwrapData() with AcceptAll=true should succeed, got: %v", err)
	}

	if !bytes.Equal(unwrappedData, testData) {
		t.Errorf("Unwrapped data = %v, expected %v", unwrappedData, testData)
	}

	// Test UnwrapData with invalid data (too short)
	shortData := []byte{0x00, 0x00}
	_, err = auth.UnwrapData(shortData)
	if err == nil {
		t.Errorf("GSSAPIAuthenticator.UnwrapData() should fail with short data")
	}

	// Test UnwrapData with length mismatch
	invalidData := []byte{0x00, 0x00, 0x00, 0x10, 0x01, 0x02} // Claims 16 bytes but only has 2
	_, err = auth.UnwrapData(invalidData)
	if err == nil {
		t.Errorf("GSSAPIAuthenticator.UnwrapData() should fail with length mismatch")
	}

	// Test with empty data
	emptyWrapped, err := auth.WrapData([]byte{})
	if err != nil {
		t.Errorf("GSSAPIAuthenticator.WrapData() should handle empty data")
	}

	emptyUnwrapped, err := auth.UnwrapData(emptyWrapped)
	if err != nil {
		t.Errorf("GSSAPIAuthenticator.UnwrapData() should handle empty wrapped data")
	}

	if len(emptyUnwrapped) != 0 {
		t.Errorf("Unwrapped empty data should be empty, got %d bytes", len(emptyUnwrapped))
	}
}

func TestGSSAPIAuthenticateReadError(t *testing.T) {
	auth := GSSAPIAuthenticator{AcceptAll: true}

	// Test read error
	mock := &mockReadWriter{
		readErr: io.ErrUnexpectedEOF,
	}

	err := auth.Authenticate(mock)
	if err == nil {
		t.Errorf("Expected error when read fails")
	}

	expectedError := "failed to read GSSAPI token"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

func TestGSSAPIAuthenticateWriteError(t *testing.T) {
	auth := GSSAPIAuthenticator{AcceptAll: true}

	// Test write error
	mock := &mockReadWriter{
		readData: []byte("token"),
		writeErr: io.ErrShortWrite,
	}

	err := auth.Authenticate(mock)
	if err == nil {
		t.Errorf("Expected error when write fails")
	}

	expectedError := "failed to write GSSAPI response"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error containing '%s', got '%s'", expectedError, err.Error())
	}
}

// Mock ReadWriter for testing edge cases
type mockReadWriter struct {
	readData  []byte
	writeData []byte
	readErr   error
	writeErr  error
	readPos   int
}

func (m *mockReadWriter) Read(p []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	if m.readPos >= len(m.readData) {
		return 0, io.EOF
	}
	n = copy(p, m.readData[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockReadWriter) Write(p []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.writeData = append(m.writeData, p...)
	return len(p), nil
}

func TestUserPassAuthenticatorReadErrors(t *testing.T) {
	auth := UserPassAuthenticator{
		Credentials: StaticCredentials{
			"testuser": "testpass",
		},
	}

	// Test read error on version
	mock := &mockReadWriter{
		readErr: io.ErrUnexpectedEOF,
	}

	err := auth.Authenticate(mock)
	if err == nil {
		t.Errorf("Expected error when read fails")
	}
}

func TestUserPassAuthenticatorWriteErrors(t *testing.T) {
	auth := UserPassAuthenticator{
		Credentials: StaticCredentials{
			"testuser": "testpass",
		},
	}

	// Valid auth request
	authRequest := []byte{
		0x01, 0x08,
		't', 'e', 's', 't', 'u', 's', 'e', 'r',
		0x08,
		't', 'e', 's', 't', 'p', 'a', 's', 's',
	}

	mock := &mockReadWriter{
		readData: authRequest,
		writeErr: io.ErrShortWrite,
	}

	err := auth.Authenticate(mock)
	if err == nil {
		t.Errorf("Expected error when write fails")
	}
}

func TestUserPassAuthenticatorAdditionalErrors(t *testing.T) {
	auth := UserPassAuthenticator{
		Credentials: StaticCredentials{
			"testuser": "testpass",
		},
	}

	// Test username length read error
	authRequest := []byte{0x01} // Only version, missing username length
	mock := &mockReadWriter{
		readData: authRequest,
	}

	err := auth.Authenticate(mock)
	if err == nil {
		t.Errorf("Expected error when username length read fails")
	}

	// Test username read error
	authRequest2 := []byte{0x01, 0x05, 't', 'e', 's'} // Username length 5, but only 3 chars
	mock2 := &mockReadWriter{
		readData: authRequest2,
	}

	err = auth.Authenticate(mock2)
	if err == nil {
		t.Errorf("Expected error when username read fails")
	}

	// Test password length read error
	authRequest3 := []byte{0x01, 0x04, 't', 'e', 's', 't'} // Username but no password length
	mock3 := &mockReadWriter{
		readData: authRequest3,
	}

	err = auth.Authenticate(mock3)
	if err == nil {
		t.Errorf("Expected error when password length read fails")
	}

	// Test password read error
	authRequest4 := []byte{0x01, 0x04, 't', 'e', 's', 't', 0x05, 'p', 'a'} // Password length 5, but only 2 chars
	mock4 := &mockReadWriter{
		readData: authRequest4,
	}

	err = auth.Authenticate(mock4)
	if err == nil {
		t.Errorf("Expected error when password read fails")
	}

	// Test invalid username length (< 1)
	authRequest5 := []byte{0x01, 0x00} // Version and username length 0
	mock5 := &mockReadWriter{
		readData: authRequest5,
	}

	err = auth.Authenticate(mock5)
	if err == nil {
		t.Errorf("Expected error for invalid username length")
	}
	if !strings.Contains(err.Error(), "invalid username length") {
		t.Errorf("Expected error about invalid username length, got: %v", err)
	}

	// Test authentication failure write error
	authRequest6 := []byte{
		0x01, 0x04, 't', 'e', 's', 't', // Username "test"
		0x05, 'w', 'r', 'o', 'n', 'g', // Password "wrong"
	}
	mock6 := &mockReadWriter{
		readData: authRequest6,
		writeErr: fmt.Errorf("write failed"),
	}

	err = auth.Authenticate(mock6)
	if err == nil {
		t.Errorf("Expected error when write fails during auth failure")
	}
}
