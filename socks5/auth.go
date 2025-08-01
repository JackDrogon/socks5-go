package socks5

import (
	"fmt"
	"io"
)

type Authenticator interface {
	GetCode() uint8
	Authenticate(conn io.ReadWriter) error
	// SupportsEncapsulation returns true if this method provides data encapsulation
	SupportsEncapsulation() bool
	// WrapData encapsulates data for transmission (if supported)
	WrapData(data []byte) ([]byte, error)
	// UnwrapData decapsulates received data (if supported)  
	UnwrapData(data []byte) ([]byte, error)
}

type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) GetCode() uint8 {
	return authMethodNoAuth
}

func (a NoAuthAuthenticator) Authenticate(conn io.ReadWriter) error {
	return nil
}

func (a NoAuthAuthenticator) SupportsEncapsulation() bool {
	return false
}

func (a NoAuthAuthenticator) WrapData(data []byte) ([]byte, error) {
	return data, nil // No encapsulation for no-auth
}

func (a NoAuthAuthenticator) UnwrapData(data []byte) ([]byte, error) {
	return data, nil // No encapsulation for no-auth
}

type UserPassAuthenticator struct {
	Credentials StaticCredentials
}

type StaticCredentials map[string]string

func (a UserPassAuthenticator) GetCode() uint8 {
	return authMethodUserPass
}

func (a UserPassAuthenticator) Authenticate(conn io.ReadWriter) error {
	header := []byte{0, 0}
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read auth header: %w", err)
	}

	if header[0] != 0x01 {
		return fmt.Errorf("unsupported auth version: %d", header[0])
	}

	userLen := int(header[1])
	if userLen < 1 {
		return fmt.Errorf("invalid username length: %d", userLen)
	}

	username := make([]byte, userLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return fmt.Errorf("failed to read username: %w", err)
	}

	passLenBuf := []byte{0}
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		return fmt.Errorf("failed to read password length: %w", err)
	}

	passLen := int(passLenBuf[0])
	password := make([]byte, passLen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	if expectedPass, ok := a.Credentials[string(username)]; ok && expectedPass == string(password) {
		if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
			return fmt.Errorf("failed to write auth response: %w", err)
		}
		return nil
	}

	if _, err := conn.Write([]byte{0x01, 0x01}); err != nil {
		return fmt.Errorf("failed to write auth response: %w", err)
	}
	return fmt.Errorf("authentication failed")
}

func (a UserPassAuthenticator) SupportsEncapsulation() bool {
	return false
}

func (a UserPassAuthenticator) WrapData(data []byte) ([]byte, error) {
	return data, nil // No encapsulation for username/password
}

func (a UserPassAuthenticator) UnwrapData(data []byte) ([]byte, error) {
	return data, nil // No encapsulation for username/password
}

type GSSAPIAuthenticator struct {
	// GSSAPI implementation would require additional dependencies
	// For now, this is a placeholder that accepts any GSSAPI request
	AcceptAll bool
}

func (a GSSAPIAuthenticator) GetCode() uint8 {
	return authMethodGSSAPI
}

func (a GSSAPIAuthenticator) Authenticate(conn io.ReadWriter) error {
	// This is a simplified GSSAPI implementation
	// In a real implementation, this would handle the full GSSAPI negotiation
	// including mechanism selection, context establishment, etc.
	
	if !a.AcceptAll {
		return fmt.Errorf("GSSAPI authentication not fully implemented")
	}

	// For demonstration purposes, we'll accept any GSSAPI attempt
	// Real implementation would need to:
	// 1. Read GSSAPI negotiation token
	// 2. Process with GSS_Accept_sec_context()
	// 3. Handle context establishment
	// 4. Validate credentials
	
	// Read any incoming GSSAPI token (simplified)
	buffer := make([]byte, 1024)
	_, err := conn.Read(buffer)
	if err != nil {
		return fmt.Errorf("failed to read GSSAPI token: %w", err)
	}

	// Send success response (simplified)
	response := []byte{0x01, 0x00} // Version 1, Success
	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("failed to write GSSAPI response: %w", err)
	}

	return nil
}

func (a GSSAPIAuthenticator) SupportsEncapsulation() bool {
	// GSSAPI typically supports integrity and confidentiality encapsulation
	return true
}

func (a GSSAPIAuthenticator) WrapData(data []byte) ([]byte, error) {
	if !a.AcceptAll {
		return nil, fmt.Errorf("GSSAPI encapsulation not fully implemented")
	}

	// In a real implementation, this would use GSS_Wrap() to provide
	// integrity and/or confidentiality protection for the data
	// For demonstration purposes, we'll add a simple header
	
	// Format: [LENGTH:4][WRAPPED_DATA:LENGTH]
	// This is a simplified version - real GSSAPI would use proper tokens
	wrappedData := make([]byte, 4+len(data))
	
	// Length in network byte order
	length := uint32(len(data))
	wrappedData[0] = byte(length >> 24)
	wrappedData[1] = byte(length >> 16)
	wrappedData[2] = byte(length >> 8)
	wrappedData[3] = byte(length)
	
	// Copy original data
	copy(wrappedData[4:], data)
	
	return wrappedData, nil
}

func (a GSSAPIAuthenticator) UnwrapData(data []byte) ([]byte, error) {
	if !a.AcceptAll {
		return nil, fmt.Errorf("GSSAPI encapsulation not fully implemented")
	}

	if len(data) < 4 {
		return nil, fmt.Errorf("GSSAPI wrapped data too short")
	}

	// In a real implementation, this would use GSS_Unwrap() to verify
	// and decrypt the data. Here we just parse our simple format.
	
	// Read length
	length := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	
	if len(data) < int(4+length) {
		return nil, fmt.Errorf("GSSAPI wrapped data length mismatch")
	}
	
	// Return unwrapped data
	unwrappedData := make([]byte, length)
	copy(unwrappedData, data[4:4+length])
	
	return unwrappedData, nil
}