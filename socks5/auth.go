package socks5

import (
	"fmt"
	"io"
)

type Authenticator interface {
	GetCode() uint8
	Authenticate(conn io.ReadWriter) error
}

type NoAuthAuthenticator struct{}

func (a NoAuthAuthenticator) GetCode() uint8 {
	return authMethodNoAuth
}

func (a NoAuthAuthenticator) Authenticate(conn io.ReadWriter) error {
	return nil
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