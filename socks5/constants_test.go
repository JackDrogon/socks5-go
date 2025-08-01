package socks5

import (
	"testing"
)

func TestConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant uint8
		expected uint8
	}{
		{"SOCKS5 Version", SOCKS5Version, 0x05},
		{"Auth Method No Auth", AuthMethodNoAuth, 0x00},
		{"Auth Method GSSAPI", AuthMethodGSSAPI, 0x01},
		{"Auth Method UserPass", AuthMethodUserPass, 0x02},
		{"Auth Method No Acceptable", AuthMethodNoAcceptable, 0xFF},
		{"Command Connect", CmdConnect, 0x01},
		{"Command Bind", CmdBind, 0x02},
		{"Command UDP Associate", CmdUDPAssociate, 0x03},
		{"Address Type IPv4", AtypeIPv4, 0x01},
		{"Address Type Domain", AtypeDomain, 0x03},
		{"Address Type IPv6", AtypeIPv6, 0x04},
		{"Reply Success", RepSuccess, 0x00},
		{"Reply Server Failure", RepServerFailure, 0x01},
		{"Reply Not Allowed", RepNotAllowed, 0x02},
		{"Reply Network Unreachable", RepNetworkUnreachable, 0x03},
		{"Reply Host Unreachable", RepHostUnreachable, 0x04},
		{"Reply Connection Refused", RepConnectionRefused, 0x05},
		{"Reply TTL Expired", RepTTLExpired, 0x06},
		{"Reply Command Not Supported", RepCommandNotSupported, 0x07},
		{"Reply Address Not Supported", RepAddressNotSupported, 0x08},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("%s = %v, expected %v", tt.name, tt.constant, tt.expected)
			}
		})
	}
}

func TestRFC1928Compliance(t *testing.T) {
	// Test RFC 1928 compliance constants
	if SOCKS5Version != 0x05 {
		t.Errorf("SOCKS version should be 0x05 per RFC 1928, got 0x%02X", SOCKS5Version)
	}

	// Test command constants per RFC 1928
	commands := map[string]uint8{
		"CONNECT":       CmdConnect,
		"BIND":          CmdBind,
		"UDP ASSOCIATE": CmdUDPAssociate,
	}

	expectedCommands := map[string]uint8{
		"CONNECT":       0x01,
		"BIND":          0x02,
		"UDP ASSOCIATE": 0x03,
	}

	for name, cmd := range commands {
		if cmd != expectedCommands[name] {
			t.Errorf("Command %s should be 0x%02X per RFC 1928, got 0x%02X", name, expectedCommands[name], cmd)
		}
	}

	// Test address type constants per RFC 1928
	addressTypes := map[string]uint8{
		"IPv4":   AtypeIPv4,
		"Domain": AtypeDomain,
		"IPv6":   AtypeIPv6,
	}

	expectedAddressTypes := map[string]uint8{
		"IPv4":   0x01,
		"Domain": 0x03,
		"IPv6":   0x04,
	}

	for name, atype := range addressTypes {
		if atype != expectedAddressTypes[name] {
			t.Errorf("Address type %s should be 0x%02X per RFC 1928, got 0x%02X", name, expectedAddressTypes[name], atype)
		}
	}

	// Test reply codes per RFC 1928
	replyCodes := []uint8{
		RepSuccess,
		RepServerFailure,
		RepNotAllowed,
		RepNetworkUnreachable,
		RepHostUnreachable,
		RepConnectionRefused,
		RepTTLExpired,
		RepCommandNotSupported,
		RepAddressNotSupported,
	}

	expectedReplyCodes := []uint8{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	}

	for i, code := range replyCodes {
		if code != expectedReplyCodes[i] {
			t.Errorf("Reply code %d should be 0x%02X per RFC 1928, got 0x%02X", i, expectedReplyCodes[i], code)
		}
	}
}
