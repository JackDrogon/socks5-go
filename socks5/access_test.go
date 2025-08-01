package socks5

import (
	"net"
	"testing"
)

func TestAllowAllAccess(t *testing.T) {
	access := AllowAllAccess{}

	testCases := []struct {
		name       string
		clientAddr string
		destAddr   string
		expected   bool
	}{
		{"Allow localhost", "127.0.0.1:1234", "127.0.0.1:80", true},
		{"Allow external", "192.168.1.1:5678", "google.com:80", true},
		{"Allow IPv6", "[::1]:1234", "[::1]:80", true},
		{"Allow domain", "10.0.0.1:1234", "example.com:443", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clientAddr, _ := net.ResolveTCPAddr("tcp", tc.clientAddr)
			result := access.Allow(clientAddr, tc.destAddr)
			if result != tc.expected {
				t.Errorf("Allow(%s, %s) = %v, expected %v", tc.clientAddr, tc.destAddr, result, tc.expected)
			}
		})
	}
}

func TestBlacklistAccess(t *testing.T) {
	_, blockedNet, _ := net.ParseCIDR("192.168.1.0/24")
	access := BlacklistAccess{
		BlacklistedHosts: []string{"blocked.com", "evil.org"},
		BlacklistedNets:  []*net.IPNet{blockedNet},
	}

	testCases := []struct {
		name       string
		clientAddr string
		destAddr   string
		expected   bool
	}{
		{"Allow good host", "127.0.0.1:1234", "google.com:80", true},
		{"Block bad host", "127.0.0.1:1234", "blocked.com:80", false},
		{"Block bad host case insensitive", "127.0.0.1:1234", "BLOCKED.COM:80", false},
		{"Block bad IP", "127.0.0.1:1234", "192.168.1.100:80", false},
		{"Allow good IP", "127.0.0.1:1234", "8.8.8.8:53", true},
		{"Block another bad host", "127.0.0.1:1234", "evil.org:443", false},
		{"Invalid dest addr", "127.0.0.1:1234", "invalid-addr", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clientAddr, _ := net.ResolveTCPAddr("tcp", tc.clientAddr)
			result := access.Allow(clientAddr, tc.destAddr)
			if result != tc.expected {
				t.Errorf("Allow(%s, %s) = %v, expected %v", tc.clientAddr, tc.destAddr, result, tc.expected)
			}
		})
	}
}

func TestWhitelistAccess(t *testing.T) {
	_, allowedNet, _ := net.ParseCIDR("10.0.0.0/24")
	access := WhitelistAccess{
		WhitelistedHosts: []string{"allowed.com", "trusted.org"},
		WhitelistedNets:  []*net.IPNet{allowedNet},
	}

	testCases := []struct {
		name       string
		clientAddr string
		destAddr   string
		expected   bool
	}{
		{"Block unlisted host", "127.0.0.1:1234", "google.com:80", false},
		{"Allow good host", "127.0.0.1:1234", "allowed.com:80", true},
		{"Allow good host case insensitive", "127.0.0.1:1234", "ALLOWED.COM:80", true},
		{"Allow good IP", "127.0.0.1:1234", "10.0.0.100:80", true},
		{"Block bad IP", "127.0.0.1:1234", "192.168.1.100:80", false},
		{"Allow another good host", "127.0.0.1:1234", "trusted.org:443", true},
		{"Invalid dest addr", "127.0.0.1:1234", "invalid-addr", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clientAddr, _ := net.ResolveTCPAddr("tcp", tc.clientAddr)
			result := access.Allow(clientAddr, tc.destAddr)
			if result != tc.expected {
				t.Errorf("Allow(%s, %s) = %v, expected %v", tc.clientAddr, tc.destAddr, result, tc.expected)
			}
		})
	}
}

func TestCombinedAccess(t *testing.T) {
	_, blockedNet, _ := net.ParseCIDR("192.168.1.0/24")
	_, allowedNet, _ := net.ParseCIDR("10.0.0.0/8")

	blacklist := BlacklistAccess{
		BlacklistedHosts: []string{"blocked.com"},
		BlacklistedNets:  []*net.IPNet{blockedNet},
	}

	whitelist := WhitelistAccess{
		WhitelistedHosts: []string{"allowed.com"},
		WhitelistedNets:  []*net.IPNet{allowedNet},
	}

	access := CombinedAccess{
		Rules: []AccessControl{blacklist, whitelist},
	}

	testCases := []struct {
		name       string
		clientAddr string
		destAddr   string
		expected   bool
	}{
		{"Allow whitelisted and not blacklisted", "127.0.0.1:1234", "allowed.com:80", true},
		{"Block blacklisted even if whitelisted", "127.0.0.1:1234", "blocked.com:80", false},
		{"Block not whitelisted", "127.0.0.1:1234", "google.com:80", false},
		{"Allow IP in whitelist", "127.0.0.1:1234", "10.0.0.100:80", true},
		{"Block IP in blacklist", "127.0.0.1:1234", "192.168.1.100:80", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clientAddr, _ := net.ResolveTCPAddr("tcp", tc.clientAddr)
			result := access.Allow(clientAddr, tc.destAddr)
			if result != tc.expected {
				t.Errorf("Allow(%s, %s) = %v, expected %v", tc.clientAddr, tc.destAddr, result, tc.expected)
			}
		})
	}
}

func TestCombinedAccessEmptyRules(t *testing.T) {
	access := CombinedAccess{
		Rules: []AccessControl{},
	}

	clientAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:1234")
	result := access.Allow(clientAddr, "google.com:80")
	if !result {
		t.Errorf("CombinedAccess with empty rules should allow all, got false")
	}
}

func TestBlacklistAccessEdgeCases(t *testing.T) {
	access := BlacklistAccess{
		BlacklistedHosts: []string{},
		BlacklistedNets:  []*net.IPNet{},
	}

	testCases := []struct {
		name       string
		clientAddr string
		destAddr   string
		expected   bool
	}{
		{"Allow when no blacklist", "127.0.0.1:1234", "google.com:80", true},
		{"Allow IP when no blacklist", "127.0.0.1:1234", "8.8.8.8:53", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clientAddr, _ := net.ResolveTCPAddr("tcp", tc.clientAddr)
			result := access.Allow(clientAddr, tc.destAddr)
			if result != tc.expected {
				t.Errorf("Allow(%s, %s) = %v, expected %v", tc.clientAddr, tc.destAddr, result, tc.expected)
			}
		})
	}
}

func TestWhitelistAccessEdgeCases(t *testing.T) {
	access := WhitelistAccess{
		WhitelistedHosts: []string{},
		WhitelistedNets:  []*net.IPNet{},
	}

	testCases := []struct {
		name       string
		clientAddr string
		destAddr   string
		expected   bool
	}{
		{"Block when empty whitelist", "127.0.0.1:1234", "google.com:80", false},
		{"Block IP when empty whitelist", "127.0.0.1:1234", "8.8.8.8:53", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			clientAddr, _ := net.ResolveTCPAddr("tcp", tc.clientAddr)
			result := access.Allow(clientAddr, tc.destAddr)
			if result != tc.expected {
				t.Errorf("Allow(%s, %s) = %v, expected %v", tc.clientAddr, tc.destAddr, result, tc.expected)
			}
		})
	}
}
