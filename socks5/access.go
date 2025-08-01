package socks5

import (
	"net"
	"strings"
)

// AccessControl defines access control rules
type AccessControl interface {
	Allow(clientAddr net.Addr, destAddr string) bool
}

// AllowAllAccess allows all connections
type AllowAllAccess struct{}

func (a AllowAllAccess) Allow(clientAddr net.Addr, destAddr string) bool {
	return true
}

// BlacklistAccess denies connections to blacklisted destinations
type BlacklistAccess struct {
	BlacklistedHosts []string
	BlacklistedNets  []*net.IPNet
}

func (a BlacklistAccess) Allow(clientAddr net.Addr, destAddr string) bool {
	host, _, err := net.SplitHostPort(destAddr)
	if err != nil {
		return false
	}

	// Check host blacklist
	for _, blockedHost := range a.BlacklistedHosts {
		if strings.EqualFold(host, blockedHost) {
			return false
		}
	}

	// Check IP/network blacklist
	ip := net.ParseIP(host)
	if ip != nil {
		for _, blockedNet := range a.BlacklistedNets {
			if blockedNet.Contains(ip) {
				return false
			}
		}
	}

	return true
}

// WhitelistAccess only allows connections to whitelisted destinations
type WhitelistAccess struct {
	WhitelistedHosts []string
	WhitelistedNets  []*net.IPNet
}

func (a WhitelistAccess) Allow(clientAddr net.Addr, destAddr string) bool {
	host, _, err := net.SplitHostPort(destAddr)
	if err != nil {
		return false
	}

	// Check host whitelist
	for _, allowedHost := range a.WhitelistedHosts {
		if strings.EqualFold(host, allowedHost) {
			return true
		}
	}

	// Check IP/network whitelist
	ip := net.ParseIP(host)
	if ip != nil {
		for _, allowedNet := range a.WhitelistedNets {
			if allowedNet.Contains(ip) {
				return true
			}
		}
	}

	return false
}

// CombinedAccess combines multiple access controls with AND logic
type CombinedAccess struct {
	Rules []AccessControl
}

func (a CombinedAccess) Allow(clientAddr net.Addr, destAddr string) bool {
	for _, rule := range a.Rules {
		if !rule.Allow(clientAddr, destAddr) {
			return false
		}
	}
	return true
}
