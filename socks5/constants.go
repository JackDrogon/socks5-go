package socks5

const (
	socks5Version = 0x05

	authMethodNoAuth       = 0x00
	authMethodGSSAPI       = 0x01
	authMethodUserPass     = 0x02
	authMethodNoAcceptable = 0xFF

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	atypeIPv4   = 0x01
	atypeDomain = 0x03
	atypeIPv6   = 0x04

	repSuccess             = 0x00
	repServerFailure       = 0x01
	repNotAllowed          = 0x02
	repNetworkUnreachable  = 0x03
	repHostUnreachable     = 0x04
	repConnectionRefused   = 0x05
	repTTLExpired          = 0x06
	repCommandNotSupported = 0x07
	repAddressNotSupported = 0x08
)
