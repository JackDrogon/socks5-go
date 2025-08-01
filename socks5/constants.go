package socks5

const (
	SOCKS5Version = 0x05

	AuthMethodNoAuth       = 0x00
	AuthMethodGSSAPI       = 0x01
	AuthMethodUserPass     = 0x02
	AuthMethodNoAcceptable = 0xFF

	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUDPAssociate = 0x03

	AtypeIPv4   = 0x01
	AtypeDomain = 0x03
	AtypeIPv6   = 0x04

	RepSuccess             = 0x00
	RepServerFailure       = 0x01
	RepNotAllowed          = 0x02
	RepNetworkUnreachable  = 0x03
	RepHostUnreachable     = 0x04
	RepConnectionRefused   = 0x05
	RepTTLExpired          = 0x06
	RepCommandNotSupported = 0x07
	RepAddressNotSupported = 0x08
)
