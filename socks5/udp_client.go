package socks5

import (
	"fmt"
	"net"
	"strconv"
	"time"
)

// UDPConnection represents a UDP connection through SOCKS5 proxy
type UDPConnection struct {
	tcpConn      net.Conn // TCP connection to maintain UDP association
	udpConn      *net.UDPConn
	udpRelayAddr string
	targetAddr   string
}

// Read implements net.Conn interface for UDP connections
func (u *UDPConnection) Read(b []byte) (int, error) {
	if u.udpConn == nil {
		if err := u.setupUDPConnection(); err != nil {
			return 0, err
		}
	}

	// Read UDP packet with SOCKS5 header
	buffer := make([]byte, len(b)+1024) // Extra space for SOCKS5 UDP header
	n, err := u.udpConn.Read(buffer)
	if err != nil {
		return 0, err
	}

	// Parse SOCKS5 UDP request header and extract data
	data, err := u.parseUDPPacket(buffer[:n])
	if err != nil {
		return 0, err
	}

	// Copy data to user buffer
	if len(data) > len(b) {
		return 0, fmt.Errorf("buffer too small: need %d bytes, have %d", len(data), len(b))
	}

	copy(b, data)
	return len(data), nil
}

// Write implements net.Conn interface for UDP connections
func (u *UDPConnection) Write(b []byte) (int, error) {
	if u.udpConn == nil {
		if err := u.setupUDPConnection(); err != nil {
			return 0, err
		}
	}

	// Build SOCKS5 UDP request header
	packet, err := u.buildUDPPacket(b)
	if err != nil {
		return 0, err
	}

	// Send packet to UDP relay
	_, err = u.udpConn.Write(packet)
	if err != nil {
		return 0, err
	}

	return len(b), nil
}

// Close implements net.Conn interface
func (u *UDPConnection) Close() error {
	var err error
	if u.udpConn != nil {
		err = u.udpConn.Close()
	}
	if u.tcpConn != nil {
		// Closing TCP connection terminates UDP association
		tcpErr := u.tcpConn.Close()
		if err == nil {
			err = tcpErr
		}
	}
	return err
}

// LocalAddr implements net.Conn interface
func (u *UDPConnection) LocalAddr() net.Addr {
	if u.udpConn != nil {
		return u.udpConn.LocalAddr()
	}
	return nil
}

// RemoteAddr implements net.Conn interface
func (u *UDPConnection) RemoteAddr() net.Addr {
	if u.udpConn != nil {
		return u.udpConn.RemoteAddr()
	}
	return nil
}

// SetDeadline implements net.Conn interface
func (u *UDPConnection) SetDeadline(t time.Time) error {
	if u.udpConn != nil {
		return u.udpConn.SetDeadline(t)
	}
	return nil
}

// SetReadDeadline implements net.Conn interface
func (u *UDPConnection) SetReadDeadline(t time.Time) error {
	if u.udpConn != nil {
		return u.udpConn.SetReadDeadline(t)
	}
	return nil
}

// SetWriteDeadline implements net.Conn interface
func (u *UDPConnection) SetWriteDeadline(t time.Time) error {
	if u.udpConn != nil {
		return u.udpConn.SetWriteDeadline(t)
	}
	return nil
}

// setupUDPConnection establishes the actual UDP connection to the relay server
func (u *UDPConnection) setupUDPConnection() error {
	relayAddr, err := net.ResolveUDPAddr("udp", u.udpRelayAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP relay address: %w", err)
	}

	u.udpConn, err = net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		return fmt.Errorf("failed to connect to UDP relay: %w", err)
	}

	return nil
}

// buildUDPPacket creates a SOCKS5 UDP request packet
func (u *UDPConnection) buildUDPPacket(data []byte) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(u.targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid target address format: %w", err)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	// Build UDP request header: RSV | FRAG | ATYP | DST.ADDR | DST.PORT | DATA
	packet := []byte{0x00, 0x00, 0x00} // RSV (2 bytes) + FRAG (1 byte)

	// Add address type and address
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			// IPv4 address
			packet = append(packet, AtypeIPv4)
			packet = append(packet, ip4...)
		} else {
			// IPv6 address
			packet = append(packet, AtypeIPv6)
			packet = append(packet, ip.To16()...)
		}
	} else {
		// Domain name
		if len(host) > 255 {
			return nil, fmt.Errorf("domain name too long")
		}
		packet = append(packet, AtypeDomain)
		packet = append(packet, byte(len(host)))
		packet = append(packet, []byte(host)...)
	}

	// Add port (2 bytes, network byte order)
	packet = append(packet, byte(port>>8), byte(port&0xff))

	// Add user data
	packet = append(packet, data...)

	return packet, nil
}

// parseUDPPacket extracts data from a SOCKS5 UDP response packet
func (u *UDPConnection) parseUDPPacket(packet []byte) ([]byte, error) {
	if len(packet) < 4 {
		return nil, fmt.Errorf("packet too short")
	}

	// Skip RSV (2 bytes) and FRAG (1 byte)
	offset := 3
	addrType := packet[offset]
	offset++

	// Parse address based on type
	switch addrType {
	case AtypeIPv4:
		if len(packet) < offset+4+2 {
			return nil, fmt.Errorf("IPv4 packet too short")
		}
		offset += 4 + 2 // IPv4 (4 bytes) + port (2 bytes)

	case AtypeIPv6:
		if len(packet) < offset+16+2 {
			return nil, fmt.Errorf("IPv6 packet too short")
		}
		offset += 16 + 2 // IPv6 (16 bytes) + port (2 bytes)

	case AtypeDomain:
		if len(packet) < offset+1 {
			return nil, fmt.Errorf("domain packet too short")
		}
		domainLen := int(packet[offset])
		offset++
		if len(packet) < offset+domainLen+2 {
			return nil, fmt.Errorf("domain packet too short")
		}
		offset += domainLen + 2 // domain + port (2 bytes)

	default:
		return nil, fmt.Errorf("unsupported address type: %d", addrType)
	}

	// Return remaining data
	return packet[offset:], nil
}
