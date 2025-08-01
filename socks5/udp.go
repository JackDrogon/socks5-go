package socks5

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

// UDPHeader represents the UDP request header as per RFC 1928
type UDPHeader struct {
	Reserved uint16
	Fragment uint8
	AddrType uint8
	DstAddr  []byte
	DstPort  uint16
	Data     []byte
}

// UDPAssociation manages a UDP association
type UDPAssociation struct {
	clientAddr net.Addr
	lastSeen   time.Time
	mutex      sync.RWMutex
}

// parseUDPHeader parses UDP datagram header according to RFC 1928
func parseUDPHeader(data []byte) (*UDPHeader, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("UDP header too short")
	}

	header := &UDPHeader{
		Reserved: uint16(data[0])<<8 | uint16(data[1]),
		Fragment: data[2],
		AddrType: data[3],
	}

	// RFC 1928: RSV field MUST be X'0000'
	if header.Reserved != 0x0000 {
		return nil, fmt.Errorf("invalid UDP RSV field: expected 0x0000, got 0x%04X", header.Reserved)
	}

	offset := 4
	var addrLen int

	switch header.AddrType {
	case AtypeIPv4:
		addrLen = 4
	case AtypeIPv6:
		addrLen = 16
	case AtypeDomain:
		if len(data) < offset+1 {
			return nil, fmt.Errorf("invalid domain length")
		}
		addrLen = int(data[offset])
		offset++
	default:
		return nil, fmt.Errorf("unsupported address type: %d", header.AddrType)
	}

	if len(data) < offset+addrLen+2 {
		return nil, fmt.Errorf("UDP datagram too short for address and port")
	}

	header.DstAddr = make([]byte, addrLen)
	copy(header.DstAddr, data[offset:offset+addrLen])
	offset += addrLen

	header.DstPort = uint16(data[offset])<<8 | uint16(data[offset+1])
	offset += 2

	header.Data = data[offset:]
	return header, nil
}

// buildUDPHeader builds UDP datagram header
func buildUDPHeader(addrType uint8, addr []byte, port uint16, data []byte) []byte {
	var headerLen int
	switch addrType {
	case AtypeIPv4:
		headerLen = 4 + 4 + 2 // RSV + FRAG + ATYP + IPv4 + PORT
	case AtypeIPv6:
		headerLen = 4 + 16 + 2 // RSV + FRAG + ATYP + IPv6 + PORT
	case AtypeDomain:
		headerLen = 4 + 1 + len(addr) + 2 // RSV + FRAG + ATYP + LEN + DOMAIN + PORT
	}

	packet := make([]byte, headerLen+len(data))
	offset := 0

	// Reserved (2 bytes)
	packet[0] = 0x00
	packet[1] = 0x00
	offset += 2

	// Fragment (1 byte)
	packet[offset] = 0x00
	offset++

	// Address Type (1 byte)
	packet[offset] = addrType
	offset++

	// Address
	if addrType == AtypeDomain {
		packet[offset] = byte(len(addr))
		offset++
	}
	copy(packet[offset:offset+len(addr)], addr)
	offset += len(addr)

	// Port (2 bytes)
	packet[offset] = byte(port >> 8)
	packet[offset+1] = byte(port & 0xFF)
	offset += 2

	// Data
	copy(packet[offset:], data)

	return packet
}

// getDestinationAddress formats the destination address
func (h *UDPHeader) getDestinationAddress() string {
	var addr string
	switch h.AddrType {
	case AtypeIPv4, AtypeIPv6:
		addr = net.IP(h.DstAddr).String()
	case AtypeDomain:
		addr = string(h.DstAddr)
	}
	return net.JoinHostPort(addr, strconv.Itoa(int(h.DstPort)))
}

// handleUDPRelayWithEncapsulation handles UDP packet relaying with method-dependent encapsulation
func (s *Server) handleUDPRelayWithEncapsulation(udpConn *net.UDPConn, clientAddr net.Addr, auth Authenticator) {
	if !auth.SupportsEncapsulation() {
		// No encapsulation needed, use regular UDP relay
		s.handleUDPRelay(udpConn, clientAddr)
		return
	}

	s.logf("Using method-dependent encapsulation for UDP relay")
	s.handleUDPRelayEncapsulated(udpConn, clientAddr, auth)
}

// handleUDPRelay handles UDP packet relaying without encapsulation
func (s *Server) handleUDPRelay(udpConn *net.UDPConn, clientAddr net.Addr) {
	associations := make(map[string]*UDPAssociation)
	buffer := make([]byte, 65507) // Max UDP payload size

	// Cleanup goroutine
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			now := time.Now()
			for key, assoc := range associations {
				assoc.mutex.RLock()
				if now.Sub(assoc.lastSeen) > 2*time.Minute {
					delete(associations, key)
					s.logf("Cleaned up UDP association for %s", key)
				}
				assoc.mutex.RUnlock()
			}
		}
	}()

	for {
		udpConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, srcAddr, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			s.logf("UDP relay read error: %v", err)
			break
		}

		// Check if this is from our client
		clientKey := clientAddr.String()
		srcKey := srcAddr.String()

		if srcKey == clientKey {
			// Client -> Target
			header, err := parseUDPHeader(buffer[:n])
			if err != nil {
				s.logf("Failed to parse UDP header: %v", err)
				continue
			}

			// Skip fragmented packets for now
			if header.Fragment != 0 {
				s.logf("Dropping fragmented UDP packet")
				continue
			}

			destAddr := header.getDestinationAddress()
			targetUDPAddr, err := net.ResolveUDPAddr("udp", destAddr)
			if err != nil {
				s.logf("Failed to resolve target UDP address %s: %v", destAddr, err)
				continue
			}

			targetConn, err := net.DialUDP("udp", nil, targetUDPAddr)
			if err != nil {
				s.logf("Failed to dial target UDP %s: %v", destAddr, err)
				continue
			}

			_, err = targetConn.Write(header.Data)
			targetConn.Close()
			if err != nil {
				s.logf("Failed to write to target UDP: %v", err)
				continue
			}

			// Update association
			if _, exists := associations[destAddr]; !exists {
				associations[destAddr] = &UDPAssociation{
					clientAddr: srcAddr,
					lastSeen:   time.Now(),
				}
			} else {
				associations[destAddr].mutex.Lock()
				associations[destAddr].lastSeen = time.Now()
				associations[destAddr].mutex.Unlock()
			}

			s.logf("UDP relay: %s -> %s (%d bytes)", srcAddr, destAddr, len(header.Data))
		} else {
			// Target -> Client (would need more complex implementation)
			// This is a simplified version that doesn't handle responses
			s.logf("Received UDP packet from unknown source: %s", srcAddr)
		}
	}
}

// handleUDPRelayEncapsulated handles UDP packet relaying with encapsulation
func (s *Server) handleUDPRelayEncapsulated(udpConn *net.UDPConn, clientAddr net.Addr, auth Authenticator) {
	associations := make(map[string]*UDPAssociation)
	buffer := make([]byte, 65507) // Max UDP payload size

	// Cleanup goroutine
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			now := time.Now()
			for key, assoc := range associations {
				assoc.mutex.RLock()
				if now.Sub(assoc.lastSeen) > 2*time.Minute {
					delete(associations, key)
					s.logf("Cleaned up UDP association for %s", key)
				}
				assoc.mutex.RUnlock()
			}
		}
	}()

	for {
		udpConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		n, srcAddr, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			s.logf("UDP relay read error: %v", err)
			break
		}

		// Check if this is from our client
		clientKey := clientAddr.String()
		srcKey := srcAddr.String()

		if srcKey == clientKey {
			// Client -> Target: Unwrap the encapsulated UDP packet
			unwrappedData, err := auth.UnwrapData(buffer[:n])
			if err != nil {
				s.logf("Failed to unwrap UDP data from client: %v", err)
				continue
			}

			// Parse the unwrapped SOCKS UDP header
			header, err := parseUDPHeader(unwrappedData)
			if err != nil {
				s.logf("Failed to parse UDP header: %v", err)
				continue
			}

			// Skip fragmented packets for now
			if header.Fragment != 0 {
				s.logf("Dropping fragmented UDP packet")
				continue
			}

			destAddr := header.getDestinationAddress()
			targetUDPAddr, err := net.ResolveUDPAddr("udp", destAddr)
			if err != nil {
				s.logf("Failed to resolve target UDP address %s: %v", destAddr, err)
				continue
			}

			targetConn, err := net.DialUDP("udp", nil, targetUDPAddr)
			if err != nil {
				s.logf("Failed to dial target UDP %s: %v", destAddr, err)
				continue
			}

			_, err = targetConn.Write(header.Data)
			targetConn.Close()
			if err != nil {
				s.logf("Failed to write to target UDP: %v", err)
				continue
			}

			// Update association
			if _, exists := associations[destAddr]; !exists {
				associations[destAddr] = &UDPAssociation{
					clientAddr: srcAddr,
					lastSeen:   time.Now(),
				}
			} else {
				associations[destAddr].mutex.Lock()
				associations[destAddr].lastSeen = time.Now()
				associations[destAddr].mutex.Unlock()
			}

			s.logf("Encapsulated UDP relay: %s -> %s (%d bytes)", srcAddr, destAddr, len(header.Data))
		} else {
			// Target -> Client: This would need reverse lookup and encapsulation
			// For now, log that we received data from an unknown source
			s.logf("Received encapsulated UDP packet from unknown source: %s", srcAddr)
		}
	}
}
