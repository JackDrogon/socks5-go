package socks5

import (
	"fmt"
	"io"
	"net"
)

func sendReply(conn io.Writer, rep uint8, addr net.Addr) error {
	var addrType uint8
	var addrBody []byte
	var port uint16

	if addr != nil {
		switch a := addr.(type) {
		case *net.TCPAddr:
			if a.IP.To4() != nil {
				addrType = AtypeIPv4
				addrBody = a.IP.To4()
			} else {
				addrType = AtypeIPv6
				addrBody = a.IP.To16()
			}
			port = uint16(a.Port)
		case *net.UDPAddr:
			if a.IP.To4() != nil {
				addrType = AtypeIPv4
				addrBody = a.IP.To4()
			} else {
				addrType = AtypeIPv6
				addrBody = a.IP.To16()
			}
			port = uint16(a.Port)
		default:
			return fmt.Errorf("unsupported address type: %T", addr)
		}
	} else {
		addrType = AtypeIPv4
		addrBody = []byte{0, 0, 0, 0}
		port = 0
	}

	reply := make([]byte, 6+len(addrBody))
	reply[0] = SOCKS5Version
	reply[1] = rep
	reply[2] = 0
	reply[3] = addrType
	copy(reply[4:], addrBody)
	reply[4+len(addrBody)] = byte(port >> 8)
	reply[5+len(addrBody)] = byte(port & 0xff)

	_, err := conn.Write(reply)
	return err
}
