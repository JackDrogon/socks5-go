package socks5

import (
	"fmt"
	"io"
	"net"
	"strconv"
)

type Request struct {
	Version  uint8
	Command  uint8
	Reserved uint8
	AddrType uint8
	DestAddr []byte
	DestPort uint16
	RealDest string
}

func NewRequest(conn io.ReadWriter) (*Request, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, fmt.Errorf("failed to read request header: %w", err)
	}

	req := &Request{
		Version:  header[0],
		Command:  header[1],
		Reserved: header[2],
		AddrType: header[3],
	}

	if req.Version != socks5Version {
		return nil, fmt.Errorf("unsupported SOCKS version: %d", req.Version)
	}

	if req.Command != cmdConnect {
		return nil, fmt.Errorf("unsupported command: %d", req.Command)
	}

	dest, err := readAddrSpec(conn, req.AddrType)
	if err != nil {
		return nil, fmt.Errorf("failed to read address: %w", err)
	}

	req.DestAddr = dest.IP
	req.DestPort = dest.Port
	req.RealDest = dest.Address

	return req, nil
}

type AddrSpec struct {
	IP      []byte
	Port    uint16
	Address string
}

func readAddrSpec(conn io.ReadWriter, addrType uint8) (*AddrSpec, error) {
	spec := &AddrSpec{}

	switch addrType {
	case atypeIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, fmt.Errorf("failed to read IPv4 address: %w", err)
		}
		spec.IP = addr
		spec.Address = net.IP(addr).String()

	case atypeIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, fmt.Errorf("failed to read IPv6 address: %w", err)
		}
		spec.IP = addr
		spec.Address = net.IP(addr).String()

	case atypeDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, fmt.Errorf("failed to read domain length: %w", err)
		}

		domainLen := int(lenBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, fmt.Errorf("failed to read domain: %w", err)
		}

		spec.IP = domain
		spec.Address = string(domain)

	default:
		return nil, fmt.Errorf("unsupported address type: %d", addrType)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, fmt.Errorf("failed to read port: %w", err)
	}

	spec.Port = uint16(portBuf[0])<<8 | uint16(portBuf[1])
	spec.Address = net.JoinHostPort(spec.Address, strconv.Itoa(int(spec.Port)))

	return spec, nil
}