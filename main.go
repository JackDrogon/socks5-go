package main

import (
	"flag"
	"log"
	"net"

	"github.com/go-socks5/socks5"
)

func main() {
	var (
		addr     = flag.String("addr", ":1080", "SOCKS5 server address")
		username = flag.String("user", "", "Username for authentication (optional)")
		password = flag.String("pass", "", "Password for authentication (optional)")
	)
	flag.Parse()

	config := &socks5.Config{}

	if *username != "" && *password != "" {
		credentials := socks5.StaticCredentials{
			*username: *password,
		}
		authenticator := socks5.UserPassAuthenticator{Credentials: credentials}
		config.AuthMethods = []socks5.Authenticator{authenticator}
	}

	server, err := socks5.New(config)
	if err != nil {
		log.Fatalf("Failed to create SOCKS5 server: %v", err)
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *addr, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 server listening on %s", *addr)

	if err := server.Serve(listener); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
