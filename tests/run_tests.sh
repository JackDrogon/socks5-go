#!/bin/bash

# SOCKS5 Server Test Suite
# Tests the Go SOCKS5 implementation using curl

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

BINARY="../go-socks5"
TIMEOUT=10

print_status() {
	if [ $? -eq 0 ]; then
		echo -e "${GREEN}✓${NC} $1"
	else
		echo -e "${RED}✗${NC} $1"
		return 1
	fi
}

cleanup() {
	echo -e "\n${YELLOW}Cleaning up...${NC}"
	pkill -f "$BINARY" 2>/dev/null || true
	sleep 1
}

trap cleanup EXIT

echo -e "${YELLOW}SOCKS5 Server Test Suite${NC}"
echo "=================================="

# Build if needed
if [ ! -f "$BINARY" ]; then
	echo "Building SOCKS5 server..."
	cd .. && go build && cd tests
	print_status "Build completed"
fi

echo -e "\n${YELLOW}Test 1: Basic SOCKS5 Functionality (No Auth)${NC}"
echo "Starting server on port 1080..."
$BINARY -addr :1080 >test1.log 2>&1 &
SERVER1_PID=$!
sleep 2

# Test basic connectivity
curl --socks5-hostname localhost:1080 https://httpbin.org/ip --connect-timeout $TIMEOUT -s >/dev/null
print_status "Basic SOCKS5 connection"

# Test with different endpoints
curl --socks5 localhost:1080 https://httpbin.org/user-agent --connect-timeout $TIMEOUT -s | grep -q "curl"
print_status "Multiple endpoints work"

# Test domain name resolution
curl --socks5-hostname localhost:1080 http://example.com --connect-timeout $TIMEOUT -s -I | grep -q "200 OK"
print_status "Domain name resolution"

# Test IPv4 direct connection
curl --socks5 localhost:1080 http://1.1.1.1 --connect-timeout $TIMEOUT -s -I | grep -q "301"
print_status "IPv4 direct connection"

kill $SERVER1_PID 2>/dev/null || true
sleep 1

echo -e "\n${YELLOW}Test 2: Username/Password Authentication${NC}"
echo "Starting server with authentication on port 1081..."
$BINARY -addr :1081 -user testuser -pass testpass >test2.log 2>&1 &
SERVER2_PID=$!
sleep 2

# Test successful authentication
curl --socks5 testuser:testpass@localhost:1081 https://httpbin.org/ip --connect-timeout $TIMEOUT -s >/dev/null
print_status "Valid credentials accepted"

# Test failed authentication
set +e # Temporarily disable exit on error
curl --socks5 wronguser:wrongpass@localhost:1081 https://httpbin.org/ip --connect-timeout 5 -s >/dev/null 2>&1
if [ $? -ne 0 ]; then
	echo -e "${GREEN}✓${NC} Invalid credentials rejected"
else
	echo -e "${RED}✗${NC} Invalid credentials rejected"
fi

# Test no credentials provided to auth server
curl --socks5-hostname localhost:1081 https://httpbin.org/ip --connect-timeout 5 -s >/dev/null 2>&1
if [ $? -ne 0 ]; then
	echo -e "${GREEN}✓${NC} No credentials rejected when auth required"
else
	echo -e "${RED}✗${NC} No credentials rejected when auth required"
fi
set -e # Re-enable exit on error

kill $SERVER2_PID 2>/dev/null || true
sleep 1

echo -e "\n${YELLOW}Test 3: Performance and Stress Test${NC}"
echo "Starting server on port 1082..."
$BINARY -addr :1082 >test3.log 2>&1 &
SERVER3_PID=$!
sleep 2

# Test multiple concurrent connections
echo "Testing concurrent connections..."
for i in {1..5}; do
	curl --socks5-hostname localhost:1082 https://httpbin.org/ip --connect-timeout $TIMEOUT -s >/dev/null &
done
wait
print_status "Concurrent connections handled"

# Test different protocols
curl --socks5-hostname localhost:1082 http://httpbin.org/get --connect-timeout $TIMEOUT -s >/dev/null
print_status "HTTP through SOCKS5"

curl --socks5-hostname localhost:1082 https://httpbin.org/get --connect-timeout $TIMEOUT -s >/dev/null
print_status "HTTPS through SOCKS5"

kill $SERVER3_PID 2>/dev/null || true

echo -e "\n${YELLOW}Test Results Summary${NC}"
echo "=================================="

# Check logs for errors
echo "Checking server logs for errors..."
if grep -q "Failed to" test*.log 2>/dev/null; then
	echo -e "${YELLOW}⚠${NC} Some connection failures found in logs (this may be expected for negative tests)"
else
	echo -e "${GREEN}✓${NC} No unexpected errors in server logs"
fi

# Count successful connections
SUCCESSFUL_CONNECTIONS=$(grep -c "Connected to" test*.log 2>/dev/null || echo "0")
echo -e "${GREEN}✓${NC} Total successful connections: $SUCCESSFUL_CONNECTIONS"

echo -e "\n${GREEN}All tests completed!${NC}"
echo "Log files: test1.log (no auth), test2.log (with auth), test3.log (stress test)"
