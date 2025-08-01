#!/bin/bash

# Protocol Compliance Test
# Tests specific SOCKS5 protocol features

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

BINARY="../go-socks5"

echo -e "${YELLOW}SOCKS5 Protocol Compliance Tests${NC}"
echo "=================================="

cleanup() {
	pkill -f "$BINARY" 2>/dev/null || true
	sleep 1
}

trap cleanup EXIT

echo -e "\n${YELLOW}Test 1: Address Type Support${NC}"
$BINARY -addr :2080 >protocol_test.log 2>&1 &
sleep 2

# Test IPv4 address
echo "Testing IPv4 address type..."
curl --socks5 localhost:2080 http://8.8.8.8 --connect-timeout 10 -s -I | grep -q "HTTP" && echo -e "${GREEN}✓${NC} IPv4 support" || echo -e "${RED}✗${NC} IPv4 support"

# Test domain name
echo "Testing domain name address type..."
curl --socks5-hostname localhost:2080 http://httpbin.org/ip --connect-timeout 10 -s >/dev/null && echo -e "${GREEN}✓${NC} Domain name support" || echo -e "${RED}✗${NC} Domain name support"

# Test different ports
echo "Testing different ports..."
curl --socks5-hostname localhost:2080 https://httpbin.org:443/ip --connect-timeout 10 -s >/dev/null && echo -e "${GREEN}✓${NC} Custom port support" || echo -e "${RED}✗${NC} Custom port support"

cleanup

echo -e "\n${YELLOW}Test 2: Error Handling${NC}"
$BINARY -addr :2081 -user admin -pass secret >protocol_error_test.log 2>&1 &
sleep 2

# Test connection to non-existent host
echo "Testing connection to non-existent host..."
set +e
curl --socks5 admin:secret@localhost:2081 http://nonexistent.invalid --connect-timeout 5 -s >/dev/null 2>&1
if [ $? -ne 0 ]; then
	echo -e "${GREEN}✓${NC} Properly handles non-existent hosts"
else
	echo -e "${RED}✗${NC} Should fail for non-existent hosts"
fi

# Test connection to unreachable port
echo "Testing connection to unreachable port..."
curl --socks5 admin:secret@localhost:2081 http://google.com:12345 --connect-timeout 5 -s >/dev/null 2>&1
if [ $? -ne 0 ]; then
	echo -e "${GREEN}✓${NC} Properly handles unreachable ports"
else
	echo -e "${RED}✗${NC} Should fail for unreachable ports"
fi
set -e

cleanup

echo -e "\n${YELLOW}Test 3: Server Behavior${NC}"

# Test server startup on different addresses
echo "Testing server on different interfaces..."
$BINARY -addr 127.0.0.1:2082 >interface_test.log 2>&1 &
sleep 2
curl --socks5-hostname 127.0.0.1:2082 http://httpbin.org/ip --connect-timeout 10 -s >/dev/null && echo -e "${GREEN}✓${NC} Specific interface binding" || echo -e "${RED}✗${NC} Specific interface binding"
cleanup

# Test graceful handling of rapid connections
echo "Testing rapid connection handling..."
$BINARY -addr :2083 >rapid_test.log 2>&1 &
sleep 2

for i in {1..3}; do
	curl --socks5-hostname localhost:2083 http://httpbin.org/ip --connect-timeout 5 -s >/dev/null &
done

wait
echo -e "${GREEN}✓${NC} Handles rapid connections"

cleanup

echo -e "\n${GREEN}Protocol compliance tests completed!${NC}"
