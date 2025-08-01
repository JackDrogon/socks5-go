#!/bin/bash

# SOCKS5 Performance Benchmark
# Tests performance characteristics of the SOCKS5 server

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

BINARY="../go-socks5"

echo -e "${YELLOW}SOCKS5 Performance Benchmark${NC}"
echo "=================================="

cleanup() {
	pkill -f "$BINARY" 2>/dev/null || true
	sleep 1
}

trap cleanup EXIT

echo -e "\n${YELLOW}Starting benchmark server...${NC}"
$BINARY -addr :3080 >benchmark.log 2>&1 &
sleep 3

echo -e "\n${YELLOW}Test 1: Sequential Requests${NC}"
echo "Measuring time for 10 sequential requests..."

start_time=$(date +%s.%N)
for i in {1..10}; do
	curl --socks5-hostname localhost:3080 https://httpbin.org/ip --connect-timeout 10 -s >/dev/null
	echo -n "."
done
end_time=$(date +%s.%N)

sequential_time=$(echo "$end_time - $start_time" | bc -l)
echo
echo -e "${GREEN}Sequential time:${NC} ${sequential_time}s (avg: $(echo "scale=3; $sequential_time/10" | bc -l)s per request)"

echo -e "\n${YELLOW}Test 2: Concurrent Requests${NC}"
echo "Measuring time for 10 concurrent requests..."

start_time=$(date +%s.%N)
for i in {1..10}; do
	curl --socks5-hostname localhost:3080 https://httpbin.org/ip --connect-timeout 15 -s >/dev/null &
done
wait
end_time=$(date +%s.%N)

concurrent_time=$(echo "$end_time - $start_time" | bc -l)
echo -e "${GREEN}Concurrent time:${NC} ${concurrent_time}s"

# Calculate speedup
speedup=$(echo "scale=2; $sequential_time / $concurrent_time" | bc -l)
echo -e "${GREEN}Speedup:${NC} ${speedup}x"

echo -e "\n${YELLOW}Test 3: Connection Reuse${NC}"
echo "Testing persistent connections..."

start_time=$(date +%s.%N)
for i in {1..5}; do
	curl --socks5-hostname localhost:3080 https://httpbin.org/get --connect-timeout 10 -s >/dev/null
done
end_time=$(date +%s.%N)

reuse_time=$(echo "$end_time - $start_time" | bc -l)
echo -e "${GREEN}Connection reuse time:${NC} ${reuse_time}s (avg: $(echo "scale=3; $reuse_time/5" | bc -l)s per request)"

echo -e "\n${YELLOW}Test 4: Large Data Transfer${NC}"
echo "Testing large data transfer through proxy..."

start_time=$(date +%s.%N)
curl --socks5-hostname localhost:3080 https://httpbin.org/bytes/1024 --connect-timeout 15 -s >/dev/null
end_time=$(date +%s.%N)

transfer_time=$(echo "$end_time - $start_time" | bc -l)
echo -e "${GREEN}Large transfer time:${NC} ${transfer_time}s"

echo -e "\n${YELLOW}Test 5: Authentication Overhead${NC}"
cleanup
$BINARY -addr :3081 -user bench -pass test >benchmark_auth.log 2>&1 &
sleep 2

echo "Testing authentication overhead..."
start_time=$(date +%s.%N)
for i in {1..5}; do
	curl --socks5 bench:test@localhost:3081 https://httpbin.org/ip --connect-timeout 10 -s >/dev/null
done
end_time=$(date +%s.%N)

auth_time=$(echo "$end_time - $start_time" | bc -l)
echo -e "${GREEN}Auth overhead:${NC} ${auth_time}s (avg: $(echo "scale=3; $auth_time/5" | bc -l)s per request)"

cleanup

echo -e "\n${GREEN}Benchmark Summary${NC}"
echo "=================================="
echo -e "Sequential (10 requests): ${sequential_time}s"
echo -e "Concurrent (10 requests): ${concurrent_time}s (${speedup}x speedup)"
echo -e "With authentication (5 requests): ${auth_time}s"
echo -e "Large transfer: ${transfer_time}s"

# Check for any errors
ERROR_COUNT=$(grep -c "error\|Error\|ERROR" benchmark*.log 2>/dev/null || echo "0")
if [ "$ERROR_COUNT" -eq 0 ]; then
	echo -e "\n${GREEN}✓ No errors during benchmark${NC}"
else
	echo -e "\n${YELLOW}⚠ Found $ERROR_COUNT errors in logs${NC}"
fi

echo -e "\n${GREEN}Benchmark completed!${NC}"
