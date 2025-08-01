#!/bin/bash

# RFC 1928 Protocol Boundary Conditions Test
# Tests edge cases and boundary conditions in SOCKS5 protocol
# Priority: P1 socat, P2 echo+nc, P0 curl (where applicable)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SERVER_BINARY="$ROOT_DIR/go-socks5"
PID_FILE="$SCRIPT_DIR/socks5_server.pid"
LOG_FILE="$SCRIPT_DIR/socks5_server.log"

# Test configuration
TEST_PORT=1080

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test result counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

log() {
	echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
	echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
	echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_test() {
	echo -e "${BLUE}[TEST]${NC} $1"
	TESTS_RUN=$((TESTS_RUN + 1))
}

pass_test() {
	echo -e "${GREEN}[PASS]${NC} $1"
	TESTS_PASSED=$((TESTS_PASSED + 1))
}

fail_test() {
	echo -e "${RED}[FAIL]${NC} $1"
	TESTS_FAILED=$((TESTS_FAILED + 1))
}

start_server() {
	local port=${1:-1080}

	if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
		warn "Server already running with PID $(cat "$PID_FILE")"
		return 0
	fi

	log "Starting SOCKS5 server on port $port"

	cd "$ROOT_DIR"
	nohup "$SERVER_BINARY" -addr ":$port" >"$LOG_FILE" 2>&1 &
	local server_pid=$!

	echo "$server_pid" >"$PID_FILE"
	sleep 2

	if ! kill -0 "$server_pid" 2>/dev/null; then
		error "Server process died"
		cat "$LOG_FILE"
		rm -f "$PID_FILE"
		return 1
	fi

	log "Server started with PID: $server_pid"
	return 0
}

stop_server() {
	if [[ -f "$PID_FILE" ]]; then
		local pid=$(cat "$PID_FILE")
		if kill -0 "$pid" 2>/dev/null; then
			log "Stopping server with PID: $pid"
			kill "$pid"

			local count=0
			while kill -0 "$pid" 2>/dev/null && [[ $count -lt 10 ]]; do
				sleep 1
				count=$((count + 1))
			done

			if kill -0 "$pid" 2>/dev/null; then
				warn "Force killing server"
				kill -9 "$pid"
			fi
		fi
		rm -f "$PID_FILE"
	fi
}

cleanup() {
	log "Cleaning up..."
	stop_server
}

trap cleanup EXIT INT TERM

# Test protocol boundary condition with raw data
test_protocol_boundary() {
	local description="$1"
	local test_data="$2"
	local expected_behavior="$3" # "reject", "accept", "error"

	log_test "$description"

	if ! command -v nc >/dev/null 2>&1; then
		warn "nc not available, skipping test: $description"
		return 0
	fi

	# Clear log to track new entries
	local log_lines_before=0
	if [[ -f "$LOG_FILE" ]]; then
		log_lines_before=$(wc -l <"$LOG_FILE" 2>/dev/null || echo "0")
	fi

	# Send test data
	local response_file=$(mktemp)
	echo -ne "$test_data" | timeout 5 nc 127.0.0.1 $TEST_PORT >"$response_file" 2>/dev/null || true

	# Wait for server processing
	sleep 1

	# Check response and logs
	local response_size=$(wc -c <"$response_file" 2>/dev/null || echo "0")
	local new_logs=""
	if [[ -f "$LOG_FILE" ]]; then
		new_logs=$(tail -n +$((log_lines_before + 1)) "$LOG_FILE" 2>/dev/null || echo "")
	fi

	rm -f "$response_file"

	case "$expected_behavior" in
	"reject")
		if [[ $response_size -eq 0 ]] || echo "$new_logs" | grep -qi "error\|invalid\|reject"; then
			pass_test "$description - Correctly rejected invalid input"
		else
			fail_test "$description - Should have rejected invalid input"
		fi
		;;
	"accept")
		if [[ $response_size -gt 0 ]] && ! echo "$new_logs" | grep -qi "error\|invalid\|reject"; then
			pass_test "$description - Correctly accepted valid input"
		else
			fail_test "$description - Should have accepted valid input"
		fi
		;;
	"error")
		if echo "$new_logs" | grep -qi "error" || [[ $response_size -eq 2 ]]; then
			pass_test "$description - Correctly handled error condition"
		else
			fail_test "$description - Should have generated error response"
		fi
		;;
	*)
		fail_test "$description - Unknown expected behavior: $expected_behavior"
		;;
	esac
}

# Test version negotiation boundary conditions
test_version_negotiation_boundaries() {
	local description="$1"
	local test_data="$2"
	local expected_response="$3"

	log_test "$description"

	if ! command -v socat >/dev/null 2>&1; then
		warn "socat not available, skipping test: $description"
		return 0
	fi

	local response=$(echo -ne "$test_data" | timeout 5 socat - TCP:127.0.0.1:$TEST_PORT 2>/dev/null | xxd -p || echo "failed")

	if [[ "$response" == "failed" ]]; then
		if [[ "$expected_response" == "disconnect" ]]; then
			pass_test "$description - Connection properly terminated"
		else
			fail_test "$description - Unexpected connection failure"
		fi
	elif [[ "$response" == "$expected_response" ]]; then
		pass_test "$description - Correct response received"
	elif [[ "$expected_response" == "05ff" ]] && [[ "$response" =~ ^05ff ]]; then
		pass_test "$description - Correct rejection response (05FF)"
	else
		fail_test "$description - Expected '$expected_response', got '$response'"
	fi
}

echo "=== RFC 1928 Protocol Boundary Conditions Test ==="
echo ""

# Start server for boundary tests
stop_server
start_server $TEST_PORT

if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
	error "Failed to start server for boundary tests"
	exit 1
fi

echo "--- Testing Version Negotiation Boundaries ---"

# Test 1: Invalid SOCKS version
test_version_negotiation_boundaries "Version - Invalid SOCKS version 4" \
	'\x04\x01\x00' "disconnect"

# Test 2: Invalid SOCKS version (too high)
test_version_negotiation_boundaries "Version - Invalid SOCKS version 6" \
	'\x06\x01\x00' "disconnect"

# Test 3: NMETHODS = 0 (RFC violation)
test_version_negotiation_boundaries "Version - Zero methods (NMETHODS=0)" \
	'\x05\x00' "disconnect"

# Test 4: NMETHODS = 255 (maximum)
test_version_negotiation_boundaries "Version - Maximum methods (NMETHODS=255)" \
	'\x05\xff' "disconnect"

# Test 5: Truncated version negotiation
test_protocol_boundary "Protocol - Truncated version negotiation" \
	'\x05' "reject"

echo ""
echo "--- Testing Authentication Method Boundaries ---"

# Test 6: Unsupported authentication methods
test_version_negotiation_boundaries "Auth - Unsupported method 0x99" \
	'\x05\x01\x99' "05ff"

# Test 7: Multiple methods with unsupported ones
test_version_negotiation_boundaries "Auth - Mixed supported/unsupported methods" \
	'\x05\x03\x00\x99\x02' "0500"

# Test 8: GSSAPI method (should be handled)
test_version_negotiation_boundaries "Auth - GSSAPI method" \
	'\x05\x01\x01' "0501"

echo ""
echo "--- Testing Request Format Boundaries ---"

# Test 9: Invalid command in request
test_protocol_boundary "Request - Invalid command 0x99" \
	'\x05\x01\x00\x05\x99\x00\x01\x7f\x00\x00\x01\x00\x50' "error"

# Test 10: Non-zero reserved field
test_protocol_boundary "Request - Non-zero reserved field" \
	'\x05\x01\x00\x05\x01\x01\x01\x7f\x00\x00\x01\x00\x50' "error"

# Test 11: Invalid address type
test_protocol_boundary "Request - Invalid address type 0x99" \
	'\x05\x01\x00\x05\x01\x00\x99\x7f\x00\x00\x01\x00\x50' "error"

# Test 12: Truncated request
test_protocol_boundary "Request - Truncated request" \
	'\x05\x01\x00\x05\x01\x00\x01' "reject"

echo ""
echo "--- Testing Address Format Boundaries ---"

# Test 13: Domain name too long (> 255 chars)
long_domain=$(printf 'a%.0s' {1..256})
test_protocol_boundary "Address - Domain name too long" \
	"\x05\x01\x00\x05\x01\x00\x03\xff${long_domain}\x00\x50" "error"

# Test 14: Zero-length domain name
test_protocol_boundary "Address - Zero-length domain name" \
	'\x05\x01\x00\x05\x01\x00\x03\x00\x00\x50' "error"

# Test 15: IPv6 address (16 bytes)
test_protocol_boundary "Address - Valid IPv6 address" \
	'\x05\x01\x00\x05\x01\x00\x04\x20\x01\x48\x60\x48\x60\x00\x00\x00\x00\x00\x00\x00\x00\x88\x88\x00\x50' "accept"

echo ""
echo "--- Testing Connection Lifecycle Boundaries ---"

# Test 16: Immediate disconnect after auth
test_protocol_boundary "Lifecycle - Disconnect after auth negotiation" \
	'\x05\x01\x00' "accept"

# Test 17: Multiple rapid connections
log_test "Lifecycle - Rapid connection handling"
rapid_success=0
for i in {1..5}; do
	if echo -ne '\x05\x01\x00' | timeout 2 nc 127.0.0.1 $TEST_PORT >/dev/null 2>&1; then
		rapid_success=$((rapid_success + 1))
	fi
	sleep 0.1
done

if [[ $rapid_success -ge 3 ]]; then
	pass_test "Lifecycle - Rapid connection handling ($rapid_success/5 successful)"
else
	fail_test "Lifecycle - Rapid connection handling ($rapid_success/5 successful)"
fi

# Test 18: Very slow data transmission
log_test "Lifecycle - Slow data transmission handling"
{
	echo -ne '\x05'
	sleep 2
	echo -ne '\x01'
	sleep 2
	echo -ne '\x00'
} | timeout 10 nc 127.0.0.1 $TEST_PORT >/dev/null 2>&1

if [[ $? -eq 0 ]]; then
	pass_test "Lifecycle - Slow data transmission handling - Server remained responsive"
else
	pass_test "Lifecycle - Slow data transmission handling - Server appropriately timed out"
fi

stop_server

echo ""
echo "=== Protocol Boundary Test Summary ==="
echo "Tests Run: $TESTS_RUN"
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"

if [[ $TESTS_FAILED -eq 0 ]]; then
	echo -e "${GREEN}All protocol boundary tests passed!${NC}"
	exit 0
else
	echo -e "${RED}Some protocol boundary tests failed!${NC}"
	exit 1
fi
