#!/bin/bash

# RFC 1928 Connection Methods Test
# Tests SOCKS5 connection methods (CONNECT, BIND, UDP ASSOCIATE) as specified in RFC 1928
# Priority: P0 curl, P1 socat, P2 echo+nc

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SERVER_BINARY="$ROOT_DIR/go-socks5"
PID_FILE="$SCRIPT_DIR/socks5_server.pid"
LOG_FILE="$SCRIPT_DIR/socks5_server.log"

# Test configuration
TEST_PORT=1080
TEST_TARGET="httpbin.org"
TEST_TARGET_PORT=80
TEST_URL="http://$TEST_TARGET:$TEST_TARGET_PORT/get"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test result counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Server control functions
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

# Start server with specified configuration
start_server() {
	local port=${1:-1080}
	local auth=${2:-"noauth"}

	# Check if server is already running
	if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
		warn "Server already running with PID $(cat "$PID_FILE")"
		return 0
	fi

	log "Starting SOCKS5 server on port $port with auth: $auth"

	# Build command line arguments
	local cmd_args="-addr :$port"

	if [[ "$auth" == "userpass" ]]; then
		cmd_args="$cmd_args -user testuser -pass testpass"
	fi

	# Start server in background
	cd "$ROOT_DIR"
	nohup "$SERVER_BINARY" $cmd_args >"$LOG_FILE" 2>&1 &
	local server_pid=$!

	# Save PID
	echo "$server_pid" >"$PID_FILE"

	# Wait for server to start and verify it's listening
	sleep 2

	# Wait up to 10 seconds for server to be ready
	local wait_count=0
	while [[ $wait_count -lt 10 ]]; do
		if nc -z 127.0.0.1 "$port" 2>/dev/null; then
			break
		fi
		sleep 1
		wait_count=$((wait_count + 1))
	done

	# Verify server is running and listening
	if ! kill -0 "$server_pid" 2>/dev/null; then
		error "Server process died"
		cat "$LOG_FILE"
		rm -f "$PID_FILE"
		return 1
	fi

	if ! nc -z 127.0.0.1 "$port" 2>/dev/null; then
		error "Server not listening on port $port"
		cat "$LOG_FILE"
		kill "$server_pid" 2>/dev/null
		rm -f "$PID_FILE"
		return 1
	fi

	log "Server started with PID: $server_pid"
	return 0
}

# Stop server
stop_server() {
	if [[ -f "$PID_FILE" ]]; then
		local pid=$(cat "$PID_FILE")
		if kill -0 "$pid" 2>/dev/null; then
			log "Stopping server with PID: $pid"
			kill "$pid"

			# Wait for graceful shutdown
			local count=0
			while kill -0 "$pid" 2>/dev/null && [[ $count -lt 10 ]]; do
				sleep 1
				count=$((count + 1))
			done

			# Force kill if still running
			if kill -0 "$pid" 2>/dev/null; then
				warn "Force killing server"
				kill -9 "$pid"
			fi

			log "Server stopped"
		else
			warn "Server PID $pid not running"
		fi
		rm -f "$PID_FILE"
	else
		warn "No PID file found"
	fi
}

# Check if server is running
status_server() {
	if [[ -f "$PID_FILE" ]]; then
		local pid=$(cat "$PID_FILE")
		if kill -0 "$pid" 2>/dev/null; then
			return 0
		else
			warn "PID file exists but server not running"
			rm -f "$PID_FILE"
			return 1
		fi
	else
		return 1
	fi
}

# Cleanup function for trap
cleanup() {
	log "Cleaning up..."
	stop_server
}

# Set trap for cleanup on script exit
trap cleanup EXIT INT TERM

# P0: Test CONNECT method with curl
test_connect_method() {
	local description="$1"
	local target_url="$2"
	local expect_success="$3"
	local timeout="${4:-15}"

	log_test "$description"

	local output_file=$(mktemp)
	local error_file=$(mktemp)

	# Run curl with SOCKS5 proxy for CONNECT method
	if timeout "$timeout" curl -s -f --socks5 "127.0.0.1:$TEST_PORT" "$target_url" >"$output_file" 2>"$error_file"; then
		local curl_result=0
	else
		local curl_result=$?
	fi

	if [[ "$expect_success" == "true" ]]; then
		if [[ $curl_result -eq 0 ]]; then
			# Verify we got a valid response
			if [[ -s "$output_file" ]]; then
				pass_test "$description"
			else
				fail_test "$description - Empty response received"
			fi
		else
			fail_test "$description - Connection failed (exit code: $curl_result)"
			echo "Error: $(cat "$error_file")"
		fi
	else
		if [[ $curl_result -ne 0 ]]; then
			pass_test "$description - Failed as expected"
		else
			fail_test "$description - Should have failed but succeeded"
		fi
	fi

	rm -f "$output_file" "$error_file"
}

# P1: Test protocol-level CONNECT with socat
test_socat_connect() {
	local description="$1"
	local target_host="$2"
	local target_port="$3"
	local expect_success="$4"

	log_test "$description"

	if ! command -v socat >/dev/null 2>&1; then
		warn "socat not available, skipping P1 test: $description"
		return 0
	fi

	# Test simplified: just check if we can establish a connection and get method selection
	# This tests the basic protocol capability without getting into complex multi-step negotiations
	local version_nego=$(printf '\x05\x01\x00')
	local response=$(printf '%s' "$version_nego" | timeout 5 socat - TCP:127.0.0.1:$TEST_PORT 2>/dev/null | xxd -p || echo "failed")

	if [[ "$expect_success" == "true" ]]; then
		if [[ "$response" == "failed" ]]; then
			fail_test "$description - Connection failed"
		elif [[ "$response" =~ ^0500.* ]]; then
			# Version negotiation successful (Version 5, Method 0)
			pass_test "$description - Protocol negotiation successful"
		else
			fail_test "$description - Unexpected response: $response"
		fi
	else
		if [[ "$response" == "failed" ]] || [[ "$response" == "05ff" ]]; then
			pass_test "$description - Failed as expected"
		else
			fail_test "$description - Should have failed but got: $response"
		fi
	fi
}

# P2: Test boundary conditions for connection methods
test_connection_boundary() {
	local description="$1"
	local test_data="$2"
	local expected_log_pattern="$3"

	log_test "$description"

	if ! command -v nc >/dev/null 2>&1; then
		warn "nc (netcat) not available, skipping P2 test: $description"
		return 0
	fi

	# Clear previous log entries by remembering current line count
	local log_lines_before=0
	if [[ -f "$LOG_FILE" ]]; then
		log_lines_before=$(wc -l <"$LOG_FILE")
	fi

	# Send test data and close connection
	echo -ne "$test_data" | timeout 5 nc 127.0.0.1 $TEST_PORT >/dev/null 2>&1 || true

	# Wait a moment for server to process and log
	sleep 1

	# Check if expected pattern appears in new log entries
	if [[ -f "$LOG_FILE" ]]; then
		local new_logs=$(tail -n +$((log_lines_before + 1)) "$LOG_FILE")
		if echo "$new_logs" | grep -q "$expected_log_pattern"; then
			pass_test "$description - Server correctly handled boundary condition"
		else
			fail_test "$description - Expected log pattern not found: $expected_log_pattern"
			echo "New log entries: $new_logs"
		fi
	else
		fail_test "$description - No log file found"
	fi
}

# RFC 1928 Section 4: Connection Methods
echo "=== RFC 1928 Connection Methods Test ==="
echo ""

# Start server for connection method tests
stop_server
start_server $TEST_PORT "noauth"

if ! status_server; then
	error "Failed to start server for connection method tests"
	exit 1
fi

# Test 1: CONNECT Method (RFC 1928 Section 4, Command 0x01)
echo "--- Testing CONNECT Method (RFC 1928 Section 4, Command 0x01) ---"

# P0: Basic CONNECT tests with curl (which uses CONNECT method)
test_connect_method "CONNECT - HTTP to httpbin.org" "$TEST_URL" "true"
test_connect_method "CONNECT - HTTPS to httpbin.org" "https://httpbin.org/get" "true" 20
test_connect_method "CONNECT - Different endpoint" "http://httpbin.org/status/200" "true"

# P0: Test CONNECT to different address types
test_connect_method "CONNECT - IPv4 target" "http://1.1.1.1/" "true" 10
test_connect_method "CONNECT - Domain with custom port" "http://example.com:80/" "true" 15

# P0: Test CONNECT failures
test_connect_method "CONNECT - Unreachable host" "http://192.0.2.1:80/" "false" 10
test_connect_method "CONNECT - Invalid domain" "http://nonexistent.invalid.domain.test/" "false" 10

# P1: Protocol-level CONNECT tests with socat (simplified to test basic protocol)
test_socat_connect "CONNECT Protocol - Basic negotiation test" "example.com" 80 "true"

stop_server

# Test 2: Protocol boundary conditions for connection methods
echo ""
echo "--- Testing Connection Method Boundary Conditions ---"
start_server $TEST_PORT "noauth"

if status_server; then
	# P2: Test unsupported command types
	# Format: Version + Auth nego + Version + CMD + RSV + ATYP + ADDR + PORT
	test_connection_boundary "Protocol - Invalid command 0x99" \
		'\x05\x01\x00\x05\x99\x00\x01\x7f\x00\x00\x01\x00\x50' \
		"unsupported command"

	# P2: Test BIND command
	test_connection_boundary "Protocol - BIND command" \
		'\x05\x01\x00\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x50' \
		"BIND request"

	# P2: Test UDP ASSOCIATE command
	test_connection_boundary "Protocol - UDP ASSOCIATE command" \
		'\x05\x01\x00\x05\x03\x00\x01\x7f\x00\x00\x01\x00\x50' \
		"UDP ASSOCIATE request"

	# P2: Test invalid reserved field in request
	test_connection_boundary "Protocol - Invalid reserved field" \
		'\x05\x01\x00\x05\x01\x01\x01\x7f\x00\x00\x01\x00\x50' \
		"invalid reserved field"

	# P2: Test invalid address type
	test_connection_boundary "Protocol - Invalid address type" \
		'\x05\x01\x00\x05\x01\x00\x99\x7f\x00\x00\x01\x00\x50' \
		"unsupported address type"
fi

stop_server

echo ""
echo "=== Test Summary ==="
echo "Tests Run: $TESTS_RUN"
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"

if [[ $TESTS_FAILED -eq 0 ]]; then
	echo -e "${GREEN}All connection method tests passed!${NC}"
	exit 0
else
	echo -e "${RED}Some connection method tests failed!${NC}"
	exit 1
fi
