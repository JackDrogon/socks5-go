#!/bin/bash

# RFC 1928 Authentication Methods Test
# Tests SOCKS5 authentication methods as specified in RFC 1928
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
	local cmd_args=""

	case "$auth" in
	"noauth")
		cmd_args="-addr :$port"
		;;
	"userpass")
		cmd_args="-addr :$port -user testuser -pass testpass"
		;;
	*)
		error "Unknown auth method: $auth"
		exit 1
		;;
	esac

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

# P0: Test with curl SOCKS5 functionality
test_curl_socks5() {
	local description="$1"
	local socks_proxy="$2"
	local expect_success="$3"
	local timeout="${4:-10}"
	local test_url="${5:-$TEST_URL}"

	log_test "$description"

	local output_file=$(mktemp)
	local error_file=$(mktemp)

	# Run curl with SOCKS5 proxy
	if timeout "$timeout" curl -s -f --socks5 "$socks_proxy" "$test_url" >"$output_file" 2>"$error_file"; then
		local curl_result=0
	else
		local curl_result=$?
	fi

	if [[ "$expect_success" == "true" ]]; then
		if [[ $curl_result -eq 0 ]]; then
			# Verify we got a valid JSON response from httpbin
			if grep -q '"url"' "$output_file"; then
				pass_test "$description"
			else
				fail_test "$description - Invalid response received"
				echo "Response: $(head -3 "$output_file")"
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

# P1: Test with socat for more detailed protocol testing
test_socat_socks5() {
	local description="$1"
	local test_type="$2"

	log_test "$description"

	if ! command -v socat >/dev/null 2>&1; then
		warn "socat not available, skipping P1 test: $description"
		return 0
	fi

	case "$test_type" in
	"version_negotiation")
		# Test proper SOCKS5 version negotiation
		# Send: Version(5) + NMETHODS(1) + METHOD(0-no auth)
		local response=$(echo -ne '\x05\x01\x00' | timeout 5 socat - TCP:127.0.0.1:$TEST_PORT 2>/dev/null | xxd -p || echo "failed")
		# Expected response starts with: Version(5) + METHOD(0-no auth) = 0500
		if [[ "$response" == "failed" ]]; then
			fail_test "$description - Connection failed"
		elif [[ "$response" =~ ^0500.* ]]; then
			pass_test "$description - Correct version negotiation (response: ${response:0:4})"
		else
			fail_test "$description - Unexpected response: $response"
		fi
		;;
	"userpass_negotiation")
		# Test username/password negotiation
		# Send: Version(5) + NMETHODS(1) + METHOD(2-userpass)
		local response=$(echo -ne '\x05\x01\x02' | timeout 5 socat - TCP:127.0.0.1:$TEST_PORT 2>/dev/null | xxd -p || echo "failed")
		# Expected response: Version(5) + METHOD(2-userpass)
		if [[ "$response" == "0502" ]]; then
			pass_test "$description - Correct userpass negotiation"
		elif [[ "$response" == "failed" ]]; then
			fail_test "$description - Connection failed"
		else
			fail_test "$description - Unexpected response: $response"
		fi
		;;
	*)
		fail_test "$description - Unknown test type: $test_type"
		;;
	esac
}

# P2: Test edge cases with echo + nc (only for boundary conditions)
test_boundary_condition() {
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
	echo -ne "$test_data" | timeout 2 nc 127.0.0.1 $TEST_PORT >/dev/null 2>&1 || true

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

# RFC 1928 Section 3: Authentication Methods
echo "=== RFC 1928 Authentication Methods Test ==="
echo ""

# Test 1: No Authentication Required (Method 0x00)
echo "--- Testing No Authentication (RFC 1928 Section 3, Method 0x00) ---"
stop_server
start_server $TEST_PORT "noauth"

if status_server; then
	# P0: Basic connectivity test with curl
	test_curl_socks5 "No Auth - Basic HTTP request" "127.0.0.1:$TEST_PORT" "true"

	# P0: Test different target ports
	test_curl_socks5 "No Auth - HTTPS request" "127.0.0.1:$TEST_PORT" "true" 15 "https://httpbin.org/get"

	# P0: Concurrent connections test
	log_test "No Auth - Concurrent connections"
	pids=()
	for i in {1..3}; do
		(curl -s -f --connect-timeout 10 --socks5 127.0.0.1:$TEST_PORT "$TEST_URL" >/tmp/test_noauth_$i.log 2>&1) &
		pids+=($!)
	done

	concurrent_success=0
	for pid in "${pids[@]}"; do
		if wait "$pid"; then
			concurrent_success=$((concurrent_success + 1))
		fi
	done

	if [[ $concurrent_success -eq 3 ]]; then
		pass_test "No Auth - Concurrent connections ($concurrent_success/3 succeeded)"
	else
		fail_test "No Auth - Concurrent connections ($concurrent_success/3 succeeded)"
	fi
	rm -f /tmp/test_noauth_*.log

	# P1: Test proper SOCKS5 version negotiation with socat
	test_socat_socks5 "No Auth - Version negotiation" "version_negotiation"

else
	fail_test "No Auth - Server failed to start"
fi

stop_server

# Test 2: Username/Password Authentication (Method 0x02)
echo ""
echo "--- Testing Username/Password Authentication (RFC 1928 Section 3, Method 0x02) ---"
start_server $TEST_PORT "userpass"

if status_server; then
	# P0: Test with correct credentials
	test_curl_socks5 "UserPass Auth - Valid credentials" "testuser:testpass@127.0.0.1:$TEST_PORT" "true"

	# P0: Test with incorrect credentials
	test_curl_socks5 "UserPass Auth - Invalid username" "wronguser:testpass@127.0.0.1:$TEST_PORT" "false"
	test_curl_socks5 "UserPass Auth - Invalid password" "testuser:wrongpass@127.0.0.1:$TEST_PORT" "false"
	test_curl_socks5 "UserPass Auth - Empty credentials" ":@127.0.0.1:$TEST_PORT" "false"
	test_curl_socks5 "UserPass Auth - No credentials" "127.0.0.1:$TEST_PORT" "false"

	# P1: Test proper username/password negotiation
	test_socat_socks5 "UserPass Auth - Method negotiation" "userpass_negotiation"

else
	fail_test "UserPass Auth - Server failed to start"
fi

stop_server

# Test 3: Protocol boundary conditions (P2 - only when necessary)
echo ""
echo "--- Testing Protocol Boundary Conditions (RFC 1928 Edge Cases) ---"
start_server $TEST_PORT "noauth"

if status_server; then
	# P2: Test invalid SOCKS version (boundary condition)
	test_boundary_condition "Protocol - Invalid SOCKS version" '\x04\x01\x00' "unsupported SOCKS version"

	# P2: Test NMETHODS = 0 (boundary condition per RFC 1928)
	test_boundary_condition "Protocol - Zero methods" '\x05\x00' "invalid NMETHODS value: 0"

	# P2: Test unsupported authentication method
	test_boundary_condition "Protocol - Unsupported auth method" '\x05\x01\x99' "no acceptable authentication methods"

fi

stop_server

echo ""
echo "=== Test Summary ==="
echo "Tests Run: $TESTS_RUN"
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"

if [[ $TESTS_FAILED -eq 0 ]]; then
	echo -e "${GREEN}All authentication tests passed!${NC}"
	exit 0
else
	echo -e "${RED}Some authentication tests failed!${NC}"
	exit 1
fi
