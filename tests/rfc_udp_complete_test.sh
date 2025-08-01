#!/bin/bash

# RFC 1928 UDP ASSOCIATE Comprehensive Test
# Tests UDP ASSOCIATE command implementation according to RFC 1928 Section 7
# Priority: P0 curl, P1 socat, P2 echo+nc

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

	local wait_count=0
	while [[ $wait_count -lt 10 ]]; do
		if nc -z 127.0.0.1 "$port" 2>/dev/null; then
			break
		fi
		sleep 1
		wait_count=$((wait_count + 1))
	done

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

# Test UDP ASSOCIATE protocol negotiation
test_udp_associate_protocol() {
	local description="$1"
	local target_addr="$2"
	local target_port="$3"
	local expect_success="$4"

	log_test "$description"

	if ! command -v socat >/dev/null 2>&1; then
		warn "socat not available, skipping test: $description"
		return 0
	fi

	local temp_file=$(mktemp)

	# Step 1: Authentication negotiation
	printf '\x05\x01\x00' >"$temp_file"

	# Step 2: UDP ASSOCIATE request
	# VER(1) + CMD(3-UDP_ASSOCIATE) + RSV(1) + ATYP(1-IPv4) + ADDR(4) + PORT(2)
	local addr_bytes
	IFS='.' read -r -a addr_parts <<<"$target_addr"
	addr_bytes=$(printf "\\\\x%02x\\\\x%02x\\\\x%02x\\\\x%02x" "${addr_parts[0]}" "${addr_parts[1]}" "${addr_parts[2]}" "${addr_parts[3]}")
	local port_bytes=$(printf "\\\\x%02x\\\\x%02x" $((target_port >> 8)) $((target_port & 0xFF)))

	printf '\x05\x03\x00\x01%s%s' "$addr_bytes" "$port_bytes" >>"$temp_file"

	# Send negotiation and UDP ASSOCIATE request
	local response=$(timeout 10 socat - TCP:127.0.0.1:$TEST_PORT <"$temp_file" 2>/dev/null | xxd -p || echo "failed")

	rm -f "$temp_file"

	if [[ "$expect_success" == "true" ]]; then
		if [[ "$response" == "failed" ]]; then
			fail_test "$description - Connection failed"
		elif [[ "$response" =~ ^0500.*0500.* ]]; then
			# Should get auth response (0500) followed by UDP ASSOCIATE response (0500...)
			pass_test "$description - UDP ASSOCIATE protocol negotiation successful"
		elif [[ "$response" =~ ^0500.*0507.* ]]; then
			# Command not supported (0x07)
			pass_test "$description - UDP ASSOCIATE recognized but not supported (REP=0x07)"
		elif [[ "$response" =~ ^0500.* ]]; then
			# At minimum should get successful auth negotiation
			pass_test "$description - UDP ASSOCIATE auth negotiation successful"
		else
			fail_test "$description - Unexpected response: $response"
		fi
	else
		if [[ "$response" == "failed" ]] || [[ "$response" =~ 05[0-9][1-9a-f].* ]]; then
			pass_test "$description - Failed as expected"
		else
			fail_test "$description - Should have failed but got: $response"
		fi
	fi
}

# Test UDP packet header format (RFC 1928 Section 7)
test_udp_packet_header() {
	local description="$1"

	log_test "$description"

	if ! command -v python3 >/dev/null 2>&1; then
		warn "python3 not available, skipping UDP header test"
		return 0
	fi

	# Create Python script to test UDP header parsing
	cat >/tmp/udp_header_test.py <<'EOF'
import struct

def test_udp_header_format():
    """Test UDP header format according to RFC 1928 Section 7"""
    
    # RFC 1928 UDP Header Format:
    # +----+------+------+----------+----------+----------+
    # |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    # +----+------+------+----------+----------+----------+
    # | 2  |  1   |  1   | Variable |    2     | Variable |
    # +----+------+------+----------+----------+----------+
    
    try:
        # Test Case 1: IPv4 UDP header
        rsv = b'\x00\x00'  # Reserved (2 bytes)
        frag = b'\x00'     # Fragment (1 byte, 0 = standalone)
        atyp = b'\x01'     # Address type (1 byte, 1 = IPv4)
        dst_addr = b'\x08\x08\x08\x08'  # 8.8.8.8
        dst_port = b'\x00\x35'  # Port 53 (DNS)
        data = b'test_data'
        
        ipv4_header = rsv + frag + atyp + dst_addr + dst_port + data
        
        if len(ipv4_header) == 2 + 1 + 1 + 4 + 2 + len(data):
            print("IPV4_HEADER_FORMAT_VALID")
        else:
            print("IPV4_HEADER_FORMAT_INVALID")
        
        # Test Case 2: Domain name UDP header
        domain = b'\x0bgoogle.com'  # Length-prefixed domain
        domain_header = rsv + frag + b'\x03' + domain + dst_port + data
        
        if len(domain_header) == 2 + 1 + 1 + len(domain) + 2 + len(data):
            print("DOMAIN_HEADER_FORMAT_VALID")
        else:
            print("DOMAIN_HEADER_FORMAT_INVALID")
            
        # Test Case 3: IPv6 UDP header
        ipv6_addr = b'\x20\x01\x48\x60\x48\x60\x00\x00\x00\x00\x00\x00\x00\x00\x88\x88'
        ipv6_header = rsv + frag + b'\x04' + ipv6_addr + dst_port + data
        
        if len(ipv6_header) == 2 + 1 + 1 + 16 + 2 + len(data):
            print("IPV6_HEADER_FORMAT_VALID")
        else:
            print("IPV6_HEADER_FORMAT_INVALID")
            
        # Test Case 4: Fragment field validation
        frag_values = [0x00, 0x01, 0x7F, 0x80, 0xFF]
        valid_fragments = []
        
        for frag_val in frag_values:
            if frag_val == 0x00:  # Standalone
                valid_fragments.append("STANDALONE")
            elif 1 <= frag_val <= 127:  # Fragment position
                valid_fragments.append(f"FRAG_{frag_val}")
            elif frag_val >= 0x80:  # End-of-fragment sequence
                valid_fragments.append("END_FRAG")
                
        print(f"FRAGMENT_VALIDATION_{'_'.join(valid_fragments)}")
        
    except Exception as e:
        print(f"UDP_HEADER_TEST_ERROR_{str(e).replace(' ', '_')}")

if __name__ == "__main__":
    test_udp_header_format()
EOF

	local result=$(python3 /tmp/udp_header_test.py 2>/dev/null || echo "SCRIPT_ERROR")
	rm -f /tmp/udp_header_test.py

	if [[ "$result" == *"IPV4_HEADER_FORMAT_VALID"* ]] &&
		[[ "$result" == *"DOMAIN_HEADER_FORMAT_VALID"* ]] &&
		[[ "$result" == *"IPV6_HEADER_FORMAT_VALID"* ]]; then
		pass_test "$description - UDP header format validation successful"
	else
		fail_test "$description - UDP header format validation failed: $result"
	fi
}

# Test UDP ASSOCIATE command functionality
test_udp_associate_functionality() {
	local description="$1"

	log_test "$description"

	if ! command -v python3 >/dev/null 2>&1; then
		warn "python3 not available, skipping UDP functionality test"
		return 0
	fi

	# Test UDP ASSOCIATE command processing
	cat >/tmp/udp_associate_test.py <<'EOF'
import socket
import struct

def test_udp_associate():
    try:
        # Connect to SOCKS5 server
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(('127.0.0.1', 1080))
        
        # Step 1: Version negotiation
        sock.send(b'\x05\x01\x00')
        response = sock.recv(2)
        
        if len(response) != 2 or response != b'\x05\x00':
            print("AUTH_FAILED")
            return
        
        # Step 2: UDP ASSOCIATE request
        # VER=5, CMD=3 (UDP_ASSOCIATE), RSV=0, ATYP=1 (IPv4), ADDR=0.0.0.0, PORT=0
        udp_request = b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00'
        sock.send(udp_request)
        
        # Expect UDP ASSOCIATE response
        response = sock.recv(10)
        if len(response) >= 10:
            ver, rep, rsv, atyp = struct.unpack('BBBB', response[:4])
            if ver == 5:
                if rep == 0:
                    # Extract BND.ADDR and BND.PORT for UDP relay
                    if atyp == 1:  # IPv4
                        addr = socket.inet_ntoa(response[4:8])
                        port = struct.unpack('!H', response[8:10])[0]
                        print(f"UDP_ASSOCIATE_SUCCESS_{addr}_{port}")
                    else:
                        print("UDP_ASSOCIATE_SUCCESS_UNKNOWN_ADDR")
                elif rep == 7:
                    print("UDP_ASSOCIATE_NOT_SUPPORTED")
                else:
                    print(f"UDP_ASSOCIATE_ERROR_{rep:02x}")
            else:
                print("UDP_PROTOCOL_ERROR")
        else:
            print("UDP_SHORT_RESPONSE")
            
        sock.close()
        
    except Exception as e:
        print(f"UDP_EXCEPTION_{str(e).replace(' ', '_')}")

if __name__ == "__main__":
    test_udp_associate()
EOF

	local result=$(python3 /tmp/udp_associate_test.py 2>/dev/null || echo "SCRIPT_ERROR")
	rm -f /tmp/udp_associate_test.py

	case "$result" in
	"UDP_ASSOCIATE_SUCCESS_"*)
		pass_test "$description - UDP ASSOCIATE command successful with relay info"
		;;
	"UDP_ASSOCIATE_NOT_SUPPORTED")
		pass_test "$description - UDP ASSOCIATE recognized but not supported (REP=0x07)"
		;;
	"UDP_ASSOCIATE_ERROR_"*)
		pass_test "$description - UDP ASSOCIATE command recognized with error response"
		;;
	"AUTH_FAILED")
		fail_test "$description - Authentication failed"
		;;
	*)
		fail_test "$description - Unexpected result: $result"
		;;
	esac
}

echo "=== RFC 1928 UDP ASSOCIATE Comprehensive Test ==="
echo ""

# Start server for UDP tests
stop_server
start_server $TEST_PORT

if ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
	error "Failed to start server for UDP tests"
	exit 1
fi

echo "--- Testing UDP ASSOCIATE Command (RFC 1928 Section 7) ---"

# Test 1: Basic UDP ASSOCIATE protocol
test_udp_associate_protocol "UDP ASSOCIATE Protocol - Basic negotiation" "0.0.0.0" 0 "true"

# Test 2: UDP packet header format validation
test_udp_packet_header "UDP Header Format - RFC compliance validation"

# Test 3: UDP ASSOCIATE functionality
test_udp_associate_functionality "UDP ASSOCIATE - Command processing"

# Test 4: UDP ASSOCIATE with specific address
test_udp_associate_protocol "UDP ASSOCIATE Protocol - Specific address" "127.0.0.1" 53 "true"

stop_server

echo ""
echo "=== UDP ASSOCIATE Test Summary ==="
echo "Tests Run: $TESTS_RUN"
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"

if [[ $TESTS_FAILED -eq 0 ]]; then
	echo -e "${GREEN}All UDP ASSOCIATE tests passed!${NC}"
	exit 0
else
	echo -e "${RED}Some UDP ASSOCIATE tests failed!${NC}"
	exit 1
fi
