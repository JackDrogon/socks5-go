#!/bin/bash

# SOCKS5 Server Control Script
# Manages starting/stopping the Go SOCKS5 server for testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
SERVER_BINARY="$ROOT_DIR/go-socks5"
PID_FILE="$SCRIPT_DIR/socks5_server.pid"
LOG_FILE="$SCRIPT_DIR/socks5_server.log"

# Default server configuration
DEFAULT_PORT=1080
DEFAULT_AUTH="noauth"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
	echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
	echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
	echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Build server if needed
build_server() {
	if [[ ! -f "$SERVER_BINARY" ]]; then
		log "Building SOCKS5 server..."
		cd "$ROOT_DIR"
		go build -o go-socks5 ./cmd/socks5
		if [[ $? -ne 0 ]]; then
			error "Failed to build SOCKS5 server"
			exit 1
		fi
		log "Server built successfully"
	fi
}

# Start server with specified configuration
start_server() {
	local port=${1:-$DEFAULT_PORT}
	local auth=${2:-$DEFAULT_AUTH}
	local extra_args=${3:-""}

	build_server

	# Check if server is already running
	if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
		warn "Server already running with PID $(cat "$PID_FILE")"
		return 0
	fi

	log "Starting SOCKS5 server on port $port with auth: $auth"

	# Build command line arguments
	local cmd_args="-port $port"

	case "$auth" in
	"noauth")
		cmd_args="$cmd_args -auth noauth"
		;;
	"userpass")
		cmd_args="$cmd_args -auth userpass -user testuser -pass testpass"
		;;
	"gssapi")
		cmd_args="$cmd_args -auth gssapi"
		;;
	*)
		error "Unknown auth method: $auth"
		exit 1
		;;
	esac

	# Add any extra arguments
	if [[ -n "$extra_args" ]]; then
		cmd_args="$cmd_args $extra_args"
	fi

	# Start server in background
	cd "$ROOT_DIR"
	nohup "$SERVER_BINARY" $cmd_args >"$LOG_FILE" 2>&1 &
	local server_pid=$!

	# Save PID
	echo "$server_pid" >"$PID_FILE"

	# Wait a moment for server to start
	sleep 2

	# Verify server is running
	if ! kill -0 "$server_pid" 2>/dev/null; then
		error "Failed to start server"
		cat "$LOG_FILE"
		rm -f "$PID_FILE"
		exit 1
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
			log "Server running with PID: $pid"
			return 0
		else
			warn "PID file exists but server not running"
			rm -f "$PID_FILE"
			return 1
		fi
	else
		warn "Server not running"
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

# Main command handling
case "${1:-}" in
"start")
	start_server "$2" "$3" "$4"
	;;
"stop")
	stop_server
	;;
"restart")
	stop_server
	start_server "$2" "$3" "$4"
	;;
"status")
	status_server
	;;
"cleanup")
	cleanup
	;;
*)
	echo "Usage: $0 {start|stop|restart|status|cleanup} [port] [auth] [extra_args]"
	echo ""
	echo "Commands:"
	echo "  start [port] [auth] [extra_args] - Start the server"
	echo "  stop                             - Stop the server"
	echo "  restart [port] [auth] [extra_args] - Restart the server"
	echo "  status                           - Check server status"
	echo "  cleanup                          - Stop server and cleanup"
	echo ""
	echo "Auth methods: noauth, userpass, gssapi"
	echo "Default port: $DEFAULT_PORT"
	echo "Default auth: $DEFAULT_AUTH"
	exit 1
	;;
esac
