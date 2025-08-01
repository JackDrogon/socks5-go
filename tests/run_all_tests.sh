#!/bin/bash

# Run All SOCKS5 Tests
# Executes the complete test suite

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=================================="
echo -e "    SOCKS5 Complete Test Suite    "
echo -e "==================================${NC}\n"

# Make all scripts executable
chmod +x *.sh

# Track test results
TESTS_PASSED=0
TESTS_FAILED=0

run_test_suite() {
	local test_name="$1"
	local test_script="$2"

	echo -e "${YELLOW}Running $test_name...${NC}"
	echo "----------------------------------------"

	if ./"$test_script"; then
		echo -e "${GREEN}✓ $test_name PASSED${NC}\n"
		((TESTS_PASSED++))
	else
		echo -e "${RED}✗ $test_name FAILED${NC}\n"
		((TESTS_FAILED++))
	fi
}

# Clean up any existing processes
echo -e "${YELLOW}Cleaning up existing processes...${NC}"
pkill -f go-socks5 2>/dev/null || true
sleep 2

# Run test suites
run_test_suite "Basic Functionality Tests" "run_tests.sh"
run_test_suite "Protocol Compliance Tests" "protocol_test.sh"
run_test_suite "RFC 1928 Compliance Tests" "rfc_compliance_test.sh"
run_test_suite "Advanced Features Tests" "advanced_features_test.sh"

# Only run benchmark if bc is available
if command -v bc >/dev/null 2>&1; then
	run_test_suite "Performance Benchmarks" "benchmark.sh"
else
	echo -e "${YELLOW}⚠ Skipping benchmarks (bc not installed)${NC}\n"
fi

# Final cleanup
echo -e "${YELLOW}Final cleanup...${NC}"
pkill -f go-socks5 2>/dev/null || true

# Summary
echo -e "${BLUE}=================================="
echo -e "         Test Summary"
echo -e "==================================${NC}"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"

if [ $TESTS_FAILED -gt 0 ]; then
	echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"
	echo -e "\n${RED}Some tests failed. Check the output above for details.${NC}"
	exit 1
else
	echo -e "Tests Failed: ${GREEN}0${NC}"
	echo -e "\n${GREEN}🎉 All tests passed! Your SOCKS5 server is working correctly.${NC}"
fi

echo -e "\nLog files are available in the tests directory for detailed analysis."
