# SOCKS5 Server Test Suite

This directory contains comprehensive tests for the Go SOCKS5 server implementation.

## Test Files

### `run_tests.sh`
Main test suite that validates core SOCKS5 functionality:
- Basic SOCKS5 connectivity without authentication
- Username/password authentication
- Error handling for invalid credentials
- Concurrent connection handling
- HTTP and HTTPS protocol support

### `protocol_test.sh`
Protocol compliance tests:
- IPv4 address type support
- Domain name resolution
- Custom port handling
- Error handling for unreachable hosts
- Server behavior on different interfaces

### `benchmark.sh`
Performance benchmarking:
- Sequential vs concurrent request performance
- Connection reuse efficiency
- Large data transfer capabilities
- Authentication overhead measurement

## Running Tests

Make all scripts executable:
```bash
chmod +x *.sh
```

Run individual test suites:
```bash
# Basic functionality tests
./run_tests.sh

# Protocol compliance tests
./protocol_test.sh

# Performance benchmarks
./benchmark.sh
```

Run all tests:
```bash
./run_all_tests.sh
```

## Requirements

- `curl` with SOCKS5 support
- `bc` for floating point calculations (benchmark only)
- `grep`, `pkill` and other standard Unix utilities

## Test Output

- **Green ✓**: Test passed
- **Red ✗**: Test failed
- **Yellow ⚠**: Warning or informational message

Each test script generates log files:
- `test1.log`, `test2.log`, `test3.log` - Basic functionality logs
- `protocol_test.log`, `protocol_error_test.log` - Protocol test logs
- `benchmark.log`, `benchmark_auth.log` - Performance test logs

## Expected Behavior

All tests should pass for a correctly implemented SOCKS5 server. The tests verify:

1. **RFC 1928 Compliance**: Proper SOCKS5 protocol implementation
2. **Authentication**: Both no-auth and username/password methods
3. **Address Types**: IPv4, domain names, and custom ports
4. **Error Handling**: Graceful handling of connection failures
5. **Performance**: Reasonable response times and concurrent handling

## Troubleshooting

If tests fail:
1. Check that the SOCKS5 server binary exists (`../go-socks5`)
2. Verify no other services are using the test ports (1080-1083, 2080-2083, 3080-3081)
3. Check log files for detailed error messages
4. Ensure your system has the required utilities installed