<div align="center">
  <img src="logo.png" alt="Gander Logo" width="25%" />
</div>

# Gander - High-Performance MITM Proxy

[![CI](https://github.com/iamgaru/gander/workflows/CI/badge.svg)](https://github.com/iamgaru/gander/actions/workflows/ci.yml)
[![CodeQL](https://github.com/iamgaru/gander/workflows/CodeQL/badge.svg)](https://github.com/iamgaru/gander/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/iamgaru/gander)](https://goreportcard.com/report/github.com/iamgaru/gander)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/github/release/iamgaru/gander.svg)](https://github.com/iamgaru/gander/releases/latest)

A transparent, high-performance Man-in-the-Middle (MITM) proxy written in Go for selective traffic inspection and logging. Designed for network security monitoring, debugging, and traffic analysis with minimal latency overhead.

## Table of Contents

- [Features](#features)
  - [Core Capabilities](#core-capabilities)
  - [Performance Optimizations](#performance-optimizations)
  - [Security Features](#security-features)
- [Quick Start](#quick-start)
  - [Prerequisites](#prerequisites)
  - [1. Setup and Build](#1-setup-and-build)
  - [2. Generate CA Certificate (for HTTPS inspection)](#2-generate-ca-certificate-for-https-inspection)
  - [3. Configure and Run](#3-configure-and-run)
  - [4. Test the Proxy](#4-test-the-proxy)
- [Make Commands](#make-commands)
  - [Build Commands](#build-commands)
  - [Development Commands](#development-commands)
  - [Setup Commands](#setup-commands)
  - [Runtime Commands](#runtime-commands)
  - [Installation Commands](#installation-commands)
  - [Cleanup Commands](#cleanup-commands)
  - [Testing Commands](#testing-commands)
  - [Help](#help)
- [Testing](#testing)
  - [Test Files](#test-files)
  - [Running Tests](#running-tests)
  - [Test Coverage](#test-coverage)
  - [Benchmark Results](#benchmark-results)
- [Continuous Integration](#continuous-integration)
  - [Workflows](#workflows)
  - [Status Badges](#status-badges)
  - [Automated Releases](#automated-releases)
- [Configuration](#configuration)
  - [Basic Settings](#basic-settings)
  - [Certificate Management](#certificate-management)
  - [Logging Configuration](#logging-configuration)
  - [Inspection Rules](#inspection-rules)
- [Deployment Modes](#deployment-modes)
  - [Transparent Mode (Production)](#transparent-mode-production)
  - [Explicit Mode (Testing)](#explicit-mode-testing)
  - [Docker Deployment](#docker-deployment)
- [Certificate Management](#certificate-management-1)
  - [Using Custom CA](#using-custom-ca)
  - [Client Certificate Installation](#client-certificate-installation)
- [Logging and Monitoring](#logging-and-monitoring)
  - [Connection Logs](#connection-logs)
  - [HTTP Captures](#http-captures)
  - [Real-time Monitoring](#real-time-monitoring)
  - [Statistics](#statistics)
- [Performance Tuning](#performance-tuning)
  - [High-Throughput Environments](#high-throughput-environments)
  - [Memory Optimization](#memory-optimization)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)
  - [Common Issues](#common-issues)
  - [Debug Mode](#debug-mode)
- [Development](#development)
  - [Setting up Development Environment](#setting-up-development-environment)
  - [Code Quality](#code-quality)
- [Contributing](#contributing)
  - [Development Guidelines](#development-guidelines)
- [License](#license)
- [Support](#support)
- [Acknowledgments](#acknowledgments)
- [Author & Version](#author--version)

## Features

### Core Capabilities
- **Transparent Proxy Mode**: Intercepts traffic without client configuration
- **Explicit Proxy Mode**: Traditional proxy mode for debugging
- **Selective Inspection**: Rule-based traffic filtering by domain and source IP
- **High Performance**: Sub-millisecond latency for passthrough traffic
- **HTTP/HTTPS Support**: Handles both plain and TLS encrypted traffic
- **Certificate Management**: Automatic certificate generation with custom CA
- **Comprehensive Logging**: Detailed connection logs and HTTP request capture

### Performance Optimizations
- Buffer pooling for zero-allocation data copying
- Goroutine-per-connection architecture
- Fast domain/IP lookup using hash maps
- Efficient SNI extraction without regex
- Certificate caching for TLS performance
- Configurable buffer sizes and timeouts

### Security Features
- Domain-based inspection rules
- Source IP-based inspection rules
- Bypass rules for trusted domains/IPs
- Custom CA certificate support
- Automatic certificate generation and caching
- Structured logging for security analysis
- HTTP request/response capture for forensics

## Quick Start

### Prerequisites
- Go 1.21 or later
- OpenSSL (for certificate generation)
- Make (optional, for build automation)

### 1. Setup and Build
```bash
# Clone the repository
git clone https://github.com/iamgaru/gander.git
cd gander

# Setup project (creates config.json, directories)
make setup

# Build the binary
make build

# Run tests to verify everything works
make test

# Or use the traditional Go build
go build -o build/gander .
```

### 2. Generate CA Certificate (for HTTPS inspection)
```bash
# Generate self-signed CA for testing
make gen-ca

# Or manually with OpenSSL
openssl genrsa -out certs/ca.key 4096
openssl req -new -x509 -days 365 -key certs/ca.key -out certs/ca.crt \
    -subj "/C=US/ST=CA/L=San Francisco/O=Gander Proxy/CN=Gander Proxy CA"
```

### 3. Configure and Run
```bash
# Edit config.json with your specific rules and settings
nano config.json

# Run the proxy
make run

# Or run the binary directly
./build/gander config.json
```

### 4. Test the Proxy
```bash
# Test HTTP (explicit mode)
curl -x localhost:8080 http://example.com

# Test HTTPS with custom CA (explicit mode)
curl -x localhost:8080 --cacert certs/ca.crt https://example.com
```

## Make Commands

The project includes a comprehensive Makefile for easy development and deployment:

### Build Commands
```bash
make build         # Build the binary
make build-prod    # Build optimized binary for production
make build-cross   # Build for multiple platforms (Linux, macOS, Windows)
make release       # Create release archives for all platforms
```

### Development Commands
```bash
make deps          # Install Go dependencies
make fmt           # Format Go code
make lint          # Lint Go code (installs golangci-lint if needed)
make vet           # Vet Go code
make test          # Run tests
make test-coverage # Run tests with coverage report
make bench         # Run performance benchmarks
make dev           # Run in development mode with hot reload
```

### Setup Commands
```bash
make setup         # Setup initial configuration and directories
make gen-ca        # Generate CA certificate for testing
make check-deps    # Check system dependencies
```

### Runtime Commands
```bash
make run           # Build and run with default config
make logs          # View live logs
make logs-recent   # View recent log entries
```

### Installation Commands
```bash
make install       # Install binary to /usr/local/bin
make uninstall     # Remove binary from system
```

### Cleanup Commands
```bash
make clean         # Clean build artifacts
make clean-all     # Deep clean (including logs and captures)
```

### Testing Commands
```bash
make test          # Run all tests
make test-coverage # Run tests with coverage report (generates coverage.html)
make bench         # Run performance benchmarks
```

**Test Coverage**: The project includes comprehensive tests covering:
- Configuration loading and validation
- HTTP parsing and inspection logic
- Certificate management operations
- Rule matching and filtering
- Performance benchmarks for critical functions

### Help
```bash
make help          # Show all available commands (default target)
```

## Testing

Gander includes a comprehensive test suite to ensure reliability and performance:

### Test Files
- **`gander_test.go`** - Core functionality tests (configuration, proxy logic, HTTP parsing)
- **`cert_test.go`** - Certificate management and TLS operations
- **`config_test.go`** - Configuration validation and edge cases
- **`utils_test.go`** - Utility functions and performance tests

### Running Tests
```bash
# Run all tests
make test

# Run with coverage report
make test-coverage
# Opens coverage.html in your browser

# Run performance benchmarks
make bench
```

### Test Coverage
Current test coverage: **32.4%** of statements

The test suite covers:
- ✅ Configuration loading and validation
- ✅ HTTP request parsing and inspection
- ✅ Rule matching (domains, IPs, bypass logic)
- ✅ Certificate cache operations
- ✅ Statistics tracking
- ✅ Error handling and edge cases
- ✅ Performance benchmarks

### Benchmark Results
Key performance metrics on Apple M1 Max:
- Certificate cache access: **14.03 ns/op**
- Rule checking: **22.00 ns/op**
- HTTP host extraction: **649.0 ns/op**
- Configuration loading: **27,348 ns/op**

## Continuous Integration

Gander uses GitHub Actions for automated testing, building, and deployment:

### Workflows
- **🚀 Quick Check** - Fast validation on every commit (build, basic tests, formatting)
- **🧪 CI** - Comprehensive testing across Go versions (1.21, 1.22) with coverage reporting
- **🔍 CodeQL** - Security analysis and code quality scanning (weekly + on PRs)
- **🏗️ Release** - Automated releases with cross-platform binaries on tag push
- **🔄 Dependabot** - Automated dependency updates (weekly)

### Status Badges
The badges at the top of this README show:
- **CI Status** - Current build and test status
- **CodeQL** - Security analysis status  
- **Go Report Card** - Code quality score
- **License** - MIT license confirmation
- **Latest Release** - Current version available

### Automated Releases
Create a new release by pushing a version tag:
```bash
git tag v1.0.0
git push origin v1.0.0
```

This automatically:
- Runs full test suite
- Builds binaries for Linux, macOS, and Windows
- Creates GitHub release with changelog
- Uploads release artifacts

## Configuration

### Basic Settings
```json
{
  "proxy": {
    "listen_addr": ":8080",          // Proxy listen address
    "transparent": true,              // Enable transparent mode
    "explicit_port": 3128,           // Port for explicit proxy mode
    "buffer_size": 32768,            // Buffer size for data copying
    "read_timeout_seconds": 30,      // Read timeout
    "write_timeout_seconds": 30      // Write timeout
  }
}
```

### Certificate Management
```json
{
  "tls": {
    "cert_file": "certs/proxy.crt",     // Proxy server certificate
    "key_file": "certs/proxy.key",      // Proxy server private key
    "ca_file": "certs/ca.crt",          // CA certificate for signing
    "ca_key_file": "certs/ca.key",      // CA private key
    "cert_dir": "certs",                // Directory for generated certs
    "auto_generate": true,              // Auto-generate certificates
    "valid_days": 365                   // Certificate validity period
  }
}
```

### Logging Configuration
```json
{
  "logging": {
    "log_file": "proxy.log",         // Main log file
    "capture_dir": "captures",       // Directory for HTTP captures
    "max_file_size_mb": 100,         // Max log file size
    "enable_debug": false            // Enable debug logging
  }
}
```

### Inspection Rules
```json
{
  "rules": {
    "inspect_domains": [             // Domains to inspect
      "example.com",
      "api.example.com",
      "*.suspicious.com"
    ],
    "inspect_source_ips": [          // Source IPs to inspect
      "192.168.1.100",
      "10.0.0.0/24"
    ],
    "bypass_domains": [              // Domains to bypass
      "update.microsoft.com",
      "*.google.com"
    ],
    "bypass_source_ips": [           // Source IPs to bypass
      "192.168.1.1",
      "10.0.1.0/24"
    ]
  }
}
```

## Deployment Modes

### Transparent Mode (Production)

For transparent interception, configure iptables to redirect traffic:

```bash
# Create custom chain for proxy rules
iptables -t nat -N GANDER_PROXY

# Redirect HTTP traffic
iptables -t nat -A PREROUTING -p tcp --dport 80 -j GANDER_PROXY
iptables -t nat -A GANDER_PROXY -d 127.0.0.0/8 -j RETURN
iptables -t nat -A GANDER_PROXY -p tcp -j REDIRECT --to-port 8080

# Redirect HTTPS traffic
iptables -t nat -A PREROUTING -p tcp --dport 443 -j GANDER_PROXY
iptables -t nat -A GANDER_PROXY -d 127.0.0.0/8 -j RETURN
iptables -t nat -A GANDER_PROXY -p tcp -j REDIRECT --to-port 8080

# Allow proxy to access internet (replace 'gander-user' with actual user)
iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner --uid-owner gander-user -j ACCEPT
iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner gander-user -j ACCEPT
```

### Explicit Mode (Testing)

Configure clients to use the proxy:
- HTTP Proxy: `localhost:8080`
- HTTPS Proxy: `localhost:8080`
- Install CA certificate in browser/system

### Docker Deployment

```dockerfile
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN make build-prod

FROM alpine:latest
RUN apk --no-cache add ca-certificates iptables
WORKDIR /root/
COPY --from=builder /app/build/gander .
COPY config.json .
COPY certs/ certs/
EXPOSE 8080
CMD ["./gander", "config.json"]
```

## Certificate Management

### Using Custom CA

1. **Generate CA Certificate**:
```bash
make gen-ca
```

2. **Configure Auto-Generation**:
Set `auto_generate: true` in the TLS configuration to automatically generate certificates for new domains.

### Client Certificate Installation

**Chrome/Chromium**:
1. Go to Settings → Privacy and security → Security → Manage certificates
2. Import `certs/ca.crt` as a trusted root certificate

**Firefox**:
1. Go to Settings → Privacy & Security → Certificates → View Certificates
2. Import `certs/ca.crt` in the Authorities tab

**System-wide (Linux)**:
```bash
sudo cp certs/ca.crt /usr/local/share/ca-certificates/gander-proxy.crt
sudo update-ca-certificates
```

**System-wide (macOS)**:
```bash
sudo security add-trusted-cert -d root -r trustRoot -k /Library/Keychains/System.keychain certs/ca.crt
```

## Logging and Monitoring

### Connection Logs
```
[2024-06-21 10:30:45.123] 192.168.1.100 -> example.com:443 (example.com) | 2.345s | 1024/2048 bytes | HTTPS | inspected=true captured=true
```

### HTTP Captures
Inspected HTTP requests are saved as JSON files:
```json
{
  "timestamp": "2024-06-21T10:30:45.123Z",
  "client_ip": "192.168.1.100",
  "domain": "example.com",
  "method": "GET",
  "url": "/api/data",
  "headers": {
    "Host": "example.com",
    "User-Agent": "Mozilla/5.0...",
    "Authorization": "Bearer ..."
  },
  "body": "request body content"
}
```

### Real-time Monitoring
```bash
# View live logs
make logs

# View recent activity
make logs-recent

# Monitor with system tools
tail -f proxy.log | grep "HTTPS"
```

### Statistics
Real-time statistics logged every 30 seconds:
```
Stats: 1250 total, 45 active, 87 inspected, 23 captured, 145 MB transferred
```

## Performance Tuning

### High-Throughput Environments
```json
{
  "proxy": {
    "buffer_size": 65536,           // Larger buffers for better performance
    "read_timeout_seconds": 60,     // Longer timeouts for slow connections
    "write_timeout_seconds": 60
  }
}
```

### Memory Optimization
```bash
# Set Go garbage collector target
export GOGC=100

# Limit maximum goroutines (if needed)
export GOMAXPROCS=4
```

## Security Considerations

1. **Certificate Security**:
   - Keep CA private key secure (`certs/ca.key`)
   - Use strong passwords for certificate files
   - Regularly rotate certificates
   - Restrict file permissions: `chmod 600 certs/ca.key`

2. **Network Security**:
   - Run proxy as non-root user
   - Use iptables to restrict proxy access
   - Monitor logs for suspicious activity
   - Implement rate limiting if needed

3. **Access Control**:
   - Implement IP-based access controls
   - Use VPN for remote management
   - Regular security audits
   - Monitor captured data access

## Troubleshooting

### Common Issues

**Build Errors**:
```bash
# Check Go version
go version

# Clean and rebuild
make clean
make build

# Check dependencies
make check-deps
```

**Certificate Errors**:
```bash
# Verify certificate validity
openssl x509 -in certs/ca.crt -text -noout

# Check certificate chain
openssl verify -CAfile certs/ca.crt certs/generated-cert.crt

# Regenerate CA if needed
make clean-all
make gen-ca
```

**Connection Issues**:
```bash
# Check if proxy is listening
netstat -tlnp | grep 8080

# Test connectivity
telnet localhost 8080

# Check proxy logs
make logs-recent
```

**Performance Issues**:
```bash
# Monitor system resources
htop

# Check file descriptor limits
ulimit -n

# Monitor network connections
ss -tuln

# Enable debug logging
# Set "enable_debug": true in config.json
```

### Debug Mode

Enable debug logging in configuration:
```json
{
  "logging": {
    "enable_debug": true,
    "log_file": "debug.log"
  }
}
```

## Development

### Setting up Development Environment
```bash
# Clone repository
git clone https://github.com/iamgaru/gander.git
cd gander

# Setup development environment
make setup
make deps

# Format and test code
make fmt
make vet
make test

# Run in development mode with hot reload
make dev
```

### Code Quality
```bash
# Run all checks
make fmt vet lint test

# Generate coverage report
make test-coverage
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow Go best practices and conventions
- Add tests for new features
- Update documentation as needed
- Ensure all tests pass before submitting PR

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:
- Open an issue on [GitHub](https://github.com/iamgaru/gander/issues)
- Check the troubleshooting section above
- Review the configuration examples
- Use `make help` to see all available commands

## Acknowledgments

- Thanks to the Go community for excellent networking libraries
- Inspired by various MITM proxy implementations
- Built with performance and security in mind

## Author & Version

| Field    | Value        |
|----------|--------------|
| Author   | Nick Conolly |
| Version  | 0.0.1        |
| GitHub   | iamgaru      |
| License  | MIT          |