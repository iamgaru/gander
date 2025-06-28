# Gander - High-Performance Packet Filter and Proxy 

[![CI](https://github.com/iamgaru/gander/workflows/CI/badge.svg)](https://github.com/iamgaru/gander/actions/workflows/ci.yml)
[![CodeQL](https://github.com/iamgaru/gander/workflows/CodeQL/badge.svg)](https://github.com/iamgaru/gander/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/iamgaru/gander)](https://goreportcard.com/report/github.com/iamgaru/gander)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/github/release/iamgaru/gander.svg)](https://github.com/iamgaru/gander/releases/latest)

A high-performance packet filter and transparent proxy written in Go for selective inspection and logging. Designed for network security monitoring, filtering, debugging, and traffic analysis with minimal latency overhead.

## Architecture

Gander features a clean, modular architecture designed for extensibility and performance:

- **🔌 Plugin-based Filter System** (`internal/filter/`) - Extensible packet filtering with domain, IP, and custom providers
- **🔐 Certificate Management** (`internal/cert/`) - Dynamic certificate generation with upstream sniffing and caching
- **📊 HTTP Capture System** (`internal/capture/`) - Request/response correlation and structured JSON export  
- **⚡ High-Performance Relay** (`internal/relay/`) - Optimized bidirectional data forwarding
- **🛠 Protocol Utilities** (`pkg/protocol/`) - HTTP parsing and TLS detection
- **⚙️ Configuration System** (`internal/config/`) - Comprehensive validation with legacy migration

> See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for detailed architecture diagrams and component interactions.

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
- **Domain-Driven Inspection**: TLS interception and certificate generation only for specified domains
- **Selective Traffic Filtering**: Rule-based filtering by domain and source IP with different behaviors
- **High Performance**: Sub-millisecond latency for passthrough traffic
- **HTTP/HTTPS Support**: Handles both plain and TLS encrypted traffic
- **Smart Certificate Management**: Automatic certificate generation only when needed
- **Comprehensive Logging**: Detailed connection logs and HTTP request capture
- **HTTP Request/Response Capture**: Complete request/response pair capture with JSON export
- **Response Parsing and Matching**: Automatic matching of HTTP responses to their requests
- **Upstream Certificate Sniffing**: Mimics upstream server certificates for better stealth compatibility

### Performance Optimizations
- Buffer pooling for zero-allocation data copying
- Goroutine-per-connection architecture
- Fast domain/IP lookup using hash maps
- Efficient SNI extraction without regex
- Certificate caching for TLS performance
- **Domain-driven certificate generation**: No unnecessary certificate creation
- **Intelligent inspection routing**: Only domains requiring inspection get TLS interception
- Configurable buffer sizes and timeouts
- Optimized inspection vs fast relay decision making
- Performance-optimized response parsing

### Security Features
- Domain-based inspection rules
- Source IP-based inspection rules
- Bypass rules for trusted domains/IPs
- Custom CA certificate support
- Automatic certificate generation and caching
- Upstream certificate template matching for stealth operation
- Structured logging for security analysis
- HTTP request/response capture for forensics
- Complete HTTPS traffic decryption and analysis

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
- **`gander_test.go`** - Core functionality tests (configuration, proxy logic, HTTP parsing, response matching)
- **`cert_test.go`** - Certificate management, TLS operations, and certificate trust functionality
- **`config_test.go`** - Configuration validation and edge cases
- **`utils_test.go`** - Utility functions, HTTP capture, and performance tests

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
Current test coverage: **Comprehensive** across **6 packages** with **91 test functions**

The test suite covers:
- ✅ **Main Package** (38 tests) - Configuration, proxy logic, HTTP parsing, response matching
- ✅ **Capture Package** (8 tests) - Request/response correlation and JSON export
- ✅ **Certificate Package** (7 tests) - Certificate management, TLS operations, trust functionality
- ✅ **Config Package** (12 tests) - Configuration validation and default application
- ✅ **Filter Package** (12 tests) - Filter system, providers, manager, and priority execution
- ✅ **Protocol Package** (15 tests) - HTTP parsing, protocol detection, and TLS SNI extraction
- ✅ **Benchmark Tests** - Performance validation for all critical functions
- ✅ **Integration Tests** - Component interaction verification
- ✅ **Edge Cases** - Error handling and boundary condition testing

### Benchmark Results
Key performance metrics on Apple M1 Max:
- Certificate cache access: **14.03 ns/op**
- Rule checking: **22.00 ns/op**
- HTTP host extraction: **649.0 ns/op**
- HTTP response parsing: **~1,500 ns/op**
- Inspection decision making: **~25 ns/op**
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

### Domain-Driven Certificate Generation (v0.1.0+)

Starting with version 0.1.0, Gander implements **domain-driven certificate generation** for optimal performance and stealth:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│   All Traffic   │───▶│  Inspection      │───▶│  Certificate        │
│                 │    │  Rules Check     │    │  Generation         │
│ • HTTP          │    │                  │    │                     │
│ • HTTPS         │    │ Source IP  OR    │    │ Domain in           │
│ • Any Protocol  │    │ Domain     ──▶   │    │ inspect_domains?    │
└─────────────────┘    │ Match?           │    │                     │
                       └──────────────────┘    │ YES: Generate Cert  │
                                               │ NO:  Pass Through   │
                                               └─────────────────────┘
```

**Key Benefits:**
- **Performance**: Certificates only generated when needed
- **Stealth**: Minimal fingerprinting for non-targeted domains  
- **Efficiency**: Reduced overhead for high-volume proxy scenarios
- **Clarity**: Clear separation between logging rules and interception rules

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
    "valid_days": 365,                  // Certificate validity period
    "upstream_cert_sniff": true         // Mimic upstream server certificates
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

**Important**: Certificate generation and TLS interception are now **domain-driven**. Certificates are only generated for domains explicitly listed in `inspect_domains`, regardless of source IP rules. This ensures:

- **Optimal Performance**: No unnecessary certificate generation for domains that don't need inspection
- **Stealth Operation**: Only targeted domains get certificate interception
- **Resource Efficiency**: Reduced CPU and memory usage for certificate operations
- **Clear Separation**: Source IP rules control logging/filtering, domain rules control certificate generation

```json
{
  "rules": {
    "inspect_domains": [             // Domains requiring TLS interception & certificate generation
      "example.com",                 // Exact domain match
      "api.example.com",             // Subdomain match
      "*.suspicious.com"             // Wildcard domain match
    ],
    "inspect_source_ips": [          // Source IPs for connection logging (no certificate generation)
      "192.168.1.100",              // Specific IP
      "10.0.0.0/24"                  // CIDR range
    ],
    "bypass_domains": [              // Domains to bypass completely
      "update.microsoft.com",
      "*.google.com"
    ],
    "bypass_source_ips": [           // Source IPs to bypass completely
      "192.168.1.1",
      "10.0.1.0/24"
    ]
  }
}
```

**Behavior**:
- **Domain-based inspection**: Only domains in `inspect_domains` get TLS certificates generated and full HTTP inspection
- **IP-based logging**: Source IPs in `inspect_source_ips` get connection logging but no certificate generation
- **Performance optimization**: Non-inspected domains are passed through with minimal overhead
- **Bypass rules**: Take precedence over inspection rules for excluded traffic

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

### Automated Setup

For complete automated MITM certificate setup with system trust:

```bash
# Complete setup: generate CA + trust in system + setup project
make setup-mitm

# Or step by step:
make gen-ca      # Generate CA certificate
make trust-ca    # Auto-detect OS and trust CA certificate
make verify-ca   # Verify certificate trust status
```

### Using Custom CA

1. **Generate CA Certificate**:
```bash
make gen-ca
```

2. **Configure Auto-Generation**:
Set `auto_generate: true` in the TLS configuration to automatically generate certificates for new domains.

3. **Enable Upstream Certificate Sniffing**:
Set `upstream_cert_sniff: true` to make generated certificates mimic the upstream server's certificate details for better stealth operation.

### Upstream Certificate Sniffing

This advanced feature enhances the stealth capabilities of the MITM proxy by making generated certificates closely match the upstream server's certificates:

#### How It Works
1. **Certificate Inspection**: When intercepting HTTPS traffic, Gander first connects to the upstream server to inspect its certificate
2. **Template Extraction**: Extracts key details like Subject Alternative Names (SANs), Common Name, and Organization
3. **Certificate Generation**: Generates a new certificate using the upstream certificate as a template
4. **Stealth Operation**: The resulting certificate appears more legitimate to applications and security tools

#### Benefits
- **Reduced Detection**: Applications are less likely to detect the MITM operation
- **Better Compatibility**: Mimics real certificate characteristics for improved compatibility
- **Enhanced Analysis**: Provides insights into the actual certificates used by target servers

#### Configuration
```json
{
  "tls": {
    "upstream_cert_sniff": true,
    "auto_generate": true
  }
}
```

#### Debug Output
When debug logging is enabled, you'll see detailed certificate information:
```
Sniffed upstream cert for google.com: CN=*.google.com, SAN=[*.google.com, google.com, ...], Org=[Google Trust Services]
Generated certificate for google.com using upstream cert template: CN=google.com, SAN=[*.google.com, google.com, ...]
```

### System Certificate Trust

**Automatic (Recommended)**:
```bash
# Auto-detect OS and install CA certificate (supports macOS, Linux, Windows)
make trust-ca

# Verify installation
make verify-ca

# For Chrome-specific issues (macOS)
make fix-chrome
```

**Manual Installation**:

**macOS System-wide**:
```bash
# Add to System keychain (affects all apps including browsers)
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/ca.crt

# Add to login keychain (Chrome sometimes prefers this)
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db certs/ca.crt

# Verify installation
security find-certificate -c "Gander MITM CA" /Library/Keychains/System.keychain
```

**Linux (Ubuntu/Debian)**:
```bash
sudo cp certs/ca.crt /usr/local/share/ca-certificates/gander-proxy.crt
sudo update-ca-certificates
```

**Linux (RHEL/CentOS)**:
```bash
sudo cp certs/ca.crt /etc/pki/ca-trust/source/anchors/gander-proxy.crt
sudo update-ca-trust
```

**Windows System-wide**:
```powershell
# Import CA certificate to Trusted Root Certification Authorities (requires Administrator)
# Method 1: Using PowerShell (Recommended)
Import-Certificate -FilePath "certs\ca.crt" -CertStoreLocation Cert:\LocalMachine\Root

# Method 2: Using certlm.msc GUI
# 1. Run "certlm.msc" as Administrator
# 2. Navigate to "Trusted Root Certification Authorities" → "Certificates"
# 3. Right-click → "All Tasks" → "Import"
# 4. Select "certs\ca.crt" and complete the wizard

# Method 3: Using certutil command
certutil -addstore -f "ROOT" "certs\ca.crt"

# Verify installation
certutil -store ROOT | findstr "Gander"
```

**Note**: Windows commands require PowerShell and may need Administrator privileges for system-wide installation.

**Windows User-level (Alternative)**:
```powershell
# Import to Current User store (no Administrator required)
Import-Certificate -FilePath "certs\ca.crt" -CertStoreLocation Cert:\CurrentUser\Root

# Verify installation
Get-ChildItem -Path Cert:\CurrentUser\Root | Where-Object {$_.Subject -like "*Gander*"}
```

### Browser-Specific Installation

**Chrome/Chromium**:
1. Go to Settings → Privacy and security → Security → Manage certificates
2. Import `certs/ca.crt` as a trusted root certificate
3. **Note**: On macOS, restart Chrome completely after system trust installation

**Firefox**:
1. Go to Settings → Privacy & Security → Certificates → View Certificates
2. Import `certs/ca.crt` in the Authorities tab

### Testing Certificate Trust

```bash
# Test with curl (should work without certificate warnings)
curl -x localhost:1234 https://example.com

# Test with system CA bundle
make test-mitm

# Remove trust (for cleanup)
make untrust-ca
```

### Troubleshooting Certificate Issues

**Chrome shows certificate warnings**:
```bash
# Try Chrome-specific fix (macOS)
make fix-chrome

# Restart Chrome completely
pkill -f "Google Chrome"
# Then restart Chrome
```

**Certificate not trusted**:
```bash
# Verify CA is installed
make verify-ca

# Check certificate details
openssl x509 -in certs/ca.crt -text -noout

# Regenerate if needed
make clean-all
make setup-mitm
```

**Windows-specific troubleshooting**:
```powershell
# Check if certificate is installed (System store)
certutil -store ROOT | findstr "Gander"

# Check if certificate is installed (User store)
Get-ChildItem -Path Cert:\CurrentUser\Root | Where-Object {$_.Subject -like "*Gander*"}

# Remove certificate if needed (System store - requires Administrator)
certutil -delstore ROOT "Gander MITM CA"

# Remove certificate (User store)
Get-ChildItem -Path Cert:\CurrentUser\Root | Where-Object {$_.Subject -like "*Gander*"} | Remove-Item

# Clear certificate cache (may help with browser issues)
certlm.msc  # Manual certificate manager
# Or restart browser completely
```

## HTTP Request/Response Capture

### Enhanced Capture Features

Gander provides comprehensive HTTP traffic capture with the following capabilities:

- **Complete Request/Response Pairs**: Automatically matches HTTP responses to their corresponding requests
- **Detailed Metadata Extraction**: Captures method, URL, path, query parameters, headers, and body content
- **JSON Export Format**: All captures are saved as structured JSON for easy analysis
- **Performance Optimized**: Minimal overhead for non-inspected traffic using fast relay mode
- **Selective Capture**: Only captures traffic matching inspection rules

### Capture File Naming

Captured files use descriptive naming for easy identification:
```
2024-06-22_20-25-06.487_[127.0.0.1]_example.com_get_root.json
2024-06-22_20-25-57.023_[127.0.0.1]_google.com_post__api_test.json
```

Format: `{timestamp}_{client_ip}_{domain}_{method}_{safe_path}.json`

### Response Matching

The system automatically correlates HTTP responses with their requests:

1. **Request Capture**: When an HTTP request is intercepted, it's parsed and temporarily stored
2. **Response Matching**: When the corresponding response arrives, it's matched to the request
3. **Combined Export**: The complete request/response pair is saved as a single JSON file
4. **Metadata Enhancement**: Additional fields like response status, headers, and timing are included

### Supported HTTP Methods

All standard HTTP methods are supported for capture:
- GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, TRACE, CONNECT

## Logging and Monitoring

### Connection Logs
```
[2024-06-21 10:30:45.123] 192.168.1.100 -> example.com:443 (example.com) | 2.345s | 1024/2048 bytes | HTTPS | inspected=true captured=true
```

### HTTP Captures
Inspected HTTP requests and responses are saved as JSON files with complete request/response pairs:
```json
{
  "timestamp": "2024-06-21T10:30:45.123Z",
  "client_ip": "192.168.1.100",
  "domain": "example.com",
  "method": "GET",
  "url": "/api/data",
  "path": "/api/data",
  "query": "param=value",
  "http_version": "HTTP/1.1",
  "headers": {
    "Host": "example.com",
    "User-Agent": "Mozilla/5.0...",
    "Authorization": "Bearer ..."
  },
  "body": "request body content",
  "body_size": 20,
  "content_type": "application/json",
  "user_agent": "Mozilla/5.0...",
  "referer": "https://example.com/",
  "response": {
    "status_code": 200,
    "headers": {
      "Content-Type": "application/json",
      "Content-Length": "25",
      "Server": "nginx/1.18.0"
    },
    "body": "{\"status\": \"success\"}"
  }
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

- **Total**: Total connections processed since startup
- **Active**: Currently active connections
- **Inspected**: Connections that went through inspection (vs fast relay)
- **Captured**: HTTP requests/responses captured to disk
- **Transferred**: Total bytes transferred through the proxy

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

Debug mode provides detailed logging for:
- **HTTP Request/Response Processing**: Detailed parsing and capture information
- **Certificate Operations**: Upstream certificate sniffing and generation details
- **Inspection Decisions**: Why traffic was inspected or bypassed
- **Performance Metrics**: Timing information for critical operations

Example debug output:
```
Captured GET /api/test from 192.168.1.100 to example.com (Headers: 5, Body: 25 bytes)
Sniffed upstream cert for google.com: CN=*.google.com, SAN=[*.google.com, google.com]
Captured response 200 for GET /api/test from 192.168.1.100 to example.com (Headers: 8, Body: 150 bytes)
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

### Documentation
- **[docs/REFACTORING.md](docs/REFACTORING.md)** - Complete architectural refactoring summary and technical details
- **[README.md](README.md)** - This file, main project documentation
- **[docs/assets/](docs/assets/)** - Documentation assets (logos, diagrams)

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
| Version  | 0.2.0        |
| GitHub   | iamgaru      |
| License  | MIT          |
| Architecture | Modular (refactored v0.2.0) |
| Last Updated | June 2024 |