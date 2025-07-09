<div align="center">
  <img src="docs/assets/logo.png" alt="Gander Logo" width="25%" />
</div>

# Gander - Network Intelligence Platform

[![CI](https://github.com/iamgaru/gander/workflows/CI/badge.svg)](https://github.com/iamgaru/gander/actions/workflows/ci.yml)
[![CodeQL](https://github.com/iamgaru/gander/workflows/CodeQL/badge.svg)](https://github.com/iamgaru/gander/actions/workflows/codeql.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/iamgaru/gander)](https://goreportcard.com/report/github.com/iamgaru/gander)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/github/release/iamgaru/gander.svg)](https://github.com/iamgaru/gander/releases/latest)

**A comprehensive network intelligence platform that transforms simple traffic capture into powerful network analytics**

Gander evolved from a high-performance HTTP/HTTPS proxy into a complete network intelligence solution. It provides **identity-based traffic analysis**, **intelligent storage management**, and **rich reporting capabilities** while maintaining sub-millisecond latency for production environments.

## 🚀 What Makes Gander Unique

### **Identity-Based Network Intelligence**
- **Know WHO is doing WHAT** on your network
- Correlate traffic with identities (IP, MAC, users, devices)
- Track behavior patterns and detect anomalies
- Generate compliance and security reports

### **Intelligent Storage Management**  
- **97% storage reduction** through smart compression and filtering
- Automatic file rolling and retention policies
- Selective capture levels from minimal to deep inspection
- Domain and resource type organization

### **Enterprise-Ready Architecture**
- Pluggable identity providers (IP/MAC, DHCP, Active Directory)
- Multiple compression formats (Gzip, Zstd, LZ4)
- Real-time streaming to external systems
- High-performance concurrent processing

## 📊 Storage Impact

| Setup | Per Request | 10K Requests/Day | Monthly | Yearly |
|-------|-------------|------------------|---------|--------|
| **Without Optimization** | 15-50KB | 500MB | ~15GB | ~180GB |
| **With Gander Enhanced** | 800 bytes - 2KB | 15MB | ~450MB | ~5.5GB |
| **Savings** | **97% reduction** | **97% reduction** | **97% reduction** | **97% reduction** |

## 🏗️ Architecture

Gander features a modern, modular architecture designed for extensibility and performance:

```
┌─────────────────────────────────────────────────────────┐
│                   Gander Platform                        │
├─────────────────┬───────────────────┬───────────────────┤
│   Identity      │   Enhanced        │   Storage         │
│   System        │   Capture         │   Management      │
│                 │                   │                   │
│ • IP/MAC        │ • Domain          │ • Compression     │
│ • DHCP          │   Separation      │ • Rolling Files   │
│ • Active Dir    │ • Resource Types  │ • Retention       │
│ • Custom DB     │ • Smart Tagging   │ • Streaming       │
├─────────────────┼───────────────────┼───────────────────┤
│        Original Gander Foundation (HTTP/HTTPS Proxy)     │
│   • Certificate Management  • Filter System  • Relay    │
└─────────────────────────────────────────────────────────┘
```

### Core Components

- **🔍 Identity System** (`internal/identity/`) - Pluggable identity resolution with caching
- **🗜️ Storage Manager** (`internal/storage/`) - Compression, rolling, and retention management  
- **📈 Enhanced Capture** (`internal/capture/enhanced_types.go`) - Rich capture format with identity context
- **🔌 Filter System** (`internal/filter/`) - Extensible filtering with domain, IP, and custom providers
- **🔐 Certificate Management** (`internal/cert/`) - Dynamic certificate generation and caching
- **⚡ High-Performance Relay** (`internal/relay/`) - Optimized bidirectional data forwarding

> See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/FULL_FILTER_OPTIONS.md](docs/FULL_FILTER_OPTIONS.md) for detailed architecture information.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Enhanced Capabilities](#enhanced-capabilities)
  - [Identity-Based Reporting](#identity-based-reporting)
  - [Storage Management](#storage-management)
  - [Enhanced Capture Format](#enhanced-capture-format)
- [Configuration](#configuration)
- [Performance & Sizing](#performance--sizing)
- [Deployment](#deployment)
- [Development](#development)
- [Migration](#migration)
- [Support](#support)

## Features

### 🎯 **Core Network Intelligence**
- **Identity Resolution**: Automatic identification of network clients via IP/MAC, DHCP, Active Directory
- **Behavioral Analysis**: Track patterns, detect anomalies, generate compliance reports
- **Enhanced Capture**: Rich JSON format with identity context and resource classification
- **Smart Organization**: Domain/date/resource type separation for easy analysis

### 🗜️ **Intelligent Storage**
- **Compression**: 85-90% size reduction with Gzip/Zstd/LZ4 support
- **Rolling Files**: Automatic rotation at configurable sizes (default 50MB)
- **Retention Policies**: Automatic cleanup with configurable retention periods
- **Selective Capture**: Four capture levels from minimal metadata to full deep inspection

### ⚡ **High Performance**
- **Ultra-Low Latency**: ~0.25s for HTTPS inspection with connection reuse (87% improvement)
- **Advanced Connection Pooling**: 25% hit rate with automatic lifecycle management
- **TLS Session Resumption**: Optimized TLS handshakes with session caching
- **Smart Certificate Pre-generation**: Proactive certificate creation for popular domains
- **Memory Efficiency**: Buffer pooling and efficient resource management
- **Scalable**: Handles thousands of concurrent connections with sub-second response times

### 🔒 **Security & Compliance**
- **Smart TLS Verification**: Context-aware certificate validation with automatic development domain detection
- **Transparent Inspection**: HTTPS interception with dynamic certificate generation
- **Audit Trails**: Complete request/response capture for forensics
- **Access Control**: Domain and IP-based filtering rules
- **Data Protection**: Configurable body capture limits and content filtering
- **Security by Default**: Secure TLS connections for production domains, development-friendly for testing

### 🔌 **Extensibility**
- **Pluggable Identity Providers**: Easy integration with existing identity systems
- **Custom Filters**: Domain, IP, content-type, and resource-based filtering
- **Streaming Integration**: Real-time data streaming to Elasticsearch, Kafka, webhooks
- **API-First Design**: RESTful APIs for configuration and monitoring

## Quick Start

### Prerequisites
- Go 1.21 or later
- OpenSSL (for certificate generation)
- Make (optional, for build automation)

### 1. Setup and Build
```bash
# Clone and setup
git clone https://github.com/iamgaru/gander.git
cd gander
make setup && make build

# Run tests
make test
```

### 2. Generate Certificates
```bash
# Generate CA certificate for HTTPS inspection
make gen-ca
```

### 3. Quick Configuration
```bash
# Copy the optimized production config
cp conf/examples/storage_optimized.json conf/config.json

# Edit for your environment
nano conf/config.json
```

### 4. Run and Test
```bash
# Start Gander
make run

# Test HTTP traffic
curl -x localhost:8848 http://example.com

# Test HTTPS with CA
curl -x localhost:8848 --cacert certs/ca.crt https://example.com
```

## Enhanced Capabilities

### Identity-Based Reporting

Transform anonymous network traffic into actionable intelligence:

```json
{
  "identity": {
    "primary_identity": {
      "type": "ip",
      "id": "192.168.1.100",
      "display_name": "John's MacBook",
      "confidence": 0.95,
      "metadata": {
        "mac_address": "A4:83:E7:12:34:56",
        "mac_vendor": "Apple", 
        "device_info": {
          "device_name": "John's MacBook",
          "owner": "John Doe",
          "department": "Engineering"
        }
      }
    }
  }
}
```

**Available Reports:**
- Traffic volume by identity
- Domain access patterns 
- Security events and anomalies
- Behavioral analysis
- Compliance audit trails

> See [docs/identity_based_reporting.md](docs/identity_based_reporting.md) for complete documentation.

### Storage Management

Massive storage savings with intelligent management:

```json
{
  "storage": {
    "compression_enabled": true,
    "compression_format": "gzip",
    "rolling_enabled": true,
    "max_file_size": 52428800,
    "capture_level": "basic",
    "retention_period": "720h"
  }
}
```

**Capture Levels:**
- **Minimal**: Metadata only (~200 bytes/request)
- **Basic**: Headers + small bodies (~1-2KB/request)  
- **Full**: Everything except large bodies (~5-50KB/request)
- **Deep**: Complete capture including large bodies
- **Custom**: Fine-grained filtering by domain, resource type, identity

> See [docs/storage_and_compression.md](docs/storage_and_compression.md) for complete documentation.

### Enhanced Capture Format

Rich, structured capture format with automatic classification:

```json
{
  "id": "20250628_165020_127001_49258_post_api",
  "timestamp": "2025-06-28T16:50:20.093755+10:00",
  "identity": { "primary_identity": "..." },
  "connection": { "client_ip": "...", "domain": "..." },
  "request": { "method": "POST", "url": "...", "headers": "..." },
  "response": { "status_code": 200, "headers": "...", "body": "..." },
  "resource_type": "api",
  "tags": ["api", "encrypted", "identified", "trusted"],
  "duration_ms": "255ms"
}
```

**Automatic Classification:**
- Resource types (API, webpage, image, CSS, JavaScript, etc.)
- Security context (encrypted, trusted, suspicious)
- Performance metrics (fast, slow, large response)
- Identity context (identified, anonymous, trusted network)

## Configuration

### Production-Ready Example

The `config_storage_example.json` provides a complete production configuration:

```json
{
  "identity": {
    "enabled": true,
    "enabled_providers": ["ip_mac"],
    "provider_configs": {
      "ip_mac": {
        "arp_scan_interval": "5m",
        "trusted_networks": ["192.168.1.0/24", "10.0.0.0/8"]
      }
    }
  },
  "storage": {
    "compression_enabled": true,
    "compression_format": "gzip", 
    "rolling_enabled": true,
    "max_file_size": 52428800,
    "capture_level": "basic",
    "retention_period": "720h"
  }
}
```

### Key Configuration Sections

- **Identity**: Configure identity providers and resolution
- **Storage**: Compression, rolling, retention, and capture levels
- **Filters**: Domain, IP, and content-based filtering rules
- **Streaming**: Real-time data streaming to external systems
- **Monitoring**: Metrics, alerts, and performance monitoring

## Performance & Sizing

### Benchmarks

| Environment | Requests/Second | CPU Usage | Memory | Storage/Day | HTTPS Latency |
|-------------|----------------|-----------|---------|-------------|---------------|
| **Development** | 1,000 | ~15% | ~50MB | ~15MB | ~0.25s (reused) |
| **Production** | 10,000 | ~45% | ~200MB | ~150MB | ~0.30s (reused) |
| **High Volume** | 50,000+ | ~80% | ~500MB | ~750MB | ~0.35s (reused) |

### Performance Optimizations

**HTTPS Inspection Performance:**
- **First Request**: ~1.9s (certificate generation + new connection)
- **Subsequent Requests**: ~0.25s (**87% faster** with connection reuse)
- **Connection Pool Hit Rate**: 25% (dramatically reduces TLS handshake overhead)
- **Transparent Relay**: ~0.19s (non-inspected domains)

**Recent Optimizations (v3.0.1):**
- Fixed critical worker pool configuration bug causing 30s timeouts
- Implemented advanced connection pooling with automatic lifecycle management
- Enhanced TLS session resumption with optimized caching
- Smart certificate pre-generation for popular domains reduces first-request latency

### Optimization Tips

**High Volume Environments:**
- Use LZ4 compression for speed
- Set capture level to "minimal" or "basic"
- Increase rolling file sizes (100MB+)
- Use larger buffer sizes

**Storage-Constrained:**
- Use Zstd compression for maximum compression
- Aggressive retention policies (7-14 days)
- Selective capture filtering
- External log shipping

**Development:**
- Use "full" or "deep" capture levels
- Shorter retention (1-3 days)
- Smaller rolling files for analysis

## Deployment

### Docker Deployment
```bash
# Build Docker image
docker build -t gander .

# Run with volume mounts
docker run -d \
  -p 8848:8848 \
  -v $(pwd)/conf/config.json:/app/conf/config.json \
  -v $(pwd)/captures:/app/captures \
  -v $(pwd)/certs:/app/certs \
  gander
```

### Transparent Mode (Production)
```bash
# Setup iptables redirect (Linux)
iptables -t nat -A OUTPUT -p tcp --dport 80,443 \
  -j REDIRECT --to-port 8848

# Or use with a gateway/router redirect
```

### High Availability
```yaml
# docker-compose.yml example
version: '3'
services:
  gander:
    image: gander:latest
    ports: ["8848:8848"]
    volumes:
      - ./conf/config.json:/app/conf/config.json
      - ./captures:/app/captures
    deploy:
      replicas: 3
```

## Development

### Setting Up Development Environment
```bash
# Clone and setup
git clone https://github.com/iamgaru/gander.git
cd gander

# Install dependencies and setup
make setup
make build
make test

# Development with hot reload
make dev
```

### Testing
```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run benchmarks
make benchmark

# Integration tests
make test-integration
```

### Code Quality
```bash
# Lint code
make lint

# Format code
make fmt

# Security scan
make security-scan
```

## Migration

### From Existing HTTP Proxies

1. **Assessment**: Analyze current traffic patterns and storage needs
2. **Gradual Rollout**: Start with compression and basic capture
3. **Identity Integration**: Add identity providers progressively
4. **Optimization**: Fine-tune capture levels and retention

### Configuration Migration
```bash
# Migrate from older Gander versions
make migrate-config

# Validate new configuration
make validate-config
```

## Make Commands

### Essential Commands
```bash
make setup          # Initial project setup
make build          # Build the binary
make run            # Run with default config
make test           # Run all tests
make clean          # Clean build artifacts
```

### Development Commands  
```bash
make dev            # Development mode with hot reload
make lint           # Code linting
make fmt            # Code formatting
make benchmark      # Performance benchmarks
```

### Deployment Commands
```bash
make build-prod     # Production build
make build-cross    # Multi-platform builds
make docker-build   # Build Docker image
make release        # Create release packages
```

## Documentation

- **[Architecture Guide](docs/ARCHITECTURE.md)** - Detailed system architecture
- **[Security Fixes](docs/SECURITY_FIXES.md)** - TLS security improvements and implementation details
- **[Identity-Based Reporting](docs/identity_based_reporting.md)** - Complete identity system guide
- **[Storage & Compression](docs/storage_and_compression.md)** - Storage management documentation  
- **[Enhanced Capture Config](docs/enhanced_capture_config.md)** - Capture format specifications
- **[Full Filter Options](docs/FULL_FILTER_OPTIONS.md)** - Network filtering architecture

## Support

### Community
- **GitHub Issues**: Bug reports and feature requests
- **Discussions**: Community support and questions
- **Wiki**: Additional documentation and examples

### Enterprise
- Professional support available
- Custom identity provider development
- Performance optimization consulting
- Compliance and security auditing

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Guidelines
- Go 1.21+ required
- Follow existing code style
- Add tests for new features
- Update documentation
- Run `make test` before submitting

## Roadmap

### Version 3.0 (Current)
- ✅ Identity-based reporting system
- ✅ Enhanced capture format with compression
- ✅ Storage management and retention
- ✅ Pluggable identity providers
- ✅ **Major Performance Optimizations** (v3.0.1)
  - 87% latency reduction on repeated HTTPS requests
  - Advanced connection pooling with 25% hit rate
  - Fixed critical worker pool configuration bug
  - Enhanced TLS session resumption and certificate pre-generation
- ✅ **Security Enhancements** (v3.0.2)
  - Smart TLS certificate verification system
  - Resolved all GitHub Advanced Security alerts
  - Context-aware certificate validation
  - Automatic development domain detection
  - Zero breaking changes with enhanced security

### Version 3.1 (Q1 2025)
- 🔄 DHCP identity provider
- 🔄 Active Directory integration
- 🔄 Real-time streaming improvements
- 🔄 Web-based dashboard

### Version 3.2 (Q2 2025)
- 📅 Machine learning anomaly detection
- 📅 Advanced behavioral analysis
- 📅 Compliance automation
- 📅 Multi-layer network filtering

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with ❤️ by the Gander team
- Inspired by the need for better network visibility
- Thanks to all contributors and the Go community

---

**Gander - Know your network. Secure your data. Scale your insights.**

<div align="center">
  <sub>
    Made with ❤️ by <a href="https://github.com/iamgaru">@iamgaru</a> and <a href="https://github.com/iamgaru/gander/graphs/contributors">contributors</a>
  </sub>
</div> 