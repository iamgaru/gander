# Gander Architecture

## Current Modular Architecture

Gander follows a clean, modular architecture designed for extensibility and maintainability:

```
                         ┌─────────────────────────────────────┐
                         │            Gander Proxy            │
                         └─────────────────┬───────────────────┘
                                           │
                         ┌─────────────────▼───────────────────┐
                         │          cmd/gander/main.go         │
                         │        (Entry Point & CLI)          │
                         └─────────────────┬───────────────────┘
                                           │
                         ┌─────────────────▼───────────────────┐
                         │       internal/config/              │
                         │   • Configuration Management        │
                         │   • Validation & Defaults          │
                         │   • Legacy Migration               │
                         │   • File Watching                  │
                         └─────────────────┬───────────────────┘
                                           │
          ┌────────────────────────────────┼────────────────────────────────┐
          │                                │                                │
          ▼                                ▼                                ▼
┌─────────────────┐           ┌─────────────────┐           ┌─────────────────┐
│ internal/proxy/ │           │ internal/relay/ │           │ internal/cert/  │
│ • Server Setup  │           │ • Data Relay    │           │ • CA Management │
│ • Connection    │◄──────────┤ • Bidirectional │◄──────────┤ • Auto-Generate │
│   Handling      │           │   Forwarding    │           │ • Cert Caching  │
│ • TLS Detection │           │ • Performance   │           │ • Upstream Sniff│
└─────────┬───────┘           │   Optimized     │           └─────────────────┘
          │                   └─────────────────┘
          │
          ▼
┌─────────────────┐           ┌─────────────────┐           ┌─────────────────┐
│ internal/filter/│           │internal/capture/│           │  pkg/protocol/  │
│ • Filter System │◄──────────┤ • HTTP Capture  │◄──────────┤ • HTTP Parsing  │
│ • Provider Mgmt │           │ • Req/Res Match │           │ • TLS Detection │
│ • Rule Engine   │           │ • JSON Export   │           │ • Protocol Utils│
└─────────┬───────┘           │ • Statistics    │           └─────────────────┘
          │                   └─────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                    internal/filter/providers/                              │
│  ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────────────────────┐│
│  │    domain.go    │ │      ip.go      │ │           custom.go             ││
│  │ • Domain Rules  │ │ • IP Rules      │ │ • Plugin Architecture          ││
│  │ • Allow/Block   │ │ • Source Filter │ │ • Extensible Providers         ││
│  │ • Inspect Rules │ │ • CIDR Support  │ │ • Custom Logic Integration     ││
│  └─────────────────┘ └─────────────────┘ └─────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────┘
```

## Data Flow

```
Client Request
      │
      ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Proxy     │    │   Filter    │    │    Cert     │    │   Relay     │
│   Server    │───▶│   System    │───▶│  Manager    │───▶│   System    │
│             │    │             │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                   │                   │                   │
      │            ┌──────▼──────┐           │                   │
      │            │   Domain    │           │                   │
      │            │     IP      │           │                   │
      │            │   Custom    │           │                   │
      │            │  Providers  │           │                   │
      │            └─────────────┘           │                   │
      │                                      │                   │
      ▼                                      ▼                   ▼
┌─────────────┐                    ┌─────────────┐    ┌─────────────┐
│   Capture   │                    │ Certificate │    │  Upstream   │
│   System    │                    │ Generation  │    │   Server    │
│             │                    │             │    │             │
└─────────────┘                    └─────────────┘    └─────────────┘
```

## Component Responsibilities

### Core Systems
- **proxy/server.go**: Main server, connection handling, TLS detection
- **relay/relay.go**: High-performance bidirectional data forwarding
- **config/**: Configuration management with validation and legacy support

### Filtering & Rules
- **filter/manager.go**: Central filter orchestration and rule processing
- **filter/providers/**: Pluggable provider system for different rule types
- **filter/registry.go**: Provider registration and lifecycle management

### Certificate Management
- **cert/manager.go**: Automated certificate generation and caching
- **cert/types.go**: Certificate configuration and custom details

### HTTP Processing
- **capture/capture.go**: HTTP request/response capture and correlation
- **pkg/protocol/**: Protocol detection and HTTP parsing utilities

## Key Design Principles

1. **Modularity**: Each component has a single responsibility
2. **Extensibility**: Plugin-based provider system for filters
3. **Performance**: Optimized data paths and minimal allocations
4. **Configuration**: Comprehensive validation with backward compatibility
5. **Testing**: Each component is thoroughly tested in isolation

## Configuration Flow

```
config.json
     │
     ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Loader    │───▶│ Validator   │───▶│  Defaults   │───▶│ Components  │
│             │    │             │    │             │    │             │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
      │                   │                   │                   │
      │            ┌──────▼──────┐           │                   │
      │            │ • Proxy     │           │                   │
      │            │ • Logging   │           │                   │
      │            │ • TLS       │           │                   │
      │            │ • Filters   │           │                   │
      │            └─────────────┘           │                   │
      │                                      │                   │
      ▼                                      ▼                   ▼
┌─────────────┐                    ┌─────────────┐    ┌─────────────┐
│   Legacy    │                    │ Structured  │    │ Runtime     │
│ Migration   │                    │   Config    │    │ Components  │
│             │                    │             │    │             │
└─────────────┘                    └─────────────┘    └─────────────┘
```

This architecture ensures clean separation of concerns while maintaining high performance and extensibility. 