# Full Network Filtering Architecture Options

## Overview

This document outlines architectural approaches for evolving Gander from its current HTTP/HTTPS proxy-based filtering into a comprehensive multi-layer network traffic analysis and filtering platform capable of inspecting and controlling traffic at L3/L4/L7 layers.

## Current Architecture Limitations

### Current State (v0.2.0)
- **Scope**: Application-layer proxy (L7) focused on HTTP/HTTPS only
- **Traffic Capture**: Proxy-based interception on single port (e.g., :8848)
- **Protocol Support**: HTTP and HTTPS with TLS MITM
- **Filter Context**: Domain and IP-based rules
- **Deployment**: Explicit proxy or transparent proxy with iptables redirects

### Proposed Evolution Goals
- **Expanded Scope**: Multi-layer filtering (L3/L4/L7)
- **Protocol Coverage**: All IP traffic (TCP, UDP, ICMP, etc.)
- **Fine-grained Control**: Port-level, connection state, and protocol-specific filtering
- **Performance**: High-throughput packet processing capabilities
- **Flexibility**: Extensible protocol handling and filter strategies

## Architectural Options

### Option A: Layered Hybrid Architecture

**Concept**: Extend the current system by adding L3/L4 packet processing alongside the existing HTTP proxy engine.

```
┌─────────────────────────────────────────────────────────┐
│                    Filter Manager                       │
├─────────────────┬───────────────────┬───────────────────┤
│   L3/L4 Engine  │   L7 HTTP Engine  │  L7 Protocol      │
│   (Raw Packets) │   (Current Proxy) │  Extensions       │
│                 │                   │  (DNS, SSH, etc.) │
├─────────────────┼───────────────────┼───────────────────┤
│ • Raw sockets   │ • MITM proxy      │ • Protocol parsers│
│ • libpcap/AF_PACKET │ • Cert generation │ • Deep inspection │
│ • IP/TCP/UDP    │ • JSON capture    │ • Custom filters  │
│ • Connection    │ • Request/response│ • Specialized     │
│   tracking      │   correlation     │   capture formats │
└─────────────────┴───────────────────┴───────────────────┘
```

#### Implementation Details

**L3/L4 Packet Processing Engine**:
```go
type PacketEngine struct {
    capture     PacketCapture    // Raw packet source
    connTracker ConnectionTracker // TCP state management
    filters     []L34Filter      // Network/transport filters
    dispatcher  ProtocolDispatcher // Route to L7 engines
}

type L34FilterContext struct {
    SrcIP, DstIP     net.IP
    SrcPort, DstPort uint16
    Protocol         uint8  // TCP=6, UDP=17, etc.
    ConnState        TCPState
    PacketData       []byte
    Direction        PacketDirection
    Timestamp        time.Time
}
```

**Integration Points**:
- **Packet-to-Proxy Handoff**: L3/L4 engine identifies HTTP traffic and hands off to existing proxy
- **Unified Logging**: Correlate packet-level and application-level events
- **Shared Filter Rules**: Common rule configuration across layers

#### Advantages
- **Incremental Evolution**: Preserves existing HTTP functionality and investment
- **Risk Mitigation**: Can be developed and tested in parallel with current system
- **Specialized Optimization**: Each engine optimized for its specific use case
- **Backward Compatibility**: Existing configurations and features remain functional

#### Disadvantages
- **Architectural Complexity**: Multiple engines with coordination overhead
- **Potential Duplication**: HTTP traffic processed by both engines
- **Resource Overhead**: Multiple packet capture and processing pipelines
- **Configuration Complexity**: Need to manage multiple engine configurations

#### Implementation Phases
1. **Phase 1A**: Add basic packet capture capability (libpcap integration)
2. **Phase 1B**: Implement TCP connection tracking and state management
3. **Phase 1C**: Create L3/L4 filter interfaces and basic IP/port filtering
4. **Phase 1D**: Integration with existing HTTP proxy for unified logging
5. **Phase 1E**: Performance optimization and memory management

---

### Option B: Unified Packet Processing Engine

**Concept**: Rebuild the system around a single, unified packet processing engine that handles all layers.

```
┌─────────────────────────────────────────────────────────┐
│              Packet Capture & Injection                 │
│     (libpcap, eBPF, netfilter, raw sockets)            │
├─────────────────────────────────────────────────────────┤
│           Protocol Detection & Parsing                  │
│  ┌─────────────┬─────────────┬─────────────┬─────────┐  │
│  │     L3      │     L4      │     L7      │  Custom │  │
│  │   (IP)      │ (TCP/UDP)   │(HTTP/DNS/..│ Plugins │  │
│  └─────────────┴─────────────┴─────────────┴─────────┘  │
├─────────────────────────────────────────────────────────┤
│        Unified Multi-Layer Filter System                │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  Filter Chain (L3 → L4 → L7 → Decision)           │ │
│  └─────────────────────────────────────────────────────┘ │
├─────────────────────────────────────────────────────────┤
│         Action Engine (ALLOW/BLOCK/INSPECT/LOG)         │
└─────────────────────────────────────────────────────────┘
```

#### Implementation Details

**Unified Filter Context**:
```go
type UnifiedFilterContext struct {
    // Packet-level data
    RawPacket    []byte
    PacketTime   time.Time
    Direction    PacketDirection
    
    // L3 Network Layer
    L3 *L3Context // IP headers, addresses, protocol
    
    // L4 Transport Layer  
    L4 *L4Context // TCP/UDP ports, flags, sequence numbers
    
    // L7 Application Layer
    L7 *L7Context // Protocol-specific parsed data
    
    // Connection state
    Connection *ConnectionState
    
    // Metadata
    Interface  string
    Tags       map[string]interface{}
}

type L3Context struct {
    SrcIP, DstIP net.IP
    Protocol     uint8
    TTL          uint8
    Length       uint16
    Fragmented   bool
}

type L4Context struct {
    SrcPort, DstPort uint16
    TCPFlags         uint8
    SequenceNum      uint32
    WindowSize       uint16
    ConnState        TCPConnState
}

type L7Context struct {
    Protocol    string // "HTTP", "DNS", "SSH", etc.
    ParsedData  interface{} // Protocol-specific structures
    Confidence  float32 // Detection confidence level
}
```

**Protocol Detection Pipeline**:
```go
type ProtocolDetector interface {
    Name() string
    DetectProtocol(ctx *UnifiedFilterContext) (confidence float32, err error)
    ParsePacket(ctx *UnifiedFilterContext) error
}

// Example implementations
type HTTPDetector struct {
    patterns [][]byte // "GET ", "POST ", "HTTP/", etc.
}

type DNSDetector struct {
    // DNS packet structure validation
}

type SSHDetector struct {
    handshakeParser *SSHHandshakeParser
}
```

#### Advantages
- **Clean Architecture**: Single processing pipeline, no duplication
- **Unified Context**: Complete packet information available to all filters
- **Performance Potential**: Optimized single-pass processing
- **Consistent Interface**: Same filter interface across all layers
- **Easier Testing**: Single engine to test and validate

#### Disadvantages
- **Complete Rewrite**: Existing HTTP proxy functionality must be rebuilt
- **Higher Risk**: All functionality depends on new engine working correctly
- **Development Time**: Longer initial development cycle
- **Learning Curve**: More complex initial implementation

#### Implementation Phases
1. **Phase 2A**: Core packet capture and basic L3 parsing
2. **Phase 2B**: TCP connection tracking and L4 parsing
3. **Phase 2C**: Protocol detection framework and HTTP parser
4. **Phase 2D**: Filter system integration and rule engine
5. **Phase 2E**: Rebuild HTTP MITM and certificate functionality
6. **Phase 2F**: JSON capture system integration

---

### Option C: Plugin-Based Multi-Engine Architecture

**Concept**: Create a flexible framework where different protocol engines can be plugged in as needed.

```
┌─────────────────────────────────────────────────────────┐
│                 Engine Registry                         │
│  ┌─────────────┬─────────────┬─────────────┬─────────┐  │
│  │    HTTP     │     TCP     │     UDP     │   DNS   │  │
│  │   Engine    │   Engine    │   Engine    │ Engine  │  │
│  └─────────────┴─────────────┴─────────────┴─────────┘  │
├─────────────────────────────────────────────────────────┤
│              Traffic Classification                     │
│           (Route packets to engines)                    │
├─────────────────────────────────────────────────────────┤
│          Multi-Source Capture Layer                     │
│  ┌─────────────┬─────────────┬─────────────┬─────────┐  │
│  │  Raw Socket │  HTTP Proxy │   TUN/TAP   │  eBPF   │  │
│  │   Capture   │   (current) │  Interface  │  Hook   │  │
│  └─────────────┴─────────────┴─────────────┴─────────┘  │
└─────────────────────────────────────────────────────────┘
```

#### Implementation Details

**Engine Interface**:
```go
type ProtocolEngine interface {
    Name() string
    SupportedProtocols() []string
    CanHandle(ctx *FilterContext) bool
    ProcessPacket(ctx *FilterContext) (*EngineResult, error)
    GetFilters() []ProtocolFilter
    Initialize(config EngineConfig) error
    Shutdown() error
}

type EngineResult struct {
    Decision    FilterDecision
    Metadata    map[string]interface{}
    ModifiedData []byte // For packet modification
    CaptureData  *CaptureRecord
}
```

**HTTP Engine (Evolved from Current)**:
```go
type HTTPEngine struct {
    proxy       *HTTPProxy
    mitm        *MITMManager
    capture     *HTTPCaptureManager
    filters     []HTTPFilter
}

func (e *HTTPEngine) CanHandle(ctx *FilterContext) bool {
    return ctx.L4.DstPort == 80 || ctx.L4.DstPort == 443 ||
           e.detectHTTPTraffic(ctx.PacketData)
}
```

**TCP Engine (New)**:
```go
type TCPEngine struct {
    connTracker  *TCPConnectionTracker
    stateFilters []TCPStateFilter
    portFilters  []PortFilter
}

func (e *TCPEngine) ProcessPacket(ctx *FilterContext) (*EngineResult, error) {
    // Track connection state
    conn := e.connTracker.GetOrCreateConnection(ctx)
    
    // Apply TCP-specific filters
    for _, filter := range e.stateFilters {
        if result := filter.FilterTCPState(conn); result != FilterAllow {
            return &EngineResult{Decision: result}, nil
        }
    }
    
    return &EngineResult{Decision: FilterAllow}, nil
}
```

**UDP Engine (New)**:
```go
type UDPEngine struct {
    dnsParser    *DNSParser
    dhcpParser   *DHCPParser
    portFilters  []PortFilter
}
```

#### Advantages
- **Maximum Flexibility**: Easy to add new protocols without touching core
- **Specialized Optimization**: Each engine optimized for its specific protocols
- **Parallel Development**: Teams can work on different engines independently
- **Gradual Migration**: Can migrate protocols one at a time from current system
- **Third-party Extensions**: External developers can create custom engines

#### Disadvantages
- **Coordination Complexity**: Managing interactions between engines
- **Resource Management**: Need to coordinate memory/CPU usage across engines
- **Configuration Complexity**: Each engine may have different configuration needs
- **Testing Complexity**: Must test engine interactions and edge cases

#### Implementation Phases
1. **Phase 3A**: Design and implement engine registry framework
2. **Phase 3B**: Extract current HTTP functionality into HTTP engine
3. **Phase 3C**: Create basic TCP and UDP engines with port filtering
4. **Phase 3D**: Implement traffic classification and routing logic
5. **Phase 3E**: Add DNS engine with specialized parsing
6. **Phase 3F**: Performance optimization and engine coordination

---

## Technical Implementation Considerations

### Packet Capture Technologies

#### Raw Sockets (Cross-platform)
```go
// Linux: AF_PACKET
// Windows: WinPcap/Npcap  
// macOS: BPF device

type RawSocketCapture struct {
    socket    int
    buffer    []byte
    interface string
}
```

**Pros**: Cross-platform, userspace, no special drivers
**Cons**: Performance limitations, requires root/admin privileges

#### eBPF Programs (Linux-specific)
```go
type eBPFCapture struct {
    program    *ebpf.Program
    maps       map[string]*ebpf.Map
    perfReader *perf.Reader
}
```

**Pros**: Kernel-level performance, programmable filtering
**Cons**: Linux-only, complex development, requires recent kernels

#### Netfilter Hooks (Linux-specific)
```go
type NetfilterCapture struct {
    queue    *netfilter.NFQueue
    hooks    []netfilter.Hook
    verdict  chan netfilter.Verdict
}
```

**Pros**: Kernel integration, can modify/drop packets
**Cons**: Linux-only, requires root, affects system networking

#### TUN/TAP Interface
```go
type TUNCapture struct {
    device   *water.Interface
    routes   []Route
    bridge   *NetworkBridge
}
```

**Pros**: Clean userspace interface, can create virtual networks
**Cons**: Requires network reconfiguration, more complex setup

### Performance Considerations

#### Zero-Copy Packet Processing
```go
type PacketBuffer struct {
    data     []byte
    capacity int
    refCount int32
}

type PacketPool struct {
    buffers chan *PacketBuffer
    size    int
}

func (p *PacketPool) Get() *PacketBuffer {
    select {
    case buf := <-p.buffers:
        return buf
    default:
        return &PacketBuffer{
            data:     make([]byte, p.size),
            capacity: p.size,
            refCount: 1,
        }
    }
}
```

#### Concurrent Processing Pipeline
```go
type ProcessingPipeline struct {
    capture    chan *PacketBuffer
    classify   chan *ClassifiedPacket  
    filter     chan *FilteredPacket
    action     chan *ActionablePacket
    
    workers    []Worker
    bufferPool *PacketPool
}

func (p *ProcessingPipeline) Start() {
    // Start worker goroutines for each stage
    go p.captureWorker()
    go p.classifyWorker()
    go p.filterWorker()
    go p.actionWorker()
}
```

#### Memory Management
```go
type ConnectionTracker struct {
    connections map[ConnectionKey]*Connection
    expiry      *time.Timer
    maxConns    int
    gcInterval  time.Duration
}

func (ct *ConnectionTracker) cleanup() {
    // Periodic cleanup of expired connections
    // LRU eviction when hitting limits
    // Memory pool reuse
}
```

### Protocol Detection Strategies

#### Port-Based Classification
```go
var WellKnownPorts = map[uint16]string{
    80:   "http",
    443:  "https", 
    53:   "dns",
    22:   "ssh",
    25:   "smtp",
    110:  "pop3",
    143:  "imap",
    993:  "imaps",
    995:  "pop3s",
}
```

#### Deep Packet Inspection
```go
type ProtocolSignature struct {
    Protocol    string
    Patterns    [][]byte
    Offset      int
    MinLength   int
    Confidence  float32
}

var HTTPSignatures = []ProtocolSignature{
    {
        Protocol:   "http",
        Patterns:   [][]byte{[]byte("GET "), []byte("POST "), []byte("PUT ")},
        Offset:     0,
        MinLength:  4,
        Confidence: 0.9,
    },
    {
        Protocol:   "http-response", 
        Patterns:   [][]byte{[]byte("HTTP/1.0 "), []byte("HTTP/1.1 "), []byte("HTTP/2.0 ")},
        Offset:     0,
        MinLength:  9,
        Confidence: 0.95,
    },
}
```

#### Stateful Protocol Analysis
```go
type ProtocolStateMachine struct {
    currentState State
    transitions  map[StateTransition]State
    timeout      time.Duration
}

// Example: TLS handshake detection
type TLSStateMachine struct {
    state        TLSState // CLIENT_HELLO, SERVER_HELLO, etc.
    version      uint16
    cipherSuites []uint16
    sni          string
}
```

### Configuration Evolution

#### Multi-Layer Rule Configuration
```json
{
  "capture": {
    "interfaces": ["eth0", "lo"],
    "methods": ["raw_socket", "ebpf"],
    "buffer_size": 65536,
    "worker_count": 4
  },
  "filters": {
    "l3": {
      "allow_ips": ["192.168.1.0/24"],
      "block_ips": ["10.0.0.0/8"],
      "protocols": ["tcp", "udp", "icmp"]
    },
    "l4": {
      "tcp": {
        "allow_ports": [80, 443, 22],
        "block_ports": [23, 135, 139],
        "track_connections": true,
        "connection_timeout": "5m"
      },
      "udp": {
        "allow_ports": [53, 67, 68],
        "block_ports": [161, 162],
        "stateless": true
      }
    },
    "l7": {
      "http": {
        "inspect_domains": ["*.example.com"],
        "mitm_enabled": true,
        "capture_bodies": true
      },
      "dns": {
        "log_queries": true,
        "block_domains": ["*.malware.com"],
        "inspect_responses": true
      }
    }
  },
  "engines": {
    "enabled": ["http", "tcp", "udp", "dns"],
    "http": {
      "proxy_port": 8080,
      "mitm_ca": "certs/ca.crt"
    },
    "dns": {
      "parse_responses": true,
      "track_resolutions": true
    }
  }
}
```

## Migration Strategy

### Phase-Based Implementation

#### Phase 1: Foundation (2-3 months)
- Choose architectural option based on requirements analysis
- Implement basic packet capture infrastructure
- Create multi-layer filter interfaces
- Basic L3/L4 filtering functionality
- Integration testing with current HTTP system

#### Phase 2: Core Protocols (3-4 months)  
- TCP connection tracking and state management
- UDP packet filtering
- DNS protocol parsing and filtering
- Performance optimization and memory management
- Comprehensive logging integration

#### Phase 3: Advanced Features (2-3 months)
- Protocol detection and classification
- Advanced L7 protocol support (SSH, SMTP, etc.)
- Real-time configuration reloading
- Monitoring and statistics dashboard
- Documentation and deployment guides

#### Phase 4: Production Hardening (1-2 months)
- Performance benchmarking and optimization
- Security audit and hardening
- High-availability features
- Operational tooling and monitoring
- Migration tools from v0.2.x

### Backward Compatibility Strategy

#### Configuration Migration
```go
type ConfigMigrator struct {
    fromVersion string
    toVersion   string
    migrations  []MigrationStep
}

func (cm *ConfigMigrator) MigrateConfig(oldConfig *v2.Config) (*v3.Config, error) {
    // Convert v0.2.x HTTP-focused config to multi-layer config
    newConfig := &v3.Config{}
    
    // Migrate HTTP rules to L7 engine config
    newConfig.Engines.HTTP.InspectDomains = oldConfig.Rules.InspectDomains
    
    // Convert IP rules to L3 filters
    newConfig.Filters.L3.AllowIPs = oldConfig.Rules.InspectIPs
    
    return newConfig, nil
}
```

#### Feature Compatibility
- Maintain existing HTTP proxy functionality during transition
- Provide compatibility shims for current API interfaces
- Support both old and new configuration formats
- Gradual deprecation of old features with clear migration paths

## Performance Benchmarks & Targets

### Current Performance (v0.2.x)
- **HTTP Throughput**: ~500 requests/second (with MITM)
- **Connection Latency**: <10ms overhead for inspected traffic
- **Memory Usage**: ~50MB baseline + ~1KB per active connection
- **CPU Usage**: ~15% on modern hardware for moderate load

### Target Performance (Multi-layer)
- **Packet Processing**: 1M+ packets/second (raw filtering)
- **L7 Inspection**: 10K+ HTTP requests/second (with MITM)
- **Connection Tracking**: 100K+ concurrent TCP connections
- **Memory Efficiency**: <5KB per tracked connection
- **Latency Overhead**: <5ms for L3/L4 filtering, <15ms for L7 inspection

### Benchmarking Framework
```go
type PerformanceBenchmark struct {
    name           string
    packetRate     int    // packets per second
    connectionRate int    // new connections per second
    duration       time.Duration
    
    results        BenchmarkResults
}

type BenchmarkResults struct {
    PacketsProcessed    int64
    ConnectionsTracked  int64
    MemoryUsageMB      float64
    CPUUsagePercent    float64
    AverageLatencyMs   float64
    DroppedPackets     int64
}
```

## Risk Assessment & Mitigation

### Technical Risks

#### Performance Degradation
**Risk**: Multi-layer processing could significantly impact performance
**Mitigation**: 
- Extensive benchmarking during development
- Configurable processing depth (L3-only mode for high throughput)
- Efficient packet buffer management and zero-copy operations

#### Platform Compatibility
**Risk**: Advanced features may not work across all platforms
**Mitigation**:
- Graceful feature degradation on unsupported platforms
- Multiple capture backend implementations
- Clear documentation of platform-specific limitations

#### Memory Exhaustion
**Risk**: Connection tracking could consume excessive memory
**Mitigation**:
- Configurable connection limits and timeouts
- LRU eviction policies for connection tracking
- Memory pool reuse and garbage collection optimization

### Operational Risks

#### Configuration Complexity
**Risk**: Multi-layer configuration may be too complex for users
**Mitigation**:
- Sensible defaults and preset configurations
- Configuration validation and error reporting
- Migration tools and documentation

#### Deployment Complexity
**Risk**: Raw packet capture requires elevated privileges and network changes
**Mitigation**:
- Multiple deployment modes (proxy, transparent, tap)
- Clear installation and setup documentation
- Docker containers with proper capability configuration

## Future Extensions

### Potential Protocol Support
- **QUIC/HTTP3**: Next-generation HTTP protocol
- **gRPC**: High-performance RPC framework
- **MQTT**: IoT messaging protocol
- **WebRTC**: Real-time communication protocols
- **Custom Protocols**: Plugin framework for proprietary protocols

### Advanced Features
- **Machine Learning**: Anomaly detection and behavioral analysis
- **Geo-filtering**: Location-based traffic filtering
- **DPI Evasion Detection**: Identify traffic that attempts to evade inspection
- **API Integration**: REST/GraphQL APIs for external system integration
- **Clustering**: Distributed filtering across multiple nodes

### Integration Possibilities
- **SIEM Integration**: Send events to security information systems
- **Threat Intelligence**: Integration with threat feeds and IOC databases
- **Network Visualization**: Real-time network topology and flow visualization
- **Compliance Reporting**: Automated compliance checking and reporting

## Conclusion

This document provides three distinct architectural paths for evolving Gander into a comprehensive network filtering platform. Each option presents different trade-offs between complexity, performance, and development effort.

The **Layered Hybrid Architecture (Option A)** offers the safest migration path with incremental development, while the **Unified Packet Processing Engine (Option B)** provides the cleanest long-term architecture. The **Plugin-Based Multi-Engine Architecture (Option C)** maximizes flexibility but requires careful coordination.

The choice between these options should be based on:
- Available development resources and timeline
- Performance requirements and target environments  
- Desired feature set and protocol coverage
- Risk tolerance for architectural changes
- Long-term vision for the platform

All options maintain the core strength of Gander's current filter system while expanding capabilities to handle the full spectrum of network traffic analysis and control. 