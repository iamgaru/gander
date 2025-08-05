# Feature-Specific Logging Design

**Task Reference:** Task 4.1 - Feature-Specific Logging Design  
**Status:** Design Phase (Implementation in Future Sprint)  
**Estimated Implementation:** 6-8 hours total

## Overview

This document outlines the design for five feature-specific log files that will enhance observability and debugging capabilities while maintaining performance and consistency with the existing logging infrastructure.

## Current State Analysis

### Existing Logging Patterns
- **Structured logging** with correlation IDs in `internal/proxy/server.go`
- **Console level control** (`minimal`, `normal`, `debug`) via `console_level` config
- **File-only detailed logs** with rotation at `logs/proxy.log`
- **Critical message handling** always shown on console via `Logger.Critical()`

### Current Logging Locations Identified

#### Filtering/Inspection Decisions
- Location: `internal/proxy/server.go` (lines ~150-200)
- Current format: Structured with correlation IDs
- Examples:
  ```go
  s.logger.InfoStructured(info.CorrelationID, "Connection blocked by filter",
      "client_ip", info.ClientIP, "domain", info.Domain, "reason", decision.Reason)
  s.logger.DebugStructured(info.CorrelationID, "Connection bypassed", 
      "domain", info.Domain, "reason", decision.Reason)
  ```

#### Certificate Operations
- Location: `internal/cert/manager.go` and `internal/cert/pregeneration.go`
- Current format: Basic log.Printf statements
- Examples:
  ```go
  log.Printf("Worker %d pre-generated certificate for %s in %v", w.id, domain, duration)
  log.Printf("Worker %d failed to pre-generate certificate for %s: %v", w.id, domain, err)
  ```

#### Error Handling
- Location: `internal/logging/logger.go` (Critical method)
- Current format: Always console + file with timestamp
- Pattern: `[timestamp] CRITICAL: message`

## Proposed Feature-Specific Logs

### 1. `/logs/filtering.log`
**Purpose:** Unified filtering verdicts regardless of inspection method

**Log Format:**
```
[2025-07-30T15:04:05Z] [correlationID] target=evil.com verdict=blocked method=domain_inspection reason="domain_match" client_ip=192.168.1.100
[2025-07-30T15:04:05Z] [correlationID] target=google.com verdict=allowed method=sni_sniff reason="uninspected_domain" client_ip=192.168.1.100
[2025-07-30T15:04:05Z] [correlationID] target=192.168.1.50 verdict=blocked method=ip_filtering reason="blocked_ip_range" client_ip=192.168.1.100
[2025-07-30T15:04:05Z] [correlationID] target=https://evil.com/malware verdict=blocked method=url_analysis reason="malware_detected" client_ip=192.168.1.100
```

**Fields:**
- `timestamp` (ISO 8601)
- `correlation_id` (for request tracing)
- `target` (domain/IP/URL being filtered)
- `client_ip` (source IP)
- `verdict` (allowed|blocked|flagged)
- `method` (domain_inspection|sni_sniff|ip_filtering|url_analysis)
- `reason` (specific filter rule/pattern matched)

### 2. `/logs/certificates.log`
**Purpose:** Certificate generation, cache events, and lifecycle tracking

**Log Format:**
```
[2025-07-30T15:04:05Z] action=generate domain=example.com duration=15ms status=success
[2025-07-30T15:04:05Z] action=cache_hit domain=google.com
[2025-07-30T15:04:05Z] action=pregenerate domain=youtube.com worker_id=2 duration=45ms status=success
[2025-07-30T15:04:05Z] action=expire domain=old.com cache_age=24h
[2025-07-30T15:04:05Z] action=generate domain=fail.com duration=200ms status=error error="x509: certificate signed by unknown authority"
```

**Fields:**
- `timestamp` (ISO 8601)
- `action` (generate|cache_hit|cache_miss|pregenerate|expire|cleanup)
- `domain` (certificate domain)
- `duration` (operation time for generate/pregenerate)
- `status` (success|error)
- `worker_id` (for pregeneration operations)
- `error` (for failed operations)
- `cache_age` (for expiration events)

### 3. `/logs/errors.log`
**Purpose:** Critical errors, panics, and system failures

**Log Format:**
```
[2025-07-30T15:04:05Z] level=panic component=proxy error="runtime error: invalid memory address" stack_trace="goroutine 123..."
[2025-07-30T15:04:05Z] level=critical component=cert_manager error="failed to load CA certificate" file_path="/app/certs/ca.crt"
[2025-07-30T15:04:05Z] level=error component=config_watcher error="config file not found" file_path="/app/config.json"
```

**Fields:**
- `timestamp` (ISO 8601)
- `level` (panic|critical|error)
- `component` (proxy|cert_manager|config_watcher|filter|etc)
- `error` (error message)
- `stack_trace` (for panics)
- `file_path` (for file-related errors)
- `additional_context` (component-specific fields)

### 4. `/logs/performance.log`
**Purpose:** Performance metrics and slow request tracking

**Log Format:**
```
[2025-07-30T15:04:05Z] metric=request_duration value=250ms threshold=200ms domain=slow.com client_ip=192.168.1.100
[2025-07-30T15:04:05Z] metric=cert_generation_time value=45ms domain=new-site.com
[2025-07-30T15:04:05Z] metric=memory_usage value=256MB component=cert_cache
[2025-07-30T15:04:05Z] metric=connection_pool_size value=45 max_size=500 component=proxy
```

**Fields:**
- `timestamp` (ISO 8601)
- `metric` (request_duration|cert_generation_time|memory_usage|connection_pool_size|etc)
- `value` (measured value with units)
- `threshold` (for alerts, optional)
- `component` (system component being measured)
- `domain` (for request-specific metrics)
- `client_ip` (for request-specific metrics)

## Technical Implementation Strategy

### Log Rotation Configuration
```json
{
  "logging": {
    "feature_logs": {
      "enabled": true,
      "max_file_size_mb": 50,
      "max_files": 10,
      "compression": true,
      "logs": {
        "filtering": {
          "enabled": true,
          "level": "info"
        },
        "certificates": {
          "enabled": true,
          "level": "info"
        },
        "errors": {
          "enabled": true,
          "level": "error"
        },
        "performance": {
          "enabled": false,
          "level": "info",
          "slow_threshold_ms": 200
        }
      }
    }
  }
}
```

### Logger Interface Design
```go
type FeatureLogger interface {
    LogFiltering(correlationID, target, clientIP, verdict, method, reason string)
    LogCertificate(action, domain string, duration time.Duration, status string, extra map[string]interface{})
    LogError(level, component, error string, extra map[string]interface{})
    LogPerformance(metric string, value interface{}, extra map[string]interface{})
}
```

### Integration Points

#### 1. Filtering Logging Integration
- **Location:** `internal/proxy/server.go` (existing filter decision logic)
- **Method:** Extend existing `InfoStructured` calls to also write to filtering.log
- **No breaking changes:** Existing logging preserved

#### 2. Certificate Logging Integration  
- **Location:** `internal/cert/manager.go` and `internal/cert/pregeneration.go`
- **Method:** Replace `log.Printf` with structured certificate logging
- **Performance consideration:** Async logging for high-frequency cert operations

#### 3. Error Logging Integration
- **Location:** `internal/logging/logger.go` (existing Critical method)
- **Method:** Extend `Critical` method to write to errors.log
- **Maintain existing behavior:** Console output unchanged

#### 4. Performance Logging Integration
- **Location:** Add timing measurements around key operations
- **Strategy:** Conditional logging based on thresholds to avoid noise
- **Future enhancement:** Only log slow operations by default

## Performance Considerations

### Write Performance
- **Async logging:** Use buffered channels for high-frequency logs (certificates, performance)
- **Batch writes:** Group multiple log entries for disk efficiency
- **Memory management:** Pre-allocate log formatters to avoid allocation overhead

### File I/O Optimization
- **Dedicated file handles:** One per log file to avoid open/close overhead
- **Write-ahead buffers:** In-memory buffering before disk writes
- **Rotation efficiency:** Background rotation to avoid blocking main threads

### Configuration Granularity
- **Per-log enablement:** Turn individual logs on/off
- **Level control:** Info/debug levels per log type
- **Threshold-based:** Only log performance metrics above thresholds

## Backward Compatibility

### Existing Log Preservation
- **Console logging:** No changes to current console output behavior
- **File logging:** `logs/proxy.log` continues with all existing content
- **Configuration:** New feature logs are opt-in via config

### Migration Strategy
- **Phase 1:** Add feature logs alongside existing logs (dual logging)
- **Phase 2:** Gradually migrate verbose content from proxy.log to feature logs
- **Phase 3:** Clean up proxy.log to focus on general operations

## Future Extensions

### Additional Feature-Specific Logs

The current design establishes a pattern that can be extended for other system components:

#### `/logs/auth.log` - Identity and Authentication Events
```
[2025-07-30T15:04:05Z] [correlationID] client_ip=192.168.1.100 identity_method=ip_mac identity=user123 status=authenticated device_name="Johns-MacBook"
[2025-07-30T15:04:05Z] [correlationID] client_ip=192.168.1.50 identity_method=ip_mac status=failed reason="unknown_device" mac_address="aa:bb:cc:dd:ee:ff"
[2025-07-30T15:04:05Z] [correlationID] client_ip=192.168.1.100 identity_method=ip_mac identity=user123 status=cached cache_age=45m
```

#### `/logs/config.log` - Configuration Management Events
```
[2025-07-30T15:04:05Z] component=config_watcher action=reload config_file=/app/config.json status=success changes=["logging.console_level","rules.inspect_domains"]
[2025-07-30T15:04:05Z] component=config_watcher action=validation config_file=/app/config.json status=error error="invalid JSON syntax at line 15"
[2025-07-30T15:04:05Z] component=config_watcher action=file_changed config_file=/app/config.json size_bytes=2048 trigger=file_system_event
```

#### `/logs/storage.log` - Storage and Compression Events
```
[2025-07-30T15:04:05Z] action=capture_saved domain=example.com size_mb=2.5 compression=gzip file_path=captures/example.com/2025-07-30/001.json.gz
[2025-07-30T15:04:05Z] action=log_rotation log_file=proxy.log old_size_mb=100 new_file=proxy.log.1 compressed=true
[2025-07-30T15:04:05Z] action=cleanup target=captures retention_period=720h deleted_files=15 freed_space_mb=250
```

#### `/logs/network.log` - Network-Level Events
```
[2025-07-30T15:04:05Z] [correlationID] event=connection_opened client_ip=192.168.1.100 proxy_port=8848 target_host=example.com target_port=443
[2025-07-30T15:04:05Z] [correlationID] event=connection_closed client_ip=192.168.1.100 duration=15s bytes_sent=2048 bytes_received=8192
[2025-07-30T15:04:05Z] [correlationID] event=connection_timeout client_ip=192.168.1.100 target_host=slow.com timeout_seconds=30
```

### Extensibility Design Principles

#### Consistent Format Pattern
All future logs follow the established format:
```
[ISO8601_timestamp] [optional_correlationID] key=value key2=value2 ...
```

#### Unified Configuration
Future logs integrate into existing config structure:
```json
{
  "logging": {
    "feature_logs": {
      "logs": {
        "filtering": { "enabled": true, "level": "info" },
        "certificates": { "enabled": true, "level": "info" },
        "errors": { "enabled": true, "level": "error" },
        "performance": { "enabled": false, "level": "info" },
        "auth": { "enabled": false, "level": "info" },
        "config": { "enabled": true, "level": "info" },
        "storage": { "enabled": false, "level": "debug" },
        "network": { "enabled": false, "level": "debug" }
      }
    }
  }
}
```

#### Interface Extension
The `FeatureLogger` interface can be extended without breaking existing implementations:
```go
type FeatureLogger interface {
    // Current methods
    LogFiltering(correlationID, target, clientIP, verdict, method, reason string)
    LogCertificate(action, domain string, duration time.Duration, status string, extra map[string]interface{})
    LogError(level, component, error string, extra map[string]interface{})
    LogPerformance(metric string, value interface{}, extra map[string]interface{})
    
    // Future extensions
    LogAuth(correlationID, clientIP, identityMethod, identity, status, reason string)
    LogConfig(component, action, configFile, status string, extra map[string]interface{})
    LogStorage(action string, extra map[string]interface{})
    LogNetwork(correlationID, event, clientIP string, extra map[string]interface{})
}
```

## Future Enhancements

### Log Analysis Integration
- **Structured format:** JSON output option for log analysis tools
- **Metrics export:** Prometheus/OpenTelemetry integration points
- **Dashboard ready:** Fields designed for time-series analysis

### Advanced Features
- **Sampling:** Log every Nth occurrence for high-volume events
- **Alerting hooks:** Trigger external alerts on error log entries
- **Cross-correlation:** Link related entries across different feature logs

## Implementation Phases

### Phase 1: Core Infrastructure (2-3 hours)
- Create `FeatureLogger` interface
- Implement file rotation for feature logs
- Add configuration support

### Phase 2: Filtering & Certificate Logs (2-3 hours) 
- Integrate filtering.log with existing filter decisions
- Integrate certificates.log with cert manager operations
- Test with existing workloads

### Phase 3: Error & Performance Logs (2-3 hours)
- Extend error logging to errors.log
- Add performance measurement points
- Performance testing and optimization

---

**Next Steps:**
1. Review design with stakeholders
2. Create implementation tickets for each phase
3. Begin Phase 1 development when approved