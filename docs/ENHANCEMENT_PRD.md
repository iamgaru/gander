-# Gander Enhancement PRD

## Overview
This document outlines the planned enhancements for Gander, building on the stable baseline of commit 3b6ae97. The goal is to systematically add features while maintaining stability and performance.

## Current State (Baseline - Commit 3b6ae97)

### What Works Well
- ✅ Core HTTP/HTTPS proxy functionality
- ✅ TLS certificate interception with Gamu CA
- ✅ Connection pooling (25% hit rate, 87% latency improvement)
- ✅ TLS session caching and resumption
- ✅ Certificate pre-generation for popular domains
- ✅ Basic domain and IP filtering
- ✅ Identity resolution (IP/MAC provider)
- ✅ Performance optimizations (fixed worker pool timeouts)

### Performance Characteristics
- **First HTTPS request:** ~1.9s (certificate generation + new connection)
- **Subsequent requests:** ~0.25s (with connection reuse)
- **Connection pool hit rate:** 25%
- **Resource stability:** To be validated through testing

### Known Limitations
- [Add limitations you've identified]
- [Add pain points from current usage]

## Proposed Features

### Feature 1: Logging improvements
**Priority:**
Medium
**Complexity:**
Simple

**Description:**
Need to simplify the logging to console such that it is minimal -

1.Very high level operations like start / stop, state change in config (note to self - implement a config watcher if it does not yet exist for live reload), regular interval updates ~ 1 min for current cx etc.

2. A proxy log that will still perform normal logging as it does now, with the option for adding in debugging statements that can be rendered if config.json stipulates this (again, config watcher required). This should live in the /logs directory.

3. Consider - though for now, just propose (do not implement yet) a simple system for adding in feature specific logs into the /log directory for actions like - inspection / cert-spoofing / filtering (verdicts on urls will explain later but essentially xyz.com allowed, abx.com blocked & reason), any panics that are incurred etc.

4. We need to simplify the captures  ... we did explore:
   (i) having a simple directory structure - domain
                                             - request
                                               - etc.

Any other suggestion for approach would be considered - but important to break up into tasks prior to implementing
**Technical Approach:**
- **Performance-first design** - async/buffered logging to prevent resource consumption over time
- Minimal console logging (start/stop, config changes, periodic status ~1min)
- Structured file logging in `/logs` with debug control via config watcher
- Clean capture organization by domain/request structure
- **Critical:** Avoid synchronous I/O, string formatting in hot paths, memory leaks

**Config Changes:**
```json
{
  "logging": {
    "console_level": "minimal",        // minimal, normal, debug
    "enable_debug": true,              // existing field
    "feature_logs_enabled": true,      // for future feature-specific logs  
    "status_interval": "1m"            // periodic status updates
  }
}
```

**Testing Strategy:**
- Functional: Unit tests for log levels, config reload, directory structure
- **Performance: Extended runtime testing (4+ hours) to ensure no resource degradation**
- Memory profiling before/after implementation
- Benchmark logging overhead in hot paths

**Risk Assessment:**
- **HIGH RISK:** Structured logging performance impact (may have contributed to previous resource issues)
- Mitigation: Async logging, minimal hot-path overhead, extended performance testing
- Console logging changes could break monitoring tools
- Capture restructure risk of data loss

---

### Feature 2: Pluggable Traffic Analysis System
**Priority:** High  
**Complexity:** High  
**Dependencies:** Feature 1 (config watcher, logging system)

**Description:**
Pluggable system for analyzing traffic with allow/block/redirect decisions. Uses adapter pattern for modularity. Each filter produces binary verdicts (allow/block) rather than just inspection. Supports both packet-level filtering (hostname/IP) and full proxy inspection (headers/body). All decisions logged to central verdict file for monitoring.

**Technical Approach:**
- **Phase 1:** Core hook system with header-only analysis (performance-safe)
- **Phase 2:** Add body analysis with strict size limits (1024 bytes initially)  
- **Performance-first design:** < 10ms per filter, < 50ms total per request
- **Adapter pattern:** Easy plugin registration/management
- **Binary decisions:** Every filter produces allow/block(/redirect) verdicts
- **Central logging:** All decisions to unified verdict log
- **Block page serving:** Static HTML embedded in binary for blocked requests
- **Integration points:** Packet filter hooks, proxy inspection hooks, response analysis

**Filter Interface:**
```go
type FilterDecision struct {
    Action   string // "allow", "block", "redirect"
    Reason   string // human-readable reason  
    Metadata map[string]interface{}
    BlockPage string // optional custom block page content
}

type TrafficFilter interface {
    FilterRequestHeaders(ctx *FilterContext) FilterDecision
    FilterResponseHeaders(ctx *FilterContext) FilterDecision
    // Future: Body analysis with size limits
}
```

**Initial Plugins:**
- **packetFilter** - hostname/IP blocklist (existing domain filter integration)
- **proxyFilter** - header analysis (User-Agent, Content-Type restrictions)
- **contentFilter** - future ML/text analysis (design only)
- **blockPageHandler** - serves static HTML block page for blocked requests

**Config Changes:**
```json
{
  "traffic_analysis": {
    "enabled": true,
    "plugins": ["packetFilter", "proxyFilter"],
    "performance": {
      "timeout_ms": 100,
      "max_body_size": 1024,
      "async_logging": true
    },
    "reporting": {
      "verdict_file": "logs/verdicts.log",
      "plugin_logs": true
    },
    "block_page": {
      "enabled": true,
      "template": "default",
      "show_reason": true,
      "show_timestamp": true
    },
    "filters": {
      "packetFilter": {
        "blocklist": ["malware.com", "*.suspicious.net"],
        "allowlist": ["trusted.com"]
      },
      "proxyFilter": {
        "blocked_user_agents": ["*bot*", "*crawler*"],
        "blocked_content_types": ["application/x-executable"]
      }
    }
  }
}
```

**Testing Strategy:**
- **Performance regression:** Strict < 10ms per filter, < 50ms total budgets
- **Extended runtime:** 4+ hours testing to ensure no resource degradation
- **Integration testing:** Verify existing proxy functionality unchanged
- **Plugin testing:** Individual filter functionality and error handling
- **Load testing:** High-volume traffic with multiple filters active
- **Verdict logging:** Async logging performance and accuracy

**Risk Assessment:**
- **HIGH RISK:** Performance impact in request hot path (could regress 1.9s→0.25s baseline)
- **HIGH RISK:** Architecture complexity could reintroduce resource consumption issues
- **MEDIUM RISK:** Integration with existing filter system could break current functionality
- **Mitigation:** Phased implementation, strict performance budgets, extensive testing
- **Mitigation:** Each phase independently disableable via config
- **Mitigation:** Async verdict logging to avoid blocking request flow
- **Rollback:** Maintain existing filter system as fallback, plugin-level disable capability

---

[Add more features as needed]

## Implementation Order

### Phase 1: Foundation
1. [Foundational feature that others depend on]

### Phase 2: Core Enhancements  
1. [Feature that builds on Phase 1]
2. [Another core feature]

### Phase 3: Advanced Features
1. [Complex features that require solid foundation]

## Risk Assessment

### High Risk Items
- [Features that could impact stability]
- [Complex architectural changes]

### Mitigation Strategies
- One feature at a time implementation
- Thorough testing before moving to next feature
- Easy rollback to previous working state
- Performance monitoring during implementation

### Rollback Plan
- Each feature implemented in separate commits
- Ability to revert to any previous working state
- Configuration backward compatibility where possible

## Success Metrics

### Performance Metrics
- [ ] No degradation in baseline performance (1.9s/0.25s targets)
- [ ] Resource usage remains stable over extended periods
- [ ] Connection pool efficiency maintained or improved

### Functionality Metrics
- [ ] All existing functionality continues to work
- [ ] New features work as specified
- [ ] Chrome TLS interception remains functional

### Quality Metrics
- [ ] Clean, maintainable code
- [ ] Comprehensive testing
- [ ] Clear documentation

## Notes
- Start with thorough testing of current baseline
- Focus on incremental, testable improvements
- Avoid "too smart" over-engineering
- Prioritize stability over complexity

---

**Document Status:** Draft  
**Last Updated:** [Date]  
**Next Review:** [Date]
