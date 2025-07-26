# Feature 1: Logging Improvements - Implementation Tasks

**Feature Reference:** Enhancement PRD Feature 1  
**Priority:** Medium  
**Complexity:** Simple  
**Status:** Planning

## Task Breakdown

### Phase 1: Foundation & Config Watcher

#### Task 1.1: Implement Config Watcher
**Estimate:** 2-3 hours  
**Priority:** High (needed for live reload)

**Description:**
Create a config file watcher for live reloading of logging settings without restart.

**Implementation:**
- [ ] Create `internal/config/watcher.go` (if doesn't exist or enhance existing)
- [ ] Watch for `config.json` file changes
- [ ] Reload logging configuration on change
- [ ] Notify other components of config changes
- [ ] Handle file errors gracefully

**Testing:**
- [ ] Change logging config while running
- [ ] Verify logging behavior changes immediately
- [ ] Test with invalid config (should not crash)

**Config Impact:**
```json
{
  "logging": {
    "console_level": "minimal",
    "status_interval": "1m"
  }
}
```

---

#### Task 1.2: Console Logging Refactor
**Estimate:** 3-4 hours  
**Priority:** High

**Description:**
Implement minimal console logging with high-level operations only.

**Implementation:**
- [ ] Create console logger wrapper
- [ ] Implement log levels: `minimal`, `normal`, `debug`
- [ ] **Minimal level shows:**
  - [ ] Startup/shutdown messages
  - [ ] Config changes
  - [ ] Periodic status (connection count, active sessions)
  - [ ] Critical errors only
- [ ] Move verbose logs to file-only
- [ ] Add timestamp formatting for console

**Current Verbose Logs to Move to File:**
- [ ] Individual connection logs
- [ ] Certificate generation details  
- [ ] Pool connection reuse messages
- [ ] TLS session cache hits/misses

**Testing:**
- [ ] Verify minimal console output
- [ ] Test all three log levels
- [ ] Ensure critical info still visible

---

### Phase 2: Structured File Logging

#### Task 2.1: Enhanced Proxy Logging
**Estimate:** 2-3 hours  
**Priority:** Medium

**Description:**
Improve structured logging to `/logs/proxy.log` with debug control.

**Implementation:**
- [ ] Create structured log format (JSON or key-value)
- [ ] Separate debug statements (controlled by config)
- [ ] Add log rotation for proxy.log
- [ ] Include correlation IDs for request tracking
- [ ] Performance-optimized logging (async if needed)

**Log Structure:**
```
[TIMESTAMP] [LEVEL] [COMPONENT] message key=value key2=value2
```

**Testing:**
- [ ] Debug on/off via config change (live reload)
- [ ] Log rotation works correctly
- [ ] Performance impact minimal

---

#### Task 2.2: Periodic Status Updates
**Estimate:** 1-2 hours  
**Priority:** Medium

**Description:**
Add periodic status updates to console for monitoring.

**Implementation:**
- [ ] Create status ticker (configurable interval)
- [ ] Collect key metrics:
  - [ ] Active connections
  - [ ] Total requests processed
  - [ ] Certificate cache size
  - [ ] Connection pool stats
  - [ ] Memory usage (basic)
- [ ] Format nicely for console
- [ ] Make interval configurable

**Output Example:**
```
[11:30:00] Status: 45 active connections, 1,234 requests processed, 89 cached certs
```

**Testing:**
- [ ] Status updates appear at correct intervals
- [ ] Metrics are accurate
- [ ] Interval change via config works

---

### Phase 3: Capture Organization

#### Task 3.1: Simplified Capture Directory Structure
**Estimate:** 4-5 hours  
**Priority:** Medium (high impact on usability)

**Description:**
Reorganize captures into clean domain-based directory structure.

**Current State:**
- Flat files with complex naming

**Proposed Structure:**
```
captures/
├── google.com/
│   ├── 2025-07-26/
│   │   ├── requests/
│   │   │   ├── 001_GET_search.json
│   │   │   └── 002_POST_api.json
│   │   └── responses/
│   │       ├── 001_GET_search.json
│   │       └── 002_POST_api.json
│   └── metadata.json
└── youtube.com/
    └── [same structure]
```

**Implementation:**
- [ ] Create directory structure generator
- [ ] Update capture naming convention
- [ ] Add request/response pairing
- [ ] Create domain metadata files
- [ ] Handle edge cases (IP addresses, wildcards)
- [ ] Migration strategy for existing captures

**Testing:**
- [ ] New structure created correctly
- [ ] Request/response pairing works
- [ ] Performance impact acceptable
- [ ] Edge cases handled

---

### Phase 4: Feature-Specific Logging (Proposal Only)

#### Task 4.1: Design Feature-Specific Logging System
**Estimate:** 1-2 hours planning  
**Priority:** Low (proposal phase)

**Description:**
Design system for feature-specific logs (don't implement yet).

**Proposed Logs:**
- `/logs/inspection.log` - domains inspected, bypassed, reasons
- `/logs/certificates.log` - cert generation, cache events  
- `/logs/filtering.log` - URL verdicts (allowed/blocked + reasons)
- `/logs/errors.log` - panics, critical errors
- `/logs/performance.log` - performance metrics, slow requests

**Design Considerations:**
- [ ] Log rotation strategy
- [ ] Structured format consistency
- [ ] Performance impact
- [ ] Configuration granularity
- [ ] Integration with existing logging

**Output:** Design document only (no implementation)

---

## Implementation Order

### Sprint 1: Core Infrastructure
1. Task 1.1: Config Watcher
2. Task 1.2: Console Logging Refactor  
3. Task 2.2: Periodic Status Updates

### Sprint 2: Enhanced Logging
1. Task 2.1: Enhanced Proxy Logging
2. Task 3.1: Capture Directory Structure

### Sprint 3: Planning
1. Task 4.1: Feature-Specific Logging Design

## Definition of Done

### Sprint 1 Complete When:
- [ ] Console shows only minimal, high-level messages
- [ ] Config changes reload logging behavior live
- [ ] Periodic status updates display key metrics
- [ ] All existing functionality preserved

### Sprint 2 Complete When:
- [ ] Detailed logs properly structured in files
- [ ] Captures organized by domain with clean structure
- [ ] Debug logging controlled by config
- [ ] Performance impact negligible

### Full Feature Complete When:
- [ ] All tasks above completed
- [ ] Testing strategy executed
- [ ] Documentation updated
- [ ] No regressions in baseline functionality

## Risk Mitigation

**Risks:**
- Console logging changes break monitoring tools
- Capture restructure causes data loss
- Performance impact from structured logging

**Mitigation:**
- Implement incrementally with rollback points
- Test with existing captures before restructure
- Performance benchmark before/after
- Keep config backward compatible

---

**Status:** Ready for implementation  
**Next Steps:** Implement Sprint 1 tasks in order
