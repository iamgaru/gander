# Identity-Based Reporting System

## Overview

The Identity-Based Reporting System enables Gander to correlate network traffic with specific identities (users, devices, IP addresses, etc.) providing powerful insights for network analysis, security monitoring, and user behavior tracking.

## Key Features

### 🔍 **Pluggable Identity Providers**
- Modular architecture supports multiple identity sources
- Configurable priority and confidence scoring
- Real-time identity resolution with caching
- Enrichment capabilities for additional metadata

### 🏷️ **Multiple Identity Types**
- **IP-based**: IP addresses and network ranges
- **MAC-based**: Hardware addresses and device fingerprinting
- **User-based**: Authenticated user accounts (future)
- **Device-based**: Named devices and asset management (future)
- **Session-based**: Session tracking and correlation (future)

### 📊 **Enhanced Traffic Analysis**
- Identity correlation with captured traffic
- Domain and resource type segregation by identity
- Behavioral pattern analysis per identity
- Security context based on identity trust levels

## Architecture

### Identity Resolution Pipeline

```
Network Traffic → Identity Resolution → Enhanced Capture → Reporting
     ↓                    ↓                   ↓              ↓
Connection Info → Multiple Providers → Identity Context → Reports
```

### Provider System

#### **Identity Provider Interface**
```go
type IdentityProvider interface {
    Name() string
    Type() IdentityType
    Initialize(config map[string]interface{}) error
    ResolveIdentity(ctx context.Context, req *IdentityRequest) (*Identity, error)
    EnrichIdentity(ctx context.Context, identity *Identity) error
    IsEnabled() bool
    Priority() int
    Shutdown() error
}
```

## Built-in Identity Providers

### 1. IP/MAC Provider (`ip_mac`)

**Purpose**: Resolves identity based on IP addresses and MAC addresses from ARP table

**Features**:
- **ARP Table Scanning**: Periodic scanning of system ARP table
- **MAC Vendor Lookup**: Hardware vendor identification from OUI
- **Network Classification**: Private/public network detection
- **Trust Assessment**: Trusted network identification
- **Device Database**: Optional device naming and ownership

**Configuration**:
```json
{
  "identity": {
    "enabled": true,
    "enabled_providers": ["ip_mac"],
    "provider_configs": {
      "ip_mac": {
        "enabled": true,
        "priority": 50,
        "arp_scan_interval": "5m",
        "enable_mac_lookup": true,
        "enable_ip_metadata": true,
        "trusted_networks": ["192.168.1.0/24", "10.0.0.0/8"],
        "device_database": "/path/to/devices.json",
        "refresh_interval": "1h"
      }
    }
  }
}
```

**Sample Identity Resolution**:
```json
{
  "type": "ip",
  "id": "192.168.1.100",
  "display_name": "John's MacBook (192.168.1.100)",
  "confidence": 0.95,
  "source": "ip_mac",
  "metadata": {
    "mac_address": "A4:83:E7:12:34:56",
    "mac_vendor": "Apple",
    "interface": "en0",
    "ip_metadata": {
      "network": "192.168.1.0/24",
      "is_private": true,
      "is_trusted": true,
      "organization": "Local Network"
    },
    "device_info": {
      "device_name": "John's MacBook",
      "device_type": "laptop",
      "owner": "John Doe",
      "department": "Engineering"
    }
  }
}
```

## Enhanced Capture Integration

### Identity Context in Captures

Every captured request includes full identity context:

```json
{
  "id": "capture_id",
  "timestamp": "2025-06-28T16:50:20Z",
  
  "identity": {
    "primary_identity": {
      "type": "ip",
      "id": "192.168.1.100",
      "display_name": "John's MacBook",
      "confidence": 0.95
    },
    "all_identities": [...],
    "client_ip": "192.168.1.100",
    "resolved_at": "2025-06-28T16:50:20Z"
  },
  
  "connection": {...},
  "request": {...},
  "response": {...}
}
```

### Directory Organization by Identity

Captures can be organized by identity for easier analysis:

```
captures/
├── by_domain/
│   ├── google.com/
│   └── facebook.com/
├── by_identity/
│   ├── john_macbook_192.168.1.100/
│   │   ├── 2025-06-28/
│   │   │   ├── api/
│   │   │   ├── webpage/
│   │   │   └── image/
│   ├── engineering_server_192.168.1.10/
│   └── guest_device_192.168.1.200/
└── by_network/
    ├── trusted/
    ├── guest/
    └── external/
```

## Reporting Capabilities

### 1. Identity-Based Traffic Reports

**Traffic Volume by Identity**:
```json
{
  "report_type": "identity_traffic_volume",
  "time_range": "2025-06-28T00:00:00Z/2025-06-28T23:59:59Z",
  "identities": [
    {
      "identity": "john_macbook_192.168.1.100",
      "display_name": "John's MacBook",
      "total_requests": 1247,
      "total_bytes": 15728640,
      "domains": ["google.com", "github.com", "stackoverflow.com"],
      "top_resources": ["api", "webpage", "image"],
      "risk_score": 0.1
    }
  ]
}
```

**Domain Access by Identity**:
```json
{
  "report_type": "identity_domain_access",
  "identity": "john_macbook_192.168.1.100",
  "domains": [
    {
      "domain": "google.com",
      "requests": 456,
      "first_access": "2025-06-28T08:30:00Z",
      "last_access": "2025-06-28T17:45:00Z",
      "resource_types": {
        "api": 234,
        "webpage": 123,
        "image": 99
      }
    }
  ]
}
```

### 2. Security-Focused Reports

**Suspicious Activity by Identity**:
```json
{
  "report_type": "identity_security_events",
  "time_range": "2025-06-28",
  "events": [
    {
      "identity": "guest_device_192.168.1.200",
      "event_type": "unusual_domain_access",
      "domain": "suspicious-site.com",
      "timestamp": "2025-06-28T14:30:00Z",
      "risk_score": 0.8,
      "context": "First time accessing this domain from network"
    }
  ]
}
```

**Network Boundary Violations**:
```json
{
  "report_type": "network_boundary_violations",
  "violations": [
    {
      "identity": "internal_server_10.0.1.5",
      "violation_type": "external_communication",
      "destination": "external-api.com",
      "expected_boundary": "internal_only",
      "timestamp": "2025-06-28T12:15:00Z"
    }
  ]
}
```

### 3. Behavioral Analysis Reports

**Traffic Patterns by Identity**:
```json
{
  "report_type": "identity_behavioral_patterns",
  "identity": "john_macbook_192.168.1.100",
  "patterns": {
    "peak_hours": ["09:00-12:00", "14:00-17:00"],
    "common_domains": ["google.com", "github.com"],
    "typical_bandwidth": "50MB/hour",
    "anomalies": [
      {
        "type": "unusual_hour_activity",
        "timestamp": "2025-06-28T02:30:00Z",
        "description": "Traffic at unusual hour"
      }
    ]
  }
}
```

### 4. Compliance Reports

**Data Access Audit by Identity**:
```json
{
  "report_type": "data_access_audit",
  "compliance_framework": "GDPR",
  "time_range": "2025-06-28",
  "access_events": [
    {
      "identity": "john_macbook_192.168.1.100",
      "data_category": "personal_data",
      "domain": "crm.company.com",
      "access_type": "read",
      "timestamp": "2025-06-28T10:30:00Z",
      "justification": "legitimate_business_interest"
    }
  ]
}
```

## Configuration Examples

### Basic Identity System Configuration

```json
{
  "identity": {
    "enabled": true,
    "cache_enabled": true,
    "cache_ttl": "10m",
    "max_cache_size": 10000,
    "enabled_providers": ["ip_mac"],
    "primary_provider": "ip_mac",
    "enrichment_enabled": true,
    "resolve_timeout": "5s",
    
    "provider_configs": {
      "ip_mac": {
        "enabled": true,
        "priority": 50,
        "arp_scan_interval": "5m",
        "enable_mac_lookup": true,
        "enable_ip_metadata": true,
        "trusted_networks": [
          "192.168.1.0/24",
          "10.0.0.0/8",
          "172.16.0.0/12"
        ],
        "refresh_interval": "1h"
      }
    }
  }
}
```

### Enhanced Capture with Identity Integration

```json
{
  "capture": {
    "enhanced_format": true,
    "identity_integration": true,
    "directory_structure": {
      "organization": "identity_and_domain",
      "base_dir": "./captures",
      "create_identity_dirs": true,
      "create_date_dirs": true,
      "create_resource_dirs": true
    }
  }
}
```

### Reporting Configuration

```json
{
  "reporting": {
    "enabled": true,
    "identity_reports": {
      "enabled": true,
      "report_types": [
        "identity_traffic_volume",
        "identity_domain_access",
        "identity_security_events",
        "identity_behavioral_patterns"
      ],
      "generation_interval": "1h",
      "retention_period": "30d",
      "output_format": "json"
    }
  }
}
```

## Future Identity Providers

### 1. Active Directory Provider (`active_directory`)
- User account resolution from AD
- Group membership and permissions
- Authentication event correlation

### 2. DHCP Provider (`dhcp`)
- Hostname resolution from DHCP logs
- Device classification from DHCP options
- Lease history tracking

### 3. Certificate Provider (`certificate`)
- Client certificate-based identity
- Certificate chain validation
- Certificate metadata extraction

### 4. Custom Database Provider (`custom_db`)
- Custom identity database integration
- SQL/NoSQL database support
- Custom identity schemas

## Benefits

### 🔒 **Security**
- Track suspicious activity by identity
- Identify compromised devices quickly
- Monitor privilege escalation attempts
- Detect insider threats

### 📈 **Compliance**
- Audit data access by user/device
- Track data flow across boundaries
- Generate compliance reports
- Monitor policy violations

### 🔍 **Operations**
- Troubleshoot network issues by identity
- Monitor application usage patterns
- Optimize bandwidth allocation
- Plan capacity based on user behavior

### 🏢 **Business Intelligence**
- Understand application usage by department
- Track productivity patterns
- Monitor SaaS application adoption
- Analyze security training effectiveness

## Implementation Roadmap

### Phase 1: Foundation (Current)
- ✅ Identity provider interface
- ✅ IP/MAC provider implementation
- ✅ Enhanced capture integration
- ✅ Basic caching system

### Phase 2: Extended Providers (Next)
- 🔄 DHCP provider
- 🔄 Active Directory provider
- 🔄 Certificate provider
- 🔄 Device database integration

### Phase 3: Advanced Reporting (Future)
- 📅 Real-time identity dashboards
- 📅 Behavioral analysis engine
- 📅 Anomaly detection
- 📅 Compliance automation

### Phase 4: Intelligence (Future)
- 📅 Machine learning integration
- 📅 Threat intelligence correlation
- 📅 Predictive analysis
- 📅 Automated response actions

---

The Identity-Based Reporting System transforms Gander from a simple traffic capture tool into a comprehensive network intelligence platform, providing unprecedented visibility into who is doing what on your network. 