# Enhanced HTTP Capture System

## Key Improvements

### 1. Domain Separation & Organization
```
captures/
├── google.com/
│   ├── 2025-06-28/
│   │   ├── api/           # JSON API calls, AJAX requests
│   │   ├── webpage/       # HTML pages
│   │   ├── javascript/    # JS files
│   │   ├── css/          # Stylesheets
│   │   ├── image/        # Images, icons
│   │   └── other/        # Everything else
├── chat.google.com/
│   ├── 2025-06-28/
│   │   ├── api/
│   │   └── webpage/
└── _unknown/             # Requests without clear domain
```

### 2. Resource Type Detection

**Automatic classification based on**:
- File extensions (`.js`, `.css`, `.png`, `.json`, etc.)
- Content-Type headers (`application/json`, `text/html`, etc.)
- URL patterns (`/api/`, `/v1/`, `/graphql`, etc.)
- Request characteristics (AJAX headers, Accept headers)

**Resource Types**:
- `api` - JSON/XML APIs, AJAX calls, GraphQL
- `webpage` - HTML pages, server-rendered content
- `image` - PNG, JPEG, SVG, WebP, icons
- `javascript` - JS files, bundled scripts
- `css` - Stylesheets, fonts references
- `font` - Web fonts (WOFF, TTF, etc.)
- `video/audio` - Media files
- `document` - PDFs, Office docs
- `other` - Everything else

### 3. Enhanced Data Structure

#### Connection Data (Consistent across request/response)
```json
"connection": {
  "client_ip": "127.0.0.1",
  "client_port": 49258,
  "server_ip": "142.250.191.110", 
  "server_port": 443,
  "protocol": "HTTPS",
  "tls_version": "TLS 1.3",
  "cipher": "TLS_AES_256_GCM_SHA384",
  "domain": "chat.google.com",
  "sni": "chat.google.com"
}
```

#### Clear Request/Response Separation
```json
"request": {
  "method": "POST",
  "url": "/api/endpoint",
  "headers": {...},
  "body": "...",
  "resource_type": "api",
  "is_ajax": true,
  "has_auth": true
},
"response": {
  "status_code": 200,
  "headers": {...},
  "body": "...",
  "cache_info": {...},
  "security_headers": {...}
}
```

#### Enhanced Analysis
```json
"analysis": {
  "resource_type": "api",
  "is_static_asset": false,
  "is_api_call": true,
  "has_sensitive_data": false,
  "filter_results": [...],
  "inspection_reasons": [...]
}
```

## Configuration Options

### Enhanced Capture Config
```json
{
  "logging": {
    "capture": {
      "organization": {
        "by_domain": true,
        "by_date": true,
        "by_resource_type": true,
        "max_depth": 3
      },
      "filtering": {
        "exclude_resource_types": ["image", "css", "javascript"],
        "exclude_extensions": [".ico", ".woff", ".ttf"],
        "include_only_apis": false,
        "min_body_size": 0,
        "max_body_size": "10MB"
      },
      "analysis": {
        "detect_sensitive_data": true,
        "analyze_security_headers": true,
        "track_frequency": true,
        "correlation_timeout": "30s"
      },
      "formats": {
        "json": {
          "enabled": true,
          "pretty_print": true,
          "include_raw_headers": false
        },
        "parquet": {
          "enabled": false,
          "batch_size": 1000
        }
      }
    }
  }
}
```

### Resource Type Filtering Examples
```json
{
  "capture_rules": {
    "google.com": {
      "include_types": ["api", "webpage"],
      "exclude_types": ["image", "css", "javascript"]
    },
    "*.suspicious.com": {
      "include_types": ["*"],
      "capture_all": true
    },
    "default": {
      "include_types": ["api", "webpage"],
      "exclude_static_assets": true
    }
  }
}
```

## Benefits of Enhanced Structure

### For Analysis
- **Domain-focused analysis**: Easy to examine specific site behavior
- **Resource type filtering**: Ignore static assets, focus on dynamic content
- **Clear data separation**: Request vs response data clearly delineated
- **Rich metadata**: Security headers, timing, analysis results included

### For Performance  
- **Selective capture**: Only capture relevant resource types
- **Organized storage**: Better file system performance with organized directories
- **Efficient filtering**: Pre-categorized data for faster analysis

### For Operations
- **Better correlation**: Connection data consistent across request/response
- **Debugging support**: Rich timing and processing metadata
- **Security analysis**: Built-in security header analysis
- **Pattern detection**: Frequency and behavior tracking

## Implementation Priority

### Phase 1: Core Structure
1. Implement new data types and resource detection
2. Add domain-based directory organization  
3. Integrate resource type filtering
4. Update capture manager to use new format

### Phase 2: Analysis Enhancement
1. Add security header analysis
2. Implement sensitive data detection
3. Add frequency tracking and pattern detection
4. Create analysis aggregation tools

### Phase 3: Performance & Streaming
1. Add asynchronous capture pipeline
2. Implement batched writes and compression
3. Add upstream streaming capabilities
4. Performance optimization and monitoring

This enhanced structure directly addresses your requirements for domain separation, resource type detection, and clear request/response organization while providing a foundation for advanced Layer 7 analysis capabilities. 