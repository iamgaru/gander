# Storage Management & Compression System

## Overview

The Storage Management system addresses the critical concern of log file sizes by providing comprehensive compression, rolling, and selective capture capabilities. This ensures efficient storage usage while maintaining the rich data capture capabilities of the enhanced logging system.

## Key Features

### 🗜️ **Compression Options**
- **Multiple Formats**: Gzip, Zstd, LZ4 support
- **Configurable Levels**: Balance between compression ratio and speed
- **Real-time Compression**: On-the-fly compression during capture
- **Automatic File Extension**: `.gz`, `.zst`, `.lz4` extensions added

### 📁 **Rolling File Management**
- **Size-based Rolling**: Automatic file rotation at configurable sizes (default: 50MB)
- **Time-based Rolling**: Regular rotation at specified intervals
- **Combined Strategy**: Both size and time-based rolling
- **Concurrent Writers**: Multiple streams with independent rolling

### 🎯 **Selective Capture Levels**
- **Minimal**: Only metadata, no bodies or headers (~200 bytes/request)
- **Basic**: Headers + small bodies only (~1-5KB/request)
- **Full**: Everything except large bodies (~5-50KB/request)
- **Deep**: Complete capture including large bodies (unlimited)
- **Custom**: Fine-grained filtering by resource type, domain, identity, etc.

### 🧹 **Automatic Cleanup**
- **Retention Policies**: Automatic cleanup of old files
- **Storage Limits**: Global storage size limits with LRU cleanup
- **Scheduled Cleanup**: Configurable cleanup intervals

## Storage Impact Analysis

### Size Reduction Examples

#### **Without Compression & Filtering**
```
Single HTTP Request (Full JSON) ≈ 15-50KB
10,000 requests/day × 50KB = 500MB/day
Month: ~15GB
Year: ~180GB
```

#### **With Basic Compression + Basic Level**
```
Single HTTP Request (Compressed) ≈ 800 bytes - 2KB
10,000 requests/day × 1.5KB = 15MB/day
Month: ~450MB
Year: ~5.5GB
```

#### **Size Reduction: ~97% savings!**

### Compression Ratios by Format

| Format | Ratio | Speed | CPU Usage | Use Case |
|--------|-------|-------|-----------|----------|
| **Gzip** | 85-90% | Medium | Low | Default - good balance |
| **Zstd** | 85-92% | Fast | Medium | High throughput environments |
| **LZ4** | 70-80% | Very Fast | Very Low | CPU-constrained systems |
| **None** | 0% | Fastest | None | Development/debugging |

## Configuration Examples

### 1. **Size-Conscious Production Setup**

Perfect for production environments where storage efficiency is critical:

```json
{
  "storage": {
    "enabled": true,
    "base_dir": "./captures",
    
    "compression_enabled": true,
    "compression_format": "gzip",
    "compression_level": 6,
    
    "rolling_enabled": true,
    "rolling_strategy": "size",
    "max_file_size": 52428800,
    "roll_interval": "1h",
    
    "retention_enabled": true,
    "retention_period": "720h",
    "max_storage_size": 10737418240,
    "cleanup_interval": "1h",
    
    "capture_level": "basic",
    
    "buffer_size": 65536,
    "flush_interval": "5s",
    "concurrent_writers": 10
  }
}
```

**Expected Storage**: ~500MB/month for 10K requests/day

### 2. **Development/Debugging Setup**

Full capture for development with smaller retention:

```json
{
  "storage": {
    "enabled": true,
    "base_dir": "./dev-captures",
    
    "compression_enabled": true,
    "compression_format": "lz4",
    "compression_level": 1,
    
    "rolling_enabled": true,
    "rolling_strategy": "both",
    "max_file_size": 10485760,
    "roll_interval": "30m",
    
    "retention_enabled": true,
    "retention_period": "24h",
    "max_storage_size": 1073741824,
    
    "capture_level": "full"
  }
}
```

**Expected Storage**: ~2GB/day with 24h retention

### 3. **High-Volume Minimal Setup**

For very high-traffic environments requiring minimal storage:

```json
{
  "storage": {
    "enabled": true,
    "base_dir": "./minimal-captures",
    
    "compression_enabled": true,
    "compression_format": "zstd",
    "compression_level": 3,
    
    "rolling_enabled": true,
    "rolling_strategy": "size",
    "max_file_size": 104857600,
    
    "retention_enabled": true,
    "retention_period": "168h",
    "max_storage_size": 5368709120,
    
    "capture_level": "minimal"
  }
}
```

**Expected Storage**: ~50MB/month for 100K requests/day

### 4. **Custom Selective Capture**

Fine-grained control for specific monitoring needs:

```json
{
  "storage": {
    "enabled": true,
    "compression_enabled": true,
    "compression_format": "gzip",
    "rolling_enabled": true,
    "max_file_size": 52428800,
    
    "capture_level": "custom",
    "selective_capture": {
      "capture_headers": true,
      "capture_request_body": false,
      "capture_response_body": true,
      "max_body_size": 8192,
      
      "include_resource_types": ["api", "webpage"],
      "exclude_resource_types": ["image", "css", "javascript"],
      
      "include_domains": ["api.company.com", "app.company.com"],
      "exclude_domains": ["cdn.company.com"],
      
      "exclude_status_codes": [404, 304],
      
      "include_content_types": ["application/json", "text/html"],
      "exclude_content_types": ["image/*", "video/*"]
    }
  }
}
```

**Expected Storage**: ~200MB/month (highly variable based on filters)

## Storage Metrics & Monitoring

### Real-time Metrics Available

```json
{
  "storage_metrics": {
    "files_created": 1247,
    "files_compressed": 1247,
    "files_rolled": 23,
    "files_deleted": 156,
    "bytes_written": 52428800,
    "bytes_compressed": 8738133,
    "compression_ratio": 83.3,
    "current_storage_size": 2147483648,
    "last_cleanup": "2025-06-28T16:30:00Z",
    "write_errors": 0,
    "average_write_time_ms": 2.5
  }
}
```

### Monitoring Alerts

```json
{
  "storage_alerts": {
    "high_storage_usage": {
      "threshold": 0.8,
      "current": 0.65,
      "status": "ok"
    },
    "compression_ratio_low": {
      "threshold": 0.7,
      "current": 0.833,
      "status": "ok"
    },
    "write_errors": {
      "threshold": 10,
      "current": 0,
      "status": "ok"
    }
  }
}
```

## File Organization

### Directory Structure with Rolling

```
captures/
├── google.com/
│   ├── 2025-06-28/
│   │   ├── api/
│   │   │   ├── capture_16-50-20.000.json.gz      # Current file (35MB)
│   │   │   ├── capture_16-30-15.000.json.gz      # Rolled file (50MB)
│   │   │   └── capture_16-10-05.000.json.gz      # Rolled file (50MB)
│   │   ├── webpage/
│   │   └── image/
│   └── 2025-06-27/                               # Previous day (cleanup candidate)
├── github.com/
└── metrics/
    └── storage_stats.json                        # Storage metrics
```

### Rolling File Naming

```
Original: capture_16-50-20.000.json.gz
Rolled:   capture_16-50-20.000_001.json.gz
Rolled:   capture_16-50-20.000_002.json.gz
```

## Performance Considerations

### Compression Performance

| Requests/Second | CPU Usage (Gzip) | Memory Usage | Disk I/O |
|----------------|------------------|--------------|----------|
| 100 | ~2% | ~10MB | Minimal |
| 1,000 | ~15% | ~50MB | Low |
| 10,000 | ~45% | ~200MB | Medium |

### Optimization Tips

1. **High Volume Environments**:
   - Use LZ4 compression for speed
   - Set capture level to "minimal" or "basic"
   - Use larger rolling file sizes (100MB+)
   - Increase buffer sizes

2. **Storage-Constrained Environments**:
   - Use Zstd compression for maximum compression
   - Set aggressive retention policies (7-14 days)
   - Use selective capture to filter unnecessary data
   - Implement external log shipping

3. **Development Environments**:
   - Use "full" or "deep" capture levels
   - Shorter retention periods (1-3 days)
   - Smaller rolling files for easier analysis

## Streaming & External Integration

### Real-time Data Streaming

For environments where local storage is not desired:

```json
{
  "streaming": {
    "enabled": true,
    "targets": [
      {
        "type": "elasticsearch",
        "endpoint": "https://es.company.com:9200",
        "index": "gander-captures"
      },
      {
        "type": "kafka",
        "brokers": ["kafka1:9092", "kafka2:9092"],
        "topic": "network-captures"
      },
      {
        "type": "webhook",
        "url": "https://api.company.com/network-events",
        "headers": {"Authorization": "Bearer token"}
      }
    ],
    "batch_size": 100,
    "flush_interval": "10s",
    "retry_attempts": 3
  },
  
  "storage": {
    "enabled": false  // Disable local storage when streaming
  }
}
```

## Migration from Current System

### Gradual Migration Strategy

1. **Phase 1**: Enable compression on current captures
   ```json
   {
     "storage": {
       "compression_enabled": true,
       "capture_level": "full"  // Same as current
     }
   }
   ```

2. **Phase 2**: Add rolling files
   ```json
   {
     "storage": {
       "rolling_enabled": true,
       "max_file_size": 52428800
     }
   }
   ```

3. **Phase 3**: Optimize capture level
   ```json
   {
     "storage": {
       "capture_level": "basic"  // Reduce size
     }
   }
   ```

4. **Phase 4**: Add retention policies
   ```json
   {
     "storage": {
       "retention_enabled": true,
       "retention_period": "720h"
     }
   }
   ```

## Best Practices

### Storage Management

1. **Monitor disk usage** regularly with built-in metrics
2. **Test compression ratios** with your specific traffic patterns
3. **Adjust capture levels** based on analysis needs
4. **Implement alerting** on storage thresholds
5. **Regular cleanup verification** to ensure policies are working

### Performance Optimization

1. **Start with conservative settings** and tune based on performance
2. **Use SSDs** for high-throughput environments
3. **Separate storage** for different capture types
4. **Monitor CPU usage** and adjust compression accordingly
5. **Implement log rotation** at the OS level as a backup

### Security Considerations

1. **Encrypt stored captures** in sensitive environments
2. **Implement access controls** on capture directories
3. **Regular backup strategies** for critical captures
4. **Secure deletion** of old files containing sensitive data
5. **Audit trails** for capture access and modifications

---

This storage management system reduces log file sizes by **90-97%** while maintaining the rich capture capabilities, making it suitable for production environments with high traffic volumes and storage constraints. 