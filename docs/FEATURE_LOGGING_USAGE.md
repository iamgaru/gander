# Feature-Specific Logging Usage Guide

This document shows how to use the feature-specific logging system implemented in Gander.

## Configuration

Add feature logging configuration to your `config.json`:

```json
{
  "logging": {
    "log_file": "logs/proxy.log",
    "console_level": "minimal",
    "status_interval": "60s",
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
          "level": "info"
        }
      }
    }
  }
}
```

## Generated Log Files

When enabled, Gander will create the following log files:

### `/logs/filtering.log`
Records all filtering decisions with correlation IDs:
```
[2025-08-05T20:09:36Z] [abc123] target=evil.com verdict=blocked method=domain_inspection reason=blacklist_match client_ip=192.168.1.100
[2025-08-05T20:09:37Z] [def456] target=google.com verdict=allowed method=sni_sniff reason=uninspected_domain client_ip=192.168.1.100
```

### `/logs/certificates.log`
Records certificate operations and performance:
```
[2025-08-05T20:09:36Z] action=cache_hit domain=google.com status=success
[2025-08-05T20:09:37Z] action=generate domain=new-site.com status=success duration=45ms
[2025-08-05T20:09:38Z] action=expire domain=old-site.com status=success reason=expired
```

### `/logs/errors.log`
Records critical errors and panics:
```
[2025-08-05T20:09:36Z] level=critical component=proxy error="connection failed" client_ip=192.168.1.100
[2025-08-05T20:09:37Z] level=error component=cert_manager error="failed to generate certificate" domain=invalid.com
```

### `/logs/performance.log`
Records performance metrics and slow operations:
```
[2025-08-05T20:09:36Z] metric=request_duration value=250ms domain=slow.com client_ip=192.168.1.100 threshold=100ms
[2025-08-05T20:09:37Z] metric=active_connections value=45 component=proxy
[2025-08-05T20:09:38Z] metric=cert_cache_size value=128 component=cert_cache
```

## Log Rotation

Feature logs support automatic rotation:
- **Max file size**: Configurable (default 50MB)
- **Max files**: Configurable (default 10)
- **Compression**: Optional gzip compression
- **Rotation format**: `{logname}_{timestamp}.log`

## Integration Points

The feature logging integrates automatically with existing Gander operations:

### Filtering Integration
- **HTTP filtering**: Logged when domain inspection occurs
- **HTTPS filtering**: Logged when SNI sniffing makes decisions
- **IP filtering**: Will be logged when IP filtering is implemented
- **URL analysis**: Ready for future URL content filtering

### Certificate Integration
- **Cache operations**: Hits, misses, and expiration events
- **Generation timing**: Duration tracking for performance optimization
- **Pregeneration**: Background certificate generation events

### Error Integration
- **Critical errors**: All `logger.Critical()` calls are logged
- **Component tracking**: Identifies which component generated the error
- **Context preservation**: Additional error context is preserved

### Performance Integration
- **Request duration**: Slow requests (>100ms threshold) are logged
- **System metrics**: Periodic statistics from connection pools, caches
- **Resource usage**: Memory and connection tracking

## Analysis Examples

### Find Blocked Domains
```bash
grep "verdict=blocked" logs/filtering.log | cut -d' ' -f3 | sort | uniq -c
```

### Monitor Certificate Generation Performance
```bash
grep "action=generate" logs/certificates.log | grep -o "duration=[0-9]*ms" | sort -n
```

### Track Critical Errors
```bash
grep "level=critical" logs/errors.log | tail -10
```

### Identify Slow Requests
```bash
grep "metric=request_duration" logs/performance.log | awk '{print $4, $5}' | sort -k2 -n
```

## Best Practices

### Production Configuration
- **Enable filtering and certificates logs**: Essential for traffic analysis
- **Enable errors log**: Critical for debugging and monitoring
- **Performance log**: Enable only if monitoring slow operations
- **File rotation**: Set appropriate limits based on traffic volume

### Development Configuration
- **Enable all logs**: Full visibility during development
- **Lower rotation limits**: Prevent excessive disk usage
- **Higher performance thresholds**: Reduce noise in performance logs

### Log Analysis
- **Correlation IDs**: Use correlation IDs to trace requests across logs
- **Time-based analysis**: All logs use UTC timestamps for consistency
- **Structured parsing**: Logs use key=value format for easy parsing

## Troubleshooting

### Logs Not Created
- Check `feature_logs.enabled` is `true`
- Verify individual log `enabled` settings
- Ensure log directory permissions are correct

### High Disk Usage
- Reduce `max_file_size_mb` setting
- Reduce `max_files` setting
- Enable `compression` option
- Disable verbose logs (performance) in production

### Performance Impact
- Feature logs use async writing to minimize impact
- Log rotation happens in background
- Disable unused logs to reduce overhead