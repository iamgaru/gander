# Smart Content Inspection System

The Smart Content Inspection System provides intelligent content filtering and inspection capabilities for the Gander MITM proxy. It makes decisions about whether to inspect content based on content type, size, URL patterns, and domain-specific rules.

## Features

- **Content Type Filtering**: Automatically inspects valuable content (HTML, JS, CSS) while skipping static files
- **Size-based Limits**: Configurable size thresholds for different content types
- **Domain-specific Rules**: Per-domain inspection overrides (e.g., different rules for YouTube vs. APIs)
- **URL Pattern Matching**: Regex-based rules for specific URL patterns
- **Streaming Support**: Inspects first N bytes of streaming content
- **AI Analysis Preparation**: Queues suitable content for future AI analysis

## Configuration

### Basic Configuration

```json
{
  "inspection": {
    "global_rules": {
      "always_inspect": ["text/html", "application/javascript", "text/css"],
      "conditional_inspect": ["image/jpeg", "image/png"],
      "never_inspect": ["application/octet-stream", "video/mp4"],
      "size_limits": {
        "max_inspect_size": "10MB",
        "image_max_size": "5MB",
        "streaming_buffer_size": "1MB",
        "streaming_inspect_bytes": "4KB"
      }
    }
  }
}
```

### Domain-specific Overrides

```json
{
  "inspection": {
    "domain_overrides": {
      "*.youtube.com": {
        "always_inspect": ["text/html"],
        "never_inspect": ["video/mp4", "video/webm"],
        "size_limits": {
          "max_inspect_size": "1MB",
          "streaming_inspect_bytes": "2KB"
        }
      },
      "api.example.com": {
        "always_inspect": ["application/json"],
        "url_patterns": {
          "force_inspect": [".*\\/api\\/v1\\/.*"],
          "force_skip": [".*\\/static\\/.*"]
        }
      }
    }
  }
}
```

### AI Analysis Preparation

```json
{
  "inspection": {
    "ai_preparation": {
      "enabled": true,
      "metadata_capture": true,
      "content_preview_size": "1KB",
      "queue_directory": "ai_queue",
      "supported_analysis": ["image_ocr", "video_transcript"],
      "max_queue_size": 1000,
      "cleanup_after_days": 7
    }
  }
}
```

## Usage

### Basic Usage

```go
import "github.com/iamgaru/gander/internal/inspection"

// Create inspector
inspector := inspection.NewContentInspector(&config.Inspection)

// Create inspection context
ctx := &inspection.InspectionContext{
    URL:         "https://example.com/index.html",
    Domain:      "example.com",
    ContentType: "text/html",
    ContentSize: 1024,
    Headers:     req.Header,
    IsStreaming: false,
}

// Make inspection decision
result := inspector.InspectContent(ctx)

switch result.Decision {
case inspection.DecisionInspect:
    // Perform full inspection
    log.Printf("Inspecting content: %s", result.Reason)
    
case inspection.DecisionSkip:
    // Skip inspection
    log.Printf("Skipping content: %s", result.Reason)
    
case inspection.DecisionConditional:
    // Conditional inspection (e.g., based on size)
    log.Printf("Conditional inspection: %s", result.Reason)
}
```

### Streaming Content

```go
// Create streaming inspector
streamInspector := inspector.NewStreamingInspector(ctx)

// Stream data through inspector
for {
    data, err := conn.Read(buffer)
    if err != nil {
        break
    }
    
    // Inspector collects first N bytes
    streamInspector.Write(data[:n])
    
    if streamInspector.IsDone() {
        // Inspect collected data
        collectedData := streamInspector.GetCollectedData()
        // ... perform inspection on collected data
        break
    }
}
```

## Content Type Categories

### Always Inspect
- `text/html` - HTML pages
- `text/plain` - Plain text
- `application/json` - JSON data
- `application/javascript` - JavaScript code
- `text/css` - CSS stylesheets

### Conditional Inspect
- `image/jpeg`, `image/png` - Images (subject to size limits)
- `video/mp4`, `video/webm` - Videos (for AI analysis)

### Never Inspect
- `application/octet-stream` - Binary data
- `application/zip` - Archives
- `font/*` - Font files
- Large static files

## Size Limits

- **max_inspect_size**: Maximum size for any content inspection (default: 10MB)
- **image_max_size**: Maximum size for image inspection (default: 5MB)
- **streaming_buffer_size**: Buffer size for streaming content (default: 1MB)
- **streaming_inspect_bytes**: Bytes to inspect from streaming content (default: 4KB)

## URL Patterns

Use regex patterns to force inspection or skipping:

```json
{
  "url_patterns": {
    "force_inspect": [
      ".*\\/api\\/.*",
      ".*\\.json$"
    ],
    "force_skip": [
      ".*\\/static\\/.*",
      ".*\\.woff2?$"
    ]
  }
}
```

## Decision Priority

The inspection system uses the following priority order:

1. **URL Patterns** (highest priority)
   - `force_inspect` patterns
   - `force_skip` patterns

2. **Content Type Rules**
   - `always_inspect` list
   - `never_inspect` list
   - `conditional_inspect` list

3. **Size Limits** (for conditional content)
   - General size limits
   - Content-type specific limits

4. **Default**: Skip if no rules match

## Integration with Relay

The inspection system integrates with the HTTPS inspection handler:

```go
// In HandleHTTPSInspection
inspector := inspection.NewContentInspector(r.config.Inspection)

ctx := &inspection.InspectionContext{
    URL:         req.URL.String(),
    Domain:      info.Domain,
    ContentType: req.Header.Get("Content-Type"),
    ContentSize: req.ContentLength,
    Headers:     req.Header,
    IsStreaming: req.ContentLength < 0,
}

result := inspector.InspectContent(ctx)

switch result.Decision {
case inspection.DecisionSkip:
    return r.bidirectionalRelay(clientConn, serverConn, info)
case inspection.DecisionInspect:
    return r.handleHTTPSTraffic(clientConn, serverConn, info)
case inspection.DecisionConditional:
    if ctx.IsStreaming {
        streamInspector := inspector.NewStreamingInspector(ctx)
        // Handle streaming inspection
    }
}
```

## AI Analysis Queue

The system can queue content for future AI analysis:

- **Image OCR**: Extract text from images
- **Video Transcription**: Generate transcripts from video content
- **Content Analysis**: Analyze content for security purposes

Files are queued in the configured directory with metadata for later processing.

## Performance Considerations

- Size limits prevent inspection of large files
- Streaming inspection only examines first N bytes
- Domain-specific rules allow fine-tuning per service
- Buffer pooling minimizes memory allocation
- Regex patterns are compiled once and reused

## Security Benefits

- Focuses inspection on high-value content
- Reduces processing overhead for static files
- Enables domain-specific security policies
- Prepares data for AI-based threat detection
- Maintains detailed logs for security analysis