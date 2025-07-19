package inspection

import (
	"log"
	"net/http"

	"github.com/iamgaru/gander/internal/config"
)

// ExampleUsage demonstrates how to use the content inspection system
func ExampleUsage() {
	// Create a sample configuration
	cfg := &config.InspectionConfig{
		GlobalRules: config.InspectionRules{
			AlwaysInspect: []string{
				"text/html",
				"application/javascript",
				"text/css",
			},
			ConditionalInspect: []string{
				"image/jpeg",
				"image/png",
			},
			NeverInspect: []string{
				"application/octet-stream",
				"video/mp4",
			},
			SizeLimits: config.SizeLimitsConfig{
				MaxInspectSize:        "10MB",
				ImageMaxSize:          "5MB",
				StreamingBufferSize:   "1MB",
				StreamingInspectBytes: "4KB",
			},
		},
		DomainOverrides: map[string]config.InspectionRules{
			"*.youtube.com": {
				AlwaysInspect: []string{
					"text/html",
				},
				ConditionalInspect: []string{
					"image/jpeg",
				},
				NeverInspect: []string{
					"video/mp4",
					"video/webm",
				},
				SizeLimits: config.SizeLimitsConfig{
					MaxInspectSize:        "1MB",
					ImageMaxSize:          "500KB",
					StreamingInspectBytes: "2KB",
				},
			},
		},
		AIPreparation: config.AIPreparationConfig{
			Enabled:            true,
			MetadataCapture:    true,
			ContentPreviewSize: "1KB",
			QueueDirectory:     "ai_queue",
			SupportedAnalysis:  []string{"image_ocr", "video_transcript"},
			MaxQueueSize:       1000,
			CleanupAfterDays:   7,
		},
	}

	// Create content inspector
	inspector := NewContentInspector(cfg)

	// Example 1: HTML content (should be inspected)
	htmlContext := &InspectionContext{
		URL:         "https://example.com/index.html",
		Domain:      "example.com",
		ContentType: "text/html",
		ContentSize: 1024,
		Headers:     make(http.Header),
		IsStreaming: false,
	}

	result := inspector.InspectContent(htmlContext)
	log.Printf("HTML inspection result: %s - %s", result.Decision, result.Reason)

	// Example 2: Large image (should be conditionally inspected, but might be skipped due to size)
	imageContext := &InspectionContext{
		URL:         "https://example.com/large-image.jpg",
		Domain:      "example.com",
		ContentType: "image/jpeg",
		ContentSize: 10 * 1024 * 1024, // 10MB
		Headers:     make(http.Header),
		IsStreaming: false,
	}

	result = inspector.InspectContent(imageContext)
	log.Printf("Large image inspection result: %s - %s", result.Decision, result.Reason)

	// Example 3: YouTube video (should be skipped due to domain override)
	videoContext := &InspectionContext{
		URL:         "https://www.youtube.com/watch?v=example",
		Domain:      "www.youtube.com",
		ContentType: "video/mp4",
		ContentSize: 100 * 1024 * 1024, // 100MB
		Headers:     make(http.Header),
		IsStreaming: true,
	}

	result = inspector.InspectContent(videoContext)
	log.Printf("YouTube video inspection result: %s - %s", result.Decision, result.Reason)

	// Example 4: Streaming content inspection
	streamingContext := &InspectionContext{
		URL:         "https://api.example.com/stream",
		Domain:      "api.example.com",
		ContentType: "application/json",
		ContentSize: -1, // Unknown size for streaming
		Headers:     make(http.Header),
		IsStreaming: true,
	}

	streamingInspector := inspector.NewStreamingInspector(streamingContext)
	
	// Simulate streaming data
	sampleData := []byte(`{"data": "example streaming content"}`)
	streamingInspector.Write(sampleData)
	
	if streamingInspector.IsDone() {
		collectedData := streamingInspector.GetCollectedData()
		log.Printf("Collected streaming data: %d bytes", len(collectedData))
	}
}

// IntegrateWithRelay shows how to integrate the inspection system with the relay handler
func IntegrateWithRelay() {
	// This is a conceptual example of how you might integrate the inspection system
	// with the existing relay handler in HandleHTTPSInspection
	
	/*
	func (r *Relayer) HandleHTTPSInspection(clientConn net.Conn, serverAddr string, info *ConnectionInfo) error {
		// ... existing TLS setup code ...
		
		// Create content inspector
		inspector := NewContentInspector(r.config.Inspection)
		
		// ... handle HTTP requests ...
		
		for {
			req, err := http.ReadRequest(clientReader)
			if err != nil {
				// Handle error
				break
			}
			
			// Create inspection context
			ctx := &InspectionContext{
				URL:         req.URL.String(),
				Domain:      info.Domain,
				ContentType: req.Header.Get("Content-Type"),
				ContentSize: req.ContentLength,
				Headers:     req.Header,
				IsStreaming: req.ContentLength < 0,
			}
			
			// Make inspection decision
			result := inspector.InspectContent(ctx)
			
			switch result.Decision {
			case DecisionSkip:
				// Skip inspection, use fast relay
				log.Printf("Skipping inspection for %s: %s", ctx.URL, result.Reason)
				// Forward request without inspection
				
			case DecisionInspect:
				// Full inspection
				log.Printf("Inspecting %s: %s", ctx.URL, result.Reason)
				// Capture and inspect content
				
			case DecisionConditional:
				// Conditional inspection based on first bytes
				log.Printf("Conditional inspection for %s: %s", ctx.URL, result.Reason)
				if ctx.IsStreaming {
					// Use streaming inspector
					streamInspector := inspector.NewStreamingInspector(ctx)
					// ... handle streaming inspection ...
				}
			}
			
			// ... rest of request handling ...
		}
		
		return nil
	}
	*/
	
	log.Println("Integration example provided in comments above")
}