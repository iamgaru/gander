package inspection

import (
	"fmt"
	"mime"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/iamgaru/gander/internal/config"
)

// Decision represents an inspection decision
type Decision int

const (
	DecisionSkip Decision = iota
	DecisionInspect
	DecisionConditional
)

// InspectionContext contains information about the content being inspected
type InspectionContext struct {
	URL         string
	Domain      string
	ContentType string
	ContentSize int64
	Headers     http.Header
	IsStreaming bool
}

// ContentInspector makes smart decisions about content inspection
type ContentInspector struct {
	config *config.InspectionConfig
}

// NewContentInspector creates a new content inspector
func NewContentInspector(cfg *config.InspectionConfig) *ContentInspector {
	return &ContentInspector{
		config: cfg,
	}
}

// ShouldInspect determines if content should be inspected
func (ci *ContentInspector) ShouldInspect(ctx *InspectionContext) Decision {
	// Get applicable rules (domain-specific overrides take precedence)
	rules := ci.getApplicableRules(ctx.Domain)

	// Check URL patterns first (highest priority)
	if decision := ci.checkURLPatterns(ctx.URL, &rules); decision != DecisionConditional {
		return decision
	}

	// Check content type rules
	decision := ci.checkContentType(ctx.ContentType, &rules)
	if decision != DecisionConditional {
		return decision
	}

	// Check size limits for conditional content
	return ci.checkSizeLimits(ctx, &rules)
}

// getApplicableRules returns the rules to use for a given domain
func (ci *ContentInspector) getApplicableRules(domain string) config.InspectionRules {
	// Check for exact domain match first
	if override, exists := ci.config.DomainOverrides[domain]; exists {
		return override
	}

	// Check for wildcard domain matches
	for pattern, rules := range ci.config.DomainOverrides {
		if matched, err := filepath.Match(pattern, domain); err == nil && matched {
			return rules
		}
	}

	// Use global rules as fallback
	return ci.config.GlobalRules
}

// checkURLPatterns checks URL-based inspection rules
func (ci *ContentInspector) checkURLPatterns(url string, rules *config.InspectionRules) Decision {
	// Check force inspect patterns
	for _, pattern := range rules.URLPatterns.ForceInspect {
		if matched, err := regexp.MatchString(pattern, url); err == nil && matched {
			return DecisionInspect
		}
	}

	// Check force skip patterns
	for _, pattern := range rules.URLPatterns.ForceSkip {
		if matched, err := regexp.MatchString(pattern, url); err == nil && matched {
			return DecisionSkip
		}
	}

	return DecisionConditional
}

// checkContentType checks content type based inspection rules
func (ci *ContentInspector) checkContentType(contentType string, rules *config.InspectionRules) Decision {
	// Normalize content type (remove parameters)
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		// If we can't parse the media type, use the original contentType
		mediaType = contentType
	}

	// Check always inspect list
	for _, ct := range rules.AlwaysInspect {
		if mediaType == ct {
			return DecisionInspect
		}
	}

	// Check never inspect list
	for _, ct := range rules.NeverInspect {
		if mediaType == ct {
			return DecisionSkip
		}
	}

	// Check conditional inspect list
	for _, ct := range rules.ConditionalInspect {
		if mediaType == ct {
			return DecisionConditional
		}
	}

	// Default to skip for unknown content types
	return DecisionSkip
}

// checkSizeLimits checks if content size is within inspection limits
func (ci *ContentInspector) checkSizeLimits(ctx *InspectionContext, rules *config.InspectionRules) Decision {
	// Parse size limits
	maxInspectSize := parseSize(rules.SizeLimits.MaxInspectSize)
	imageMaxSize := parseSize(rules.SizeLimits.ImageMaxSize)

	// Check general size limit
	if ctx.ContentSize > maxInspectSize {
		return DecisionSkip
	}

	// Check image-specific size limit
	if ci.isImageContentType(ctx.ContentType) && ctx.ContentSize > imageMaxSize {
		return DecisionSkip
	}

	return DecisionInspect
}

// isImageContentType checks if content type is an image
func (ci *ContentInspector) isImageContentType(contentType string) bool {
	mediaType, _, _ := mime.ParseMediaType(contentType)
	return strings.HasPrefix(mediaType, "image/")
}

// GetStreamingInspectSize returns the number of bytes to inspect for streaming content
func (ci *ContentInspector) GetStreamingInspectSize(domain string) int64 {
	rules := ci.getApplicableRules(domain)
	return parseSize(rules.SizeLimits.StreamingInspectBytes)
}

// GetStreamingBufferSize returns the buffer size for streaming content
func (ci *ContentInspector) GetStreamingBufferSize(domain string) int64 {
	rules := ci.getApplicableRules(domain)
	return parseSize(rules.SizeLimits.StreamingBufferSize)
}

// InspectionResult contains the result of content inspection
type InspectionResult struct {
	Decision    Decision
	Reason      string
	SizeLimit   int64
	StreamBytes int64
	AIQueued    bool
}

// InspectContent performs comprehensive content inspection
func (ci *ContentInspector) InspectContent(ctx *InspectionContext) *InspectionResult {
	decision := ci.ShouldInspect(ctx)

	result := &InspectionResult{
		Decision: decision,
	}

	switch decision {
	case DecisionInspect:
		result.Reason = "Content type in always inspect list"
		if ctx.IsStreaming {
			result.StreamBytes = ci.GetStreamingInspectSize(ctx.Domain)
		}
	case DecisionSkip:
		result.Reason = "Content type in never inspect list or size exceeds limit"
	case DecisionConditional:
		rules := ci.getApplicableRules(ctx.Domain)
		result.SizeLimit = parseSize(rules.SizeLimits.MaxInspectSize)
		result.Reason = "Content type in conditional inspect list"
		if ctx.IsStreaming {
			result.StreamBytes = ci.GetStreamingInspectSize(ctx.Domain)
		}
	}

	// Check if content should be queued for AI analysis
	if ci.config.AIPreparation.Enabled && (decision == DecisionInspect || decision == DecisionConditional) {
		result.AIQueued = ci.shouldQueueForAI(ctx)
	}

	return result
}

// shouldQueueForAI determines if content should be queued for AI analysis
func (ci *ContentInspector) shouldQueueForAI(ctx *InspectionContext) bool {
	if !ci.config.AIPreparation.Enabled {
		return false
	}

	mediaType, _, _ := mime.ParseMediaType(ctx.ContentType)

	// Check if content type is supported for AI analysis
	for _, analysisType := range ci.config.AIPreparation.SupportedAnalysis {
		switch analysisType {
		case "image_ocr":
			if strings.HasPrefix(mediaType, "image/") {
				return true
			}
		case "video_transcript":
			if strings.HasPrefix(mediaType, "video/") {
				return true
			}
		}
	}

	return false
}

// StreamingInspector handles streaming content inspection
type StreamingInspector struct {
	inspector   *ContentInspector
	buffer      []byte
	inspectSize int64
	collected   int64
	done        bool
}

// NewStreamingInspector creates a new streaming inspector
func (ci *ContentInspector) NewStreamingInspector(ctx *InspectionContext) *StreamingInspector {
	inspectSize := ci.GetStreamingInspectSize(ctx.Domain)
	return &StreamingInspector{
		inspector:   ci,
		buffer:      make([]byte, 0, inspectSize),
		inspectSize: inspectSize,
	}
}

// Write implements io.Writer for streaming inspection
func (si *StreamingInspector) Write(p []byte) (int, error) {
	if si.done {
		return len(p), nil
	}

	// Calculate how many bytes we can still collect
	remaining := si.inspectSize - si.collected
	if remaining <= 0 {
		si.done = true
		return len(p), nil
	}

	// Collect up to remaining bytes
	toCollect := int64(len(p))
	if toCollect > remaining {
		toCollect = remaining
	}

	si.buffer = append(si.buffer, p[:toCollect]...)
	si.collected += toCollect

	if si.collected >= si.inspectSize {
		si.done = true
	}

	return len(p), nil
}

// GetCollectedData returns the collected data for inspection
func (si *StreamingInspector) GetCollectedData() []byte {
	return si.buffer
}

// IsDone returns true if we've collected enough data
func (si *StreamingInspector) IsDone() bool {
	return si.done
}

// String returns a string representation of the decision
func (d Decision) String() string {
	switch d {
	case DecisionSkip:
		return "skip"
	case DecisionInspect:
		return "inspect"
	case DecisionConditional:
		return "conditional"
	default:
		return "unknown"
	}
}

// AIQueue represents the file-based AI analysis queue
type AIQueue struct {
	config      *config.AIPreparationConfig
	queueDir    string
	maxSize     int
	currentSize int
}

// NewAIQueue creates a new AI analysis queue
func NewAIQueue(cfg *config.AIPreparationConfig) *AIQueue {
	return &AIQueue{
		config:   cfg,
		queueDir: cfg.QueueDirectory,
		maxSize:  cfg.MaxQueueSize,
	}
}

// QueueItem represents an item in the AI analysis queue
type QueueItem struct {
	ID          string            `json:"id"`
	Timestamp   time.Time         `json:"timestamp"`
	URL         string            `json:"url"`
	Domain      string            `json:"domain"`
	ContentType string            `json:"content_type"`
	Size        int64             `json:"size"`
	Headers     map[string]string `json:"headers"`
	FilePath    string            `json:"file_path"`
	Preview     string            `json:"preview,omitempty"`
	Analysis    []string          `json:"analysis_types"`
}

// QueueForAnalysis queues content for AI analysis
func (aq *AIQueue) QueueForAnalysis(ctx *InspectionContext, content []byte) (*QueueItem, error) {
	if !aq.config.Enabled {
		return nil, fmt.Errorf("AI preparation is disabled")
	}

	// Check queue size limit
	if aq.currentSize >= aq.maxSize {
		return nil, fmt.Errorf("AI queue is full (max: %d)", aq.maxSize)
	}

	// Create queue item
	item := &QueueItem{
		ID:          fmt.Sprintf("%d_%s", time.Now().UnixNano(), strings.ReplaceAll(ctx.Domain, ".", "_")),
		Timestamp:   time.Now(),
		URL:         ctx.URL,
		Domain:      ctx.Domain,
		ContentType: ctx.ContentType,
		Size:        ctx.ContentSize,
		Headers:     make(map[string]string),
		Analysis:    aq.config.SupportedAnalysis,
	}

	// Convert headers to map
	if ctx.Headers != nil {
		for key, values := range ctx.Headers {
			if len(values) > 0 {
				item.Headers[key] = values[0]
			}
		}
	}

	// Create preview if enabled
	if aq.config.MetadataCapture {
		previewSize := parseSize(aq.config.ContentPreviewSize)
		if previewSize > 0 && int64(len(content)) > previewSize {
			item.Preview = string(content[:previewSize])
		} else {
			item.Preview = string(content)
		}
	}

	// This is a simplified implementation - in production, you'd want to:
	// 1. Save content to file system
	// 2. Save metadata to queue index
	// 3. Implement proper queue management
	// 4. Add cleanup mechanisms

	aq.currentSize++
	return item, nil
}
