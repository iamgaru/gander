package providers

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/iamgaru/gander/internal/filter"
)

// CustomFilterProvider demonstrates how to create custom filter providers
// This example implements a time-based filter that only allows traffic during business hours
type CustomFilterProvider struct {
	name              string
	businessHoursOnly bool
	blockedUserAgents []string
	enableDebug       bool
}

// NewCustomFilterProvider creates a new custom filter provider
func NewCustomFilterProvider() *CustomFilterProvider {
	return &CustomFilterProvider{
		name:              "custom",
		blockedUserAgents: make([]string, 0),
	}
}

// Name returns the provider name
func (c *CustomFilterProvider) Name() string {
	return c.name
}

// Initialize initializes the provider with configuration
func (c *CustomFilterProvider) Initialize(config map[string]interface{}) error {
	c.enableDebug = false
	if debug, ok := config["enable_debug"].(bool); ok {
		c.enableDebug = debug
	}

	// Parse business hours only setting
	if businessHours, ok := config["business_hours_only"].(bool); ok {
		c.businessHoursOnly = businessHours
	}

	// Parse blocked user agents
	if blockedUA, ok := config["blocked_user_agents"].([]interface{}); ok {
		for _, ua := range blockedUA {
			if uaStr, ok := ua.(string); ok {
				c.blockedUserAgents = append(c.blockedUserAgents, strings.ToLower(uaStr))
			}
		}
	} else if blockedUAStr, ok := config["blocked_user_agents"].([]string); ok {
		for _, ua := range blockedUAStr {
			c.blockedUserAgents = append(c.blockedUserAgents, strings.ToLower(ua))
		}
	}

	if c.enableDebug {
		log.Printf("Custom filter initialized: business_hours_only=%t, blocked_user_agents=%d",
			c.businessHoursOnly, len(c.blockedUserAgents))
	}

	return nil
}

// GetPacketFilters returns packet filters provided by this provider
func (c *CustomFilterProvider) GetPacketFilters() []filter.PacketFilter {
	return []filter.PacketFilter{&CustomPacketFilter{provider: c}}
}

// GetInspectionFilters returns inspection filters provided by this provider
func (c *CustomFilterProvider) GetInspectionFilters() []filter.InspectionFilter {
	return []filter.InspectionFilter{&CustomInspectionFilter{provider: c}}
}

// Shutdown shuts down the provider
func (c *CustomFilterProvider) Shutdown() error {
	// No cleanup needed for custom provider
	return nil
}

// isBusinessHours checks if current time is within business hours (9 AM - 5 PM)
func (c *CustomFilterProvider) isBusinessHours() bool {
	if !c.businessHoursOnly {
		return true
	}

	now := time.Now()
	hour := now.Hour()

	// Business hours: 9 AM to 5 PM (17:00), Monday to Friday
	isWeekday := now.Weekday() >= time.Monday && now.Weekday() <= time.Friday
	return isWeekday && hour >= 9 && hour < 17
}

// isBlockedUserAgent checks if user agent contains blocked strings
func (c *CustomFilterProvider) isBlockedUserAgent(userAgent string) bool {
	if userAgent == "" {
		return false
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, blocked := range c.blockedUserAgents {
		if strings.Contains(userAgentLower, blocked) {
			return true
		}
	}

	return false
}

// CustomPacketFilter implements PacketFilter for custom filtering
type CustomPacketFilter struct {
	provider *CustomFilterProvider
}

func (f *CustomPacketFilter) Name() string {
	return "custom-packet-filter"
}

func (f *CustomPacketFilter) Priority() int {
	return 50 // Medium priority
}

func (f *CustomPacketFilter) ShouldFilter(ctx context.Context, filterCtx *filter.FilterContext) (filter.FilterResult, error) {
	// Check business hours
	if !f.provider.isBusinessHours() {
		if f.provider.enableDebug {
			log.Printf("Traffic blocked by custom filter: outside business hours")
		}
		return filter.FilterBlock, nil
	}

	return filter.FilterAllow, nil
}

// CustomInspectionFilter implements InspectionFilter for custom inspection
type CustomInspectionFilter struct {
	provider *CustomFilterProvider
}

func (f *CustomInspectionFilter) Name() string {
	return "custom-inspection-filter"
}

func (f *CustomInspectionFilter) Priority() int {
	return 50 // Medium priority
}

func (f *CustomInspectionFilter) ShouldFilter(ctx context.Context, filterCtx *filter.FilterContext) (filter.FilterResult, error) {
	// Same logic as packet filter for consistency
	return f.InspectRequest(ctx, filterCtx)
}

func (f *CustomInspectionFilter) InspectRequest(ctx context.Context, filterCtx *filter.FilterContext) (filter.FilterResult, error) {
	// Extract user agent from request data if available
	if filterCtx.RequestData != nil {
		// This is a simplified example - in reality you'd parse the HTTP headers properly
		requestStr := string(filterCtx.RequestData)
		if strings.Contains(requestStr, "User-Agent:") {
			// Extract user agent (simplified)
			lines := strings.Split(requestStr, "\n")
			for _, line := range lines {
				if strings.HasPrefix(strings.ToLower(line), "user-agent:") {
					userAgent := strings.TrimSpace(line[len("user-agent:"):])
					if f.provider.isBlockedUserAgent(userAgent) {
						if f.provider.enableDebug {
							log.Printf("Request blocked by custom filter: blocked user agent '%s'", userAgent)
						}
						return filter.FilterBlock, nil
					}
				}
			}
		}
	}

	return filter.FilterAllow, nil
}

func (f *CustomInspectionFilter) InspectResponse(ctx context.Context, filterCtx *filter.FilterContext) (filter.FilterResult, error) {
	// Custom response inspection logic could go here
	// For this example, we'll just allow all responses
	return filter.FilterAllow, nil
}
