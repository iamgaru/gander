package providers

import (
	"context"
	"log"
	"strings"

	"github.com/iamgaru/gander/internal/filter"
)

// DomainFilterProvider implements domain-based filtering
type DomainFilterProvider struct {
	name           string
	inspectDomains map[string]bool
	bypassDomains  map[string]bool

	// Wildcard patterns
	inspectWildcards []string
	bypassWildcards  []string

	// Special flags
	inspectAll bool

	enableDebug bool
}

// NewDomainFilterProvider creates a new domain filter provider
func NewDomainFilterProvider() *DomainFilterProvider {
	return &DomainFilterProvider{
		name:             "domain",
		inspectDomains:   make(map[string]bool),
		bypassDomains:    make(map[string]bool),
		inspectWildcards: make([]string, 0),
		bypassWildcards:  make([]string, 0),
	}
}

// Name returns the provider name
func (d *DomainFilterProvider) Name() string {
	return d.name
}

// Initialize initializes the provider with configuration
func (d *DomainFilterProvider) Initialize(config map[string]interface{}) error {
	d.enableDebug = false
	if debug, ok := config["enable_debug"].(bool); ok {
		d.enableDebug = debug
	}

	// Parse inspect domains
	if inspectDomains, ok := config["inspect_domains"].([]interface{}); ok {
		for _, domain := range inspectDomains {
			if domainStr, ok := domain.(string); ok {
				d.addInspectDomain(domainStr)
			}
		}
	} else if inspectDomainsStr, ok := config["inspect_domains"].([]string); ok {
		for _, domain := range inspectDomainsStr {
			d.addInspectDomain(domain)
		}
	}

	// Parse bypass domains
	if bypassDomains, ok := config["bypass_domains"].([]interface{}); ok {
		for _, domain := range bypassDomains {
			if domainStr, ok := domain.(string); ok {
				d.addBypassDomain(domainStr)
			}
		}
	} else if bypassDomainsStr, ok := config["bypass_domains"].([]string); ok {
		for _, domain := range bypassDomainsStr {
			d.addBypassDomain(domain)
		}
	}

	if d.enableDebug {
		log.Printf("Domain filter initialized: %d inspect domains (%d wildcards), %d bypass domains (%d wildcards)",
			len(d.inspectDomains), len(d.inspectWildcards),
			len(d.bypassDomains), len(d.bypassWildcards))
	}

	return nil
}

// GetPacketFilters returns packet filters provided by this provider
func (d *DomainFilterProvider) GetPacketFilters() []filter.PacketFilter {
	return []filter.PacketFilter{&DomainPacketFilter{provider: d}}
}

// GetInspectionFilters returns inspection filters provided by this provider
func (d *DomainFilterProvider) GetInspectionFilters() []filter.InspectionFilter {
	return []filter.InspectionFilter{&DomainInspectionFilter{provider: d}}
}

// Shutdown shuts down the provider
func (d *DomainFilterProvider) Shutdown() error {
	// No cleanup needed for domain provider
	return nil
}

// addInspectDomain adds a domain to the inspect list
func (d *DomainFilterProvider) addInspectDomain(domain string) {
	if domain == "*" {
		d.inspectAll = true
		return
	}

	if strings.Contains(domain, "*") {
		d.inspectWildcards = append(d.inspectWildcards, domain)
	} else {
		d.inspectDomains[domain] = true
	}
}

// addBypassDomain adds a domain to the bypass list
func (d *DomainFilterProvider) addBypassDomain(domain string) {
	if strings.Contains(domain, "*") {
		d.bypassWildcards = append(d.bypassWildcards, domain)
	} else {
		d.bypassDomains[domain] = true
	}
}

// shouldInspect checks if a domain should be inspected
func (d *DomainFilterProvider) shouldInspect(domain string) bool {
	if d.inspectAll {
		return true
	}

	// Check exact match
	if d.inspectDomains[domain] {
		return true
	}

	// Check wildcard patterns
	return d.checkWildcards(domain, d.inspectWildcards)
}

// shouldBypass checks if a domain should be bypassed
func (d *DomainFilterProvider) shouldBypass(domain string) bool {
	// Check exact match
	if d.bypassDomains[domain] {
		return true
	}

	// Check wildcard patterns
	return d.checkWildcards(domain, d.bypassWildcards)
}

// checkWildcards checks if domain matches any wildcard pattern
func (d *DomainFilterProvider) checkWildcards(domain string, wildcards []string) bool {
	for _, pattern := range wildcards {
		if d.matchDomainPattern(domain, pattern) {
			return true
		}
	}
	return false
}

// matchDomainPattern matches domain against pattern (supports * wildcard)
func (d *DomainFilterProvider) matchDomainPattern(domain, pattern string) bool {
	if pattern == "*" {
		return true
	}

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:] // Remove "*."
		return domain == suffix || strings.HasSuffix(domain, "."+suffix)
	}

	if strings.HasSuffix(pattern, ".*") {
		prefix := pattern[:len(pattern)-2] // Remove ".*"
		return strings.HasPrefix(domain, prefix+".")
	}

	return domain == pattern
}

// DomainPacketFilter implements PacketFilter for domain-based filtering
type DomainPacketFilter struct {
	provider *DomainFilterProvider
}

func (f *DomainPacketFilter) Name() string {
	return "domain-packet-filter"
}

func (f *DomainPacketFilter) Priority() int {
	return 100 // High priority for domain filtering
}

func (f *DomainPacketFilter) ShouldFilter(ctx context.Context, filterCtx *filter.FilterContext) (filter.FilterResult, error) {
	domain := filterCtx.Domain
	if domain == "" {
		return filter.FilterAllow, nil
	}

	// Check bypass first (highest priority)
	if f.provider.shouldBypass(domain) {
		if f.provider.enableDebug {
			log.Printf("Domain %s bypassed by domain filter", domain)
		}
		return filter.FilterBypass, nil
	}

	// Check if should inspect
	if f.provider.shouldInspect(domain) {
		if f.provider.enableDebug {
			log.Printf("Domain %s marked for inspection by domain filter", domain)
		}
		return filter.FilterInspect, nil
	}

	return filter.FilterAllow, nil
}

// DomainInspectionFilter implements InspectionFilter for domain-based inspection
type DomainInspectionFilter struct {
	provider *DomainFilterProvider
}

func (f *DomainInspectionFilter) Name() string {
	return "domain-inspection-filter"
}

func (f *DomainInspectionFilter) Priority() int {
	return 100 // High priority for domain filtering
}

func (f *DomainInspectionFilter) ShouldFilter(ctx context.Context, filterCtx *filter.FilterContext) (filter.FilterResult, error) {
	// Same logic as packet filter for consistency
	return f.InspectRequest(ctx, filterCtx)
}

func (f *DomainInspectionFilter) InspectRequest(ctx context.Context, filterCtx *filter.FilterContext) (filter.FilterResult, error) {
	domain := filterCtx.Domain
	if domain == "" {
		return filter.FilterAllow, nil
	}

	// Check if should capture/inspect the request
	if f.provider.shouldInspect(domain) && !f.provider.shouldBypass(domain) {
		return filter.FilterCapture, nil
	}

	return filter.FilterAllow, nil
}

func (f *DomainInspectionFilter) InspectResponse(ctx context.Context, filterCtx *filter.FilterContext) (filter.FilterResult, error) {
	domain := filterCtx.Domain
	if domain == "" {
		return filter.FilterAllow, nil
	}

	// Check if should capture/inspect the response
	if f.provider.shouldInspect(domain) && !f.provider.shouldBypass(domain) {
		return filter.FilterCapture, nil
	}

	return filter.FilterAllow, nil
}
