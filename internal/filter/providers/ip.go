package providers

import (
	"context"
	"log"
	"net"

	"github.com/iamgaru/gander/internal/filter"
)

// IPFilterProvider implements IP-based filtering
type IPFilterProvider struct {
	name       string
	inspectIPs map[string]bool
	bypassIPs  map[string]bool

	// CIDR ranges
	inspectCIDRs []*net.IPNet
	bypassCIDRs  []*net.IPNet

	enableDebug bool
}

// NewIPFilterProvider creates a new IP filter provider
func NewIPFilterProvider() *IPFilterProvider {
	return &IPFilterProvider{
		name:         "ip",
		inspectIPs:   make(map[string]bool),
		bypassIPs:    make(map[string]bool),
		inspectCIDRs: make([]*net.IPNet, 0),
		bypassCIDRs:  make([]*net.IPNet, 0),
	}
}

// Name returns the provider name
func (p *IPFilterProvider) Name() string {
	return p.name
}

// Initialize initializes the provider with configuration
func (p *IPFilterProvider) Initialize(config map[string]interface{}) error {
	p.enableDebug = false
	if debug, ok := config["enable_debug"].(bool); ok {
		p.enableDebug = debug
	}

	// Parse inspect IPs
	if inspectIPs, ok := config["inspect_ips"].([]interface{}); ok {
		for _, ip := range inspectIPs {
			if ipStr, ok := ip.(string); ok {
				p.addInspectIP(ipStr)
			}
		}
	} else if inspectIPsStr, ok := config["inspect_ips"].([]string); ok {
		for _, ip := range inspectIPsStr {
			p.addInspectIP(ip)
		}
	}

	// Parse bypass IPs
	if bypassIPs, ok := config["bypass_ips"].([]interface{}); ok {
		for _, ip := range bypassIPs {
			if ipStr, ok := ip.(string); ok {
				p.addBypassIP(ipStr)
			}
		}
	} else if bypassIPsStr, ok := config["bypass_ips"].([]string); ok {
		for _, ip := range bypassIPsStr {
			p.addBypassIP(ip)
		}
	}

	if p.enableDebug {
		log.Printf("IP filter initialized: %d inspect IPs (%d CIDRs), %d bypass IPs (%d CIDRs)",
			len(p.inspectIPs), len(p.inspectCIDRs),
			len(p.bypassIPs), len(p.bypassCIDRs))
	}

	return nil
}

// GetPacketFilters returns packet filters provided by this provider
func (p *IPFilterProvider) GetPacketFilters() []filter.PacketFilter {
	return []filter.PacketFilter{&IPPacketFilter{provider: p}}
}

// GetInspectionFilters returns inspection filters provided by this provider
func (p *IPFilterProvider) GetInspectionFilters() []filter.InspectionFilter {
	return []filter.InspectionFilter{&IPInspectionFilter{provider: p}}
}

// Shutdown shuts down the provider
func (p *IPFilterProvider) Shutdown() error {
	// No cleanup needed for IP provider
	return nil
}

// addInspectIP adds an IP or CIDR to the inspect list
func (p *IPFilterProvider) addInspectIP(ipStr string) {
	if _, cidr, err := net.ParseCIDR(ipStr); err == nil {
		p.inspectCIDRs = append(p.inspectCIDRs, cidr)
	} else {
		p.inspectIPs[ipStr] = true
	}
}

// addBypassIP adds an IP or CIDR to the bypass list
func (p *IPFilterProvider) addBypassIP(ipStr string) {
	if _, cidr, err := net.ParseCIDR(ipStr); err == nil {
		p.bypassCIDRs = append(p.bypassCIDRs, cidr)
	} else {
		p.bypassIPs[ipStr] = true
	}
}

// shouldInspect checks if an IP should be inspected
func (p *IPFilterProvider) shouldInspect(clientIP net.IP) bool {
	// Check exact match
	if p.inspectIPs[clientIP.String()] {
		return true
	}

	// Check CIDR ranges
	for _, cidr := range p.inspectCIDRs {
		if cidr.Contains(clientIP) {
			return true
		}
	}

	return false
}

// shouldBypass checks if an IP should be bypassed
func (p *IPFilterProvider) shouldBypass(clientIP net.IP) bool {
	// Check exact match
	if p.bypassIPs[clientIP.String()] {
		return true
	}

	// Check CIDR ranges
	for _, cidr := range p.bypassCIDRs {
		if cidr.Contains(clientIP) {
			return true
		}
	}

	return false
}

// IPPacketFilter implements PacketFilter for IP-based filtering
type IPPacketFilter struct {
	provider *IPFilterProvider
}

func (f *IPPacketFilter) Name() string {
	return "ip-packet-filter"
}

func (f *IPPacketFilter) Priority() int {
	return 90 // Slightly lower than domain filter
}

func (f *IPPacketFilter) ShouldFilter(ctx context.Context, filterCtx *filter.FilterContext) (filter.FilterResult, error) {
	clientIP := filterCtx.ClientIP
	if clientIP == nil {
		return filter.FilterAllow, nil
	}

	// Check bypass first (highest priority)
	if f.provider.shouldBypass(clientIP) {
		if f.provider.enableDebug {
			log.Printf("IP %s bypassed by IP filter", clientIP.String())
		}
		return filter.FilterBypass, nil
	}

	// Check if should inspect
	if f.provider.shouldInspect(clientIP) {
		if f.provider.enableDebug {
			log.Printf("IP %s marked for inspection by IP filter", clientIP.String())
		}
		return filter.FilterInspect, nil
	}

	return filter.FilterAllow, nil
}

// IPInspectionFilter implements InspectionFilter for IP-based inspection
type IPInspectionFilter struct {
	provider *IPFilterProvider
}

func (f *IPInspectionFilter) Name() string {
	return "ip-inspection-filter"
}

func (f *IPInspectionFilter) Priority() int {
	return 90 // Slightly lower than domain filter
}

func (f *IPInspectionFilter) ShouldFilter(ctx context.Context, filterCtx *filter.FilterContext) (filter.FilterResult, error) {
	// Same logic as packet filter for consistency
	return f.InspectRequest(ctx, filterCtx)
}

func (f *IPInspectionFilter) InspectRequest(ctx context.Context, filterCtx *filter.FilterContext) (filter.FilterResult, error) {
	clientIP := filterCtx.ClientIP
	if clientIP == nil {
		return filter.FilterAllow, nil
	}

	// Check if should capture/inspect the request
	if f.provider.shouldInspect(clientIP) && !f.provider.shouldBypass(clientIP) {
		return filter.FilterCapture, nil
	}

	return filter.FilterAllow, nil
}

func (f *IPInspectionFilter) InspectResponse(ctx context.Context, filterCtx *filter.FilterContext) (filter.FilterResult, error) {
	clientIP := filterCtx.ClientIP
	if clientIP == nil {
		return filter.FilterAllow, nil
	}

	// Check if should capture/inspect the response
	if f.provider.shouldInspect(clientIP) && !f.provider.shouldBypass(clientIP) {
		return filter.FilterCapture, nil
	}

	return filter.FilterAllow, nil
}
