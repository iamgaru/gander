package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/iamgaru/gander/internal/identity"
)

// IPMACProvider provides identity based on IP addresses and MAC addresses
type IPMACProvider struct {
	enabled     bool
	config      *IPMACConfig
	arpCache    map[string]*MACEntry
	arpMutex    sync.RWMutex
	ipMetadata  map[string]*IPMetadata
	ipMutex     sync.RWMutex
	lastARPScan time.Time
}

// IPMACConfig contains configuration for IP/MAC identity provider
type IPMACConfig struct {
	Enabled          bool          `json:"enabled"`
	Priority         int           `json:"priority"`
	ARPScanInterval  time.Duration `json:"arp_scan_interval"`
	EnableMACLookup  bool          `json:"enable_mac_lookup"`
	EnableIPMetadata bool          `json:"enable_ip_metadata"`
	TrustedNetworks  []string      `json:"trusted_networks"`
	DeviceDatabase   string        `json:"device_database"`
	RefreshInterval  time.Duration `json:"refresh_interval"`
}

// MACEntry represents a MAC address table entry
type MACEntry struct {
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Interface string    `json:"interface"`
	Vendor    string    `json:"vendor"`
	LastSeen  time.Time `json:"last_seen"`
	IsStatic  bool      `json:"is_static"`
}

// IPMetadata contains metadata about an IP address
type IPMetadata struct {
	IPRange      string    `json:"ip_range"`
	Network      string    `json:"network"`
	IsTrusted    bool      `json:"is_trusted"`
	IsPrivate    bool      `json:"is_private"`
	IsLoopback   bool      `json:"is_loopback"`
	Organization string    `json:"organization"`
	Location     string    `json:"location"`
	LastUpdated  time.Time `json:"last_updated"`
}

// DeviceInfo represents device information from database
type DeviceInfo struct {
	MAC         string `json:"mac"`
	DeviceName  string `json:"device_name"`
	DeviceType  string `json:"device_type"`
	Owner       string `json:"owner"`
	Department  string `json:"department"`
	Description string `json:"description"`
}

// NewIPMACProvider creates a new IP/MAC identity provider
func NewIPMACProvider() identity.IdentityProvider {
	return &IPMACProvider{
		arpCache:   make(map[string]*MACEntry),
		ipMetadata: make(map[string]*IPMetadata),
	}
}

// Name returns the provider name
func (p *IPMACProvider) Name() string {
	return "ip_mac"
}

// Type returns the identity type this provider resolves
func (p *IPMACProvider) Type() identity.IdentityType {
	return identity.IdentityIP
}

// Initialize sets up the provider with configuration
func (p *IPMACProvider) Initialize(config map[string]interface{}) error {
	// Parse configuration
	configData, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	p.config = &IPMACConfig{
		Enabled:          true,
		Priority:         50,
		ARPScanInterval:  5 * time.Minute,
		EnableMACLookup:  true,
		EnableIPMetadata: true,
		RefreshInterval:  1 * time.Hour,
	}

	if err := json.Unmarshal(configData, p.config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	p.enabled = p.config.Enabled

	if p.enabled {
		// Initial ARP table scan
		if err := p.scanARPTable(); err != nil {
			// Log error but don't fail initialization
		}

		// Load device database if configured
		if p.config.DeviceDatabase != "" {
			if err := p.loadDeviceDatabase(); err != nil {
				// Log error but don't fail initialization
			}
		}

		// Start background refresh
		go p.refreshLoop()
	}

	return nil
}

// ResolveIdentity attempts to resolve identity from connection info
func (p *IPMACProvider) ResolveIdentity(ctx context.Context, req *identity.IdentityRequest) (*identity.Identity, error) {
	if !p.enabled {
		return nil, fmt.Errorf("provider disabled")
	}

	ip := req.ClientIP
	if ip == "" {
		return nil, fmt.Errorf("no client IP provided")
	}

	// Clean IP (remove port if present)
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}

	// Create base identity
	ident := &identity.Identity{
		Type:        identity.IdentityIP,
		ID:          ip,
		DisplayName: ip,
		Source:      p.Name(),
		ResolvedAt:  time.Now(),
		Confidence:  0.8, // High confidence for IP-based identity
		Metadata:    make(map[string]interface{}),
		TTL:         10 * time.Minute,
	}

	// Add IP metadata
	if p.config.EnableIPMetadata {
		if metadata := p.getIPMetadata(ip); metadata != nil {
			ident.Metadata["ip_metadata"] = metadata
			if metadata.Organization != "" {
				ident.DisplayName = fmt.Sprintf("%s (%s)", ip, metadata.Organization)
			}
		}
	}

	// Add MAC address if available
	if p.config.EnableMACLookup {
		if macEntry := p.getMACForIP(ip); macEntry != nil {
			ident.Metadata["mac_address"] = macEntry.MAC
			ident.Metadata["mac_vendor"] = macEntry.Vendor
			ident.Metadata["interface"] = macEntry.Interface
			ident.Metadata["last_seen"] = macEntry.LastSeen

			// Try to get device info
			if deviceInfo := p.getDeviceInfo(macEntry.MAC); deviceInfo != nil {
				ident.DisplayName = deviceInfo.DeviceName
				ident.Metadata["device_info"] = deviceInfo
				ident.Confidence = 0.95 // Higher confidence with device info
			}
		}
	}

	return ident, nil
}

// EnrichIdentity adds additional metadata to an existing identity
func (p *IPMACProvider) EnrichIdentity(ctx context.Context, ident *identity.Identity) error {
	if !p.enabled || ident.Type != identity.IdentityIP {
		return nil
	}

	// Refresh ARP table if needed
	if time.Since(p.lastARPScan) > p.config.ARPScanInterval {
		go p.scanARPTable()
	}

	// Add network context
	if ipAddr := net.ParseIP(ident.ID); ipAddr != nil {
		ident.Metadata["is_private"] = ipAddr.IsPrivate()
		ident.Metadata["is_loopback"] = ipAddr.IsLoopback()
		ident.Metadata["is_multicast"] = ipAddr.IsMulticast()

		// Check if in trusted networks
		for _, network := range p.config.TrustedNetworks {
			if _, cidr, err := net.ParseCIDR(network); err == nil {
				if cidr.Contains(ipAddr) {
					ident.Metadata["is_trusted"] = true
					ident.Metadata["trusted_network"] = network
					break
				}
			}
		}
	}

	return nil
}

// IsEnabled returns whether this provider is currently enabled
func (p *IPMACProvider) IsEnabled() bool {
	return p.enabled
}

// Priority returns the provider priority
func (p *IPMACProvider) Priority() int {
	if p.config != nil {
		return p.config.Priority
	}
	return 50
}

// Shutdown cleans up provider resources
func (p *IPMACProvider) Shutdown() error {
	p.enabled = false
	return nil
}

// scanARPTable scans the system ARP table for MAC addresses
func (p *IPMACProvider) scanARPTable() error {
	p.arpMutex.Lock()
	defer p.arpMutex.Unlock()

	// Try different ARP commands based on OS
	var cmd *exec.Cmd
	switch {
	case isCommandAvailable("arp"):
		cmd = exec.Command("arp", "-a")
	case isCommandAvailable("ip"):
		cmd = exec.Command("ip", "neigh", "show")
	default:
		return fmt.Errorf("no suitable ARP command found")
	}

	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to execute ARP command: %w", err)
	}

	// Parse ARP output
	entries := p.parseARPOutput(string(output))
	for _, entry := range entries {
		p.arpCache[entry.IP] = entry
	}

	p.lastARPScan = time.Now()
	return nil
}

// parseARPOutput parses ARP command output into MAC entries
func (p *IPMACProvider) parseARPOutput(output string) []*MACEntry {
	entries := make([]*MACEntry, 0)
	lines := strings.Split(output, "\n")

	// Regex patterns for different ARP output formats
	arpPattern := regexp.MustCompile(`\(([\d.]+)\) at ([a-fA-F0-9:]{17})(?: \[ether\])?(?: on (\w+))?`)
	ipPattern := regexp.MustCompile(`([\d.]+) dev (\w+) lladdr ([a-fA-F0-9:]{17})`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var entry *MACEntry

		// Try ARP -a format
		if matches := arpPattern.FindStringSubmatch(line); len(matches) >= 3 {
			entry = &MACEntry{
				IP:       matches[1],
				MAC:      strings.ToUpper(matches[2]),
				LastSeen: time.Now(),
			}
			if len(matches) > 3 && matches[3] != "" {
				entry.Interface = matches[3]
			}
		}

		// Try ip neigh format
		if entry == nil {
			if matches := ipPattern.FindStringSubmatch(line); len(matches) >= 4 {
				entry = &MACEntry{
					IP:        matches[1],
					Interface: matches[2],
					MAC:       strings.ToUpper(matches[3]),
					LastSeen:  time.Now(),
				}
			}
		}

		if entry != nil {
			// Add vendor lookup
			entry.Vendor = p.getMACVendor(entry.MAC)
			entries = append(entries, entry)
		}
	}

	return entries
}

// getMACForIP returns the MAC address for a given IP
func (p *IPMACProvider) getMACForIP(ip string) *MACEntry {
	p.arpMutex.RLock()
	defer p.arpMutex.RUnlock()
	return p.arpCache[ip]
}

// getIPMetadata returns metadata for an IP address
func (p *IPMACProvider) getIPMetadata(ip string) *IPMetadata {
	p.ipMutex.RLock()
	defer p.ipMutex.RUnlock()

	// Check cache first
	if metadata, exists := p.ipMetadata[ip]; exists {
		return metadata
	}

	// Generate metadata for new IP
	metadata := &IPMetadata{
		LastUpdated: time.Now(),
	}

	if ipAddr := net.ParseIP(ip); ipAddr != nil {
		metadata.IsPrivate = ipAddr.IsPrivate()
		metadata.IsLoopback = ipAddr.IsLoopback()

		// Determine network range
		if metadata.IsPrivate {
			switch {
			case ipAddr.To4() != nil:
				if strings.HasPrefix(ip, "192.168.") {
					metadata.Network = "192.168.0.0/16"
					metadata.Organization = "Local Network"
				} else if strings.HasPrefix(ip, "10.") {
					metadata.Network = "10.0.0.0/8"
					metadata.Organization = "Private Network"
				} else if strings.HasPrefix(ip, "172.") {
					metadata.Network = "172.16.0.0/12"
					metadata.Organization = "Private Network"
				}
			}
		}

		metadata.IsTrusted = metadata.IsPrivate || metadata.IsLoopback
	}

	// Cache the metadata
	p.ipMutex.Lock()
	p.ipMetadata[ip] = metadata
	p.ipMutex.Unlock()

	return metadata
}

// getMACVendor returns the vendor for a MAC address (simplified)
func (p *IPMACProvider) getMACVendor(mac string) string {
	if len(mac) < 8 {
		return ""
	}

	// Extract OUI (first 3 octets)
	oui := strings.ToUpper(mac[:8])

	// Simple vendor mapping (in production, use IEEE OUI database)
	vendors := map[string]string{
		"00:50:56": "VMware",
		"08:00:27": "VirtualBox",
		"52:54:00": "QEMU",
		"00:15:5D": "Microsoft",
		"00:1C:42": "Parallels",
		"02:00:4C": "Docker",
	}

	if vendor, exists := vendors[oui]; exists {
		return vendor
	}

	return "Unknown"
}

// loadDeviceDatabase loads device information from database file
func (p *IPMACProvider) loadDeviceDatabase() error {
	if p.config.DeviceDatabase == "" {
		return nil
	}

	// Placeholder for device database loading
	// In production, this would load from JSON/CSV/database
	return nil
}

// getDeviceInfo returns device information for a MAC address
func (p *IPMACProvider) getDeviceInfo(mac string) *DeviceInfo {
	// Placeholder for device database lookup
	// In production, this would query the loaded device database
	return nil
}

// refreshLoop periodically refreshes ARP table and metadata
func (p *IPMACProvider) refreshLoop() {
	ticker := time.NewTicker(p.config.RefreshInterval)
	defer ticker.Stop()

	for p.enabled {
		select {
		case <-ticker.C:
			p.scanARPTable()
		}
	}
}

// isCommandAvailable checks if a command is available on the system
func isCommandAvailable(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}
