package identity

import (
	"context"
	"time"
)

// IdentityType represents different types of identities
type IdentityType string

const (
	IdentityIP      IdentityType = "ip"
	IdentityMAC     IdentityType = "mac"
	IdentityUser    IdentityType = "user"
	IdentityDevice  IdentityType = "device"
	IdentitySession IdentityType = "session"
	IdentityUnknown IdentityType = "unknown"
)

// Identity represents a resolved identity with metadata
type Identity struct {
	Type        IdentityType           `json:"type"`
	ID          string                 `json:"id"`
	DisplayName string                 `json:"display_name"`
	Metadata    map[string]interface{} `json:"metadata"`
	Confidence  float64                `json:"confidence"`
	Source      string                 `json:"source"`
	ResolvedAt  time.Time              `json:"resolved_at"`
	TTL         time.Duration          `json:"ttl,omitempty"`
}

// IdentityContext contains all resolved identities for a connection
type IdentityContext struct {
	PrimaryIdentity *Identity  `json:"primary_identity"`
	AllIdentities   []Identity `json:"all_identities"`
	ClientIP        string     `json:"client_ip"`
	ResolvedAt      time.Time  `json:"resolved_at"`
}

// IdentityProvider interface for pluggable identity resolution
type IdentityProvider interface {
	// Name returns the provider name
	Name() string

	// Type returns the identity type this provider resolves
	Type() IdentityType

	// Initialize sets up the provider with configuration
	Initialize(config map[string]interface{}) error

	// ResolveIdentity attempts to resolve identity from connection info
	ResolveIdentity(ctx context.Context, req *IdentityRequest) (*Identity, error)

	// EnrichIdentity adds additional metadata to an existing identity
	EnrichIdentity(ctx context.Context, identity *Identity) error

	// IsEnabled returns whether this provider is currently enabled
	IsEnabled() bool

	// Priority returns the provider priority (higher = more important)
	Priority() int

	// Shutdown cleans up provider resources
	Shutdown() error
}

// IdentityRequest contains information needed for identity resolution
type IdentityRequest struct {
	ClientIP   string            `json:"client_ip"`
	ClientPort int               `json:"client_port"`
	ServerIP   string            `json:"server_ip"`
	ServerPort int               `json:"server_port"`
	Protocol   string            `json:"protocol"`
	Domain     string            `json:"domain"`
	UserAgent  string            `json:"user_agent"`
	Headers    map[string]string `json:"headers"`
	Timestamp  time.Time         `json:"timestamp"`

	// Additional context that might be available
	Interface string `json:"interface,omitempty"`
	VlanID    int    `json:"vlan_id,omitempty"`

	// Existing partial identity (for enrichment)
	ExistingIdentity *Identity `json:"existing_identity,omitempty"`
}

// IdentityManager manages multiple identity providers
type IdentityManager struct {
	providers map[string]IdentityProvider
	cache     IdentityCache
	config    *IdentityConfig
	enabled   bool
}

// IdentityConfig contains identity system configuration
type IdentityConfig struct {
	Enabled           bool                   `json:"enabled"`
	CacheEnabled      bool                   `json:"cache_enabled"`
	CacheTTL          time.Duration          `json:"cache_ttl"`
	MaxCacheSize      int                    `json:"max_cache_size"`
	EnabledProviders  []string               `json:"enabled_providers"`
	ProviderConfigs   map[string]interface{} `json:"provider_configs"`
	PrimaryProvider   string                 `json:"primary_provider"`
	EnrichmentEnabled bool                   `json:"enrichment_enabled"`
	ResolveTimeout    time.Duration          `json:"resolve_timeout"`
}

// IdentityCache interface for caching resolved identities
type IdentityCache interface {
	Get(key string) (*IdentityContext, bool)
	Set(key string, identity *IdentityContext, ttl time.Duration)
	Delete(key string)
	Clear()
	Size() int
	Stats() CacheStats
}

// CacheStats contains cache performance statistics
type CacheStats struct {
	Hits      int64   `json:"hits"`
	Misses    int64   `json:"misses"`
	Evictions int64   `json:"evictions"`
	Size      int     `json:"size"`
	HitRatio  float64 `json:"hit_ratio"`
}

// NewIdentityManager creates a new identity manager
func NewIdentityManager(config *IdentityConfig) *IdentityManager {
	return &IdentityManager{
		providers: make(map[string]IdentityProvider),
		cache:     NewMemoryCache(config.MaxCacheSize),
		config:    config,
		enabled:   config.Enabled,
	}
}

// RegisterProvider registers an identity provider
func (im *IdentityManager) RegisterProvider(provider IdentityProvider) error {
	if !im.enabled {
		return nil
	}

	// Initialize provider with its specific config
	providerConfig := make(map[string]interface{})
	if config, exists := im.config.ProviderConfigs[provider.Name()]; exists {
		if configMap, ok := config.(map[string]interface{}); ok {
			providerConfig = configMap
		}
	}

	if err := provider.Initialize(providerConfig); err != nil {
		return err
	}

	im.providers[provider.Name()] = provider
	return nil
}

// ResolveIdentity resolves identity from connection information
func (im *IdentityManager) ResolveIdentity(ctx context.Context, req *IdentityRequest) (*IdentityContext, error) {
	if !im.enabled {
		return &IdentityContext{
			ClientIP:   req.ClientIP,
			ResolvedAt: time.Now(),
		}, nil
	}

	// Check cache first
	cacheKey := im.generateCacheKey(req)
	if im.config.CacheEnabled {
		if cached, found := im.cache.Get(cacheKey); found {
			return cached, nil
		}
	}

	// Resolve using providers
	identityCtx := &IdentityContext{
		ClientIP:      req.ClientIP,
		AllIdentities: make([]Identity, 0),
		ResolvedAt:    time.Now(),
	}

	// Try each enabled provider
	for _, providerName := range im.config.EnabledProviders {
		if provider, exists := im.providers[providerName]; exists && provider.IsEnabled() {

			// Create context with timeout
			resolveCtx, cancel := context.WithTimeout(ctx, im.config.ResolveTimeout)

			identity, err := provider.ResolveIdentity(resolveCtx, req)
			cancel()

			if err == nil && identity != nil {
				identityCtx.AllIdentities = append(identityCtx.AllIdentities, *identity)

				// Set primary identity based on priority or configured primary provider
				if identityCtx.PrimaryIdentity == nil ||
					provider.Name() == im.config.PrimaryProvider ||
					provider.Priority() > im.getPrimaryProviderPriority(identityCtx.PrimaryIdentity) {
					identityCtx.PrimaryIdentity = identity
				}
			}
		}
	}

	// Enrich identities if enabled
	if im.config.EnrichmentEnabled {
		im.enrichIdentities(ctx, identityCtx)
	}

	// Cache the result
	if im.config.CacheEnabled && identityCtx.PrimaryIdentity != nil {
		ttl := im.config.CacheTTL
		if identityCtx.PrimaryIdentity.TTL > 0 {
			ttl = identityCtx.PrimaryIdentity.TTL
		}
		im.cache.Set(cacheKey, identityCtx, ttl)
	}

	return identityCtx, nil
}

// enrichIdentities adds additional metadata to resolved identities
func (im *IdentityManager) enrichIdentities(ctx context.Context, identityCtx *IdentityContext) {
	for i := range identityCtx.AllIdentities {
		identity := &identityCtx.AllIdentities[i]

		// Find the provider that created this identity and ask it to enrich
		for _, provider := range im.providers {
			if provider.Type() == identity.Type {
				enrichCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				provider.EnrichIdentity(enrichCtx, identity)
				cancel()
				break
			}
		}
	}
}

// getPrimaryProviderPriority gets the priority of the provider that created the primary identity
func (im *IdentityManager) getPrimaryProviderPriority(primary *Identity) int {
	for _, provider := range im.providers {
		if provider.Name() == primary.Source {
			return provider.Priority()
		}
	}
	return 0
}

// generateCacheKey creates a cache key from the request
func (im *IdentityManager) generateCacheKey(req *IdentityRequest) string {
	return req.ClientIP + ":" + req.Protocol
}

// GetStats returns identity system statistics
func (im *IdentityManager) GetStats() map[string]interface{} {
	stats := map[string]interface{}{
		"enabled":           im.enabled,
		"providers_count":   len(im.providers),
		"enabled_providers": im.config.EnabledProviders,
	}

	if im.config.CacheEnabled {
		stats["cache"] = im.cache.Stats()
	}

	return stats
}

// Shutdown cleanly shuts down all providers
func (im *IdentityManager) Shutdown() error {
	for _, provider := range im.providers {
		if err := provider.Shutdown(); err != nil {
			// Log error but continue shutting down other providers
		}
	}
	return nil
}
