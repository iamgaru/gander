package filter

import (
	"context"
	"fmt"
	"log"
	"sort"
	"sync"
)

// Manager orchestrates all filter providers and manages the filtering pipeline
type Manager struct {
	packetFilters     []PacketFilter
	inspectionFilters []InspectionFilter
	providers         map[string]FilterProvider
	hooks             []FilterHook
	registry          FilterRegistry
	mu                sync.RWMutex

	// Configuration
	enableDebug bool
}

// NewManager creates a new filter manager
func NewManager(enableDebug bool) *Manager {
	return &Manager{
		providers:   make(map[string]FilterProvider),
		enableDebug: enableDebug,
		registry:    NewRegistry(),
	}
}

// RegisterProvider registers a new filter provider
func (m *Manager) RegisterProvider(name string, provider FilterProvider) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.providers[name]; exists {
		return fmt.Errorf("provider %s already registered", name)
	}

	m.providers[name] = provider

	// Collect filters from provider
	packetFilters := provider.GetPacketFilters()
	inspectionFilters := provider.GetInspectionFilters()

	m.packetFilters = append(m.packetFilters, packetFilters...)
	m.inspectionFilters = append(m.inspectionFilters, inspectionFilters...)

	// Sort by priority (higher priority first)
	m.sortFilters()

	if m.enableDebug {
		log.Printf("Registered filter provider '%s' with %d packet filters and %d inspection filters",
			name, len(packetFilters), len(inspectionFilters))
	}

	return nil
}

// UnregisterProvider unregisters a filter provider
func (m *Manager) UnregisterProvider(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	provider, exists := m.providers[name]
	if !exists {
		return fmt.Errorf("provider %s not found", name)
	}

	// Shutdown the provider
	if err := provider.Shutdown(); err != nil {
		log.Printf("Error shutting down provider %s: %v", name, err)
	}

	// Remove provider
	delete(m.providers, name)

	// Rebuild filter lists
	m.rebuildFilterLists()

	if m.enableDebug {
		log.Printf("Unregistered filter provider '%s'", name)
	}

	return nil
}

// ProcessPacket processes a packet through all packet filters
func (m *Manager) ProcessPacket(ctx context.Context, filterCtx *FilterContext) (*FilterDecision, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Execute hooks before filtering
	for _, hook := range m.hooks {
		if err := hook.OnBeforeFilter(ctx, filterCtx); err != nil {
			return nil, fmt.Errorf("hook %s failed: %w", hook.Name(), err)
		}
	}

	decision := &FilterDecision{
		Result:    FilterAllow,
		Reason:    "no filters matched",
		Metadata:  make(map[string]interface{}),
		ShouldLog: false,
	}

	// Apply packet filters in priority order
	for _, filter := range m.packetFilters {
		result, err := filter.ShouldFilter(ctx, filterCtx)
		if err != nil {
			log.Printf("Filter %s error: %v", filter.Name(), err)
			continue
		}

		if result != FilterAllow {
			decision.Result = result
			decision.FilterName = filter.Name()
			decision.Reason = fmt.Sprintf("matched by %s", filter.Name())
			decision.ShouldLog = true

			if m.enableDebug {
				log.Printf("Packet filter '%s' returned %s for %s -> %s",
					filter.Name(), result.String(), filterCtx.ClientIP, filterCtx.Domain)
			}

			break
		}
	}

	// Execute hooks after filtering
	for _, hook := range m.hooks {
		if err := hook.OnAfterFilter(ctx, filterCtx, decision.Result); err != nil {
			log.Printf("Hook %s after-filter error: %v", hook.Name(), err)
		}
	}

	return decision, nil
}

// ProcessRequest processes an HTTP request through all inspection filters
func (m *Manager) ProcessRequest(ctx context.Context, filterCtx *FilterContext) (*FilterDecision, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	decision := &FilterDecision{
		Result:    FilterAllow,
		Reason:    "no inspection filters matched",
		Metadata:  make(map[string]interface{}),
		ShouldLog: false,
	}

	// Apply inspection filters in priority order
	for _, filter := range m.inspectionFilters {
		result, err := filter.InspectRequest(ctx, filterCtx)
		if err != nil {
			log.Printf("Inspection filter %s error: %v", filter.Name(), err)
			continue
		}

		if result != FilterAllow {
			decision.Result = result
			decision.FilterName = filter.Name()
			decision.Reason = fmt.Sprintf("request matched by %s", filter.Name())
			decision.ShouldLog = true

			if m.enableDebug {
				log.Printf("Request inspection filter '%s' returned %s for %s -> %s",
					filter.Name(), result.String(), filterCtx.ClientIP, filterCtx.Domain)
			}

			break
		}
	}

	return decision, nil
}

// ProcessResponse processes an HTTP response through all inspection filters
func (m *Manager) ProcessResponse(ctx context.Context, filterCtx *FilterContext) (*FilterDecision, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	decision := &FilterDecision{
		Result:    FilterAllow,
		Reason:    "no inspection filters matched",
		Metadata:  make(map[string]interface{}),
		ShouldLog: false,
	}

	// Apply inspection filters in priority order
	for _, filter := range m.inspectionFilters {
		result, err := filter.InspectResponse(ctx, filterCtx)
		if err != nil {
			log.Printf("Inspection filter %s error: %v", filter.Name(), err)
			continue
		}

		if result != FilterAllow {
			decision.Result = result
			decision.FilterName = filter.Name()
			decision.Reason = fmt.Sprintf("response matched by %s", filter.Name())
			decision.ShouldLog = true

			if m.enableDebug {
				log.Printf("Response inspection filter '%s' returned %s for %s -> %s",
					filter.Name(), result.String(), filterCtx.ClientIP, filterCtx.Domain)
			}

			break
		}
	}

	return decision, nil
}

// AddHook adds a filter hook
func (m *Manager) AddHook(hook FilterHook) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hooks = append(m.hooks, hook)
}

// GetProviders returns all registered providers
func (m *Manager) GetProviders() map[string]FilterProvider {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]FilterProvider)
	for name, provider := range m.providers {
		result[name] = provider
	}
	return result
}

// GetStats returns filtering statistics
func (m *Manager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"providers":          len(m.providers),
		"packet_filters":     len(m.packetFilters),
		"inspection_filters": len(m.inspectionFilters),
		"hooks":              len(m.hooks),
	}
}

// Shutdown gracefully shuts down all providers
func (m *Manager) Shutdown() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	var errors []error
	for name, provider := range m.providers {
		if err := provider.Shutdown(); err != nil {
			errors = append(errors, fmt.Errorf("provider %s shutdown error: %w", name, err))
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("shutdown errors: %v", errors)
	}

	return nil
}

// ReloadProviders reloads filter providers with new configuration
func (m *Manager) ReloadProviders(providerConfigs map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Reload existing providers
	for name, provider := range m.providers {
		if config, exists := providerConfigs[name]; exists {
			if err := provider.Initialize(config.(map[string]interface{})); err != nil {
				return fmt.Errorf("failed to reload provider %s: %w", name, err)
			}
			if m.enableDebug {
				log.Printf("Reloaded filter provider '%s'", name)
			}
		}
	}

	// Rebuild filter lists after reload
	m.rebuildFilterLists()

	return nil
}

// sortFilters sorts filters by priority (higher priority first)
func (m *Manager) sortFilters() {
	sort.Slice(m.packetFilters, func(i, j int) bool {
		return m.packetFilters[i].Priority() > m.packetFilters[j].Priority()
	})
	sort.Slice(m.inspectionFilters, func(i, j int) bool {
		return m.inspectionFilters[i].Priority() > m.inspectionFilters[j].Priority()
	})
}

// rebuildFilterLists rebuilds the filter lists from all providers
func (m *Manager) rebuildFilterLists() {
	m.packetFilters = nil
	m.inspectionFilters = nil

	for _, provider := range m.providers {
		m.packetFilters = append(m.packetFilters, provider.GetPacketFilters()...)
		m.inspectionFilters = append(m.inspectionFilters, provider.GetInspectionFilters()...)
	}

	m.sortFilters()
}
