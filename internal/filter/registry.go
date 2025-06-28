package filter

import (
	"fmt"
	"sync"
)

// Registry implements FilterRegistry interface
type Registry struct {
	providers map[string]FilterProvider
	mu        sync.RWMutex
}

// NewRegistry creates a new filter registry
func NewRegistry() *Registry {
	return &Registry{
		providers: make(map[string]FilterProvider),
	}
}

// RegisterProvider registers a new filter provider
func (r *Registry) RegisterProvider(name string, provider FilterProvider) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.providers[name]; exists {
		return fmt.Errorf("provider %s already registered", name)
	}

	r.providers[name] = provider
	return nil
}

// UnregisterProvider unregisters a filter provider
func (r *Registry) UnregisterProvider(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.providers[name]; !exists {
		return fmt.Errorf("provider %s not found", name)
	}

	delete(r.providers, name)
	return nil
}

// GetProvider retrieves a filter provider by name
func (r *Registry) GetProvider(name string) (FilterProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	provider, exists := r.providers[name]
	return provider, exists
}

// GetProviders returns all registered providers
func (r *Registry) GetProviders() map[string]FilterProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make(map[string]FilterProvider)
	for name, provider := range r.providers {
		result[name] = provider
	}
	return result
}
