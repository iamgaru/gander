package analysis

import (
	"fmt"
	"sort"
	"sync"
)

// FilterRegistry manages a collection of traffic analysis filters
// Phase 2.2.A: Registration only - NO EXECUTION, NO METRICS
type FilterRegistry struct {
	// Thread-safe access to filter list
	mu sync.RWMutex
	
	// Registered filters stored by name for fast lookup
	filters map[string]TrafficFilter
	
	// Enabled state for each filter (allows disabling without unregistering)
	enabled map[string]bool
	
	// Ordered list of filters for execution (cached for performance)
	orderedFilters []TrafficFilter
	
	// Flag to track if ordered list needs refresh
	needsReorder bool
}

// NewFilterRegistry creates a new empty filter registry
func NewFilterRegistry() *FilterRegistry {
	return &FilterRegistry{
		filters:        make(map[string]TrafficFilter),
		enabled:        make(map[string]bool),
		orderedFilters: make([]TrafficFilter, 0),
		needsReorder:   false,
	}
}

// Register adds a new filter to the registry
// Returns error if filter name already exists or filter is invalid
func (r *FilterRegistry) Register(filter TrafficFilter) error {
	if filter == nil {
		return fmt.Errorf("cannot register nil filter")
	}
	
	name := filter.GetName()
	if name == "" {
		return fmt.Errorf("filter name cannot be empty")
	}
	
	r.mu.Lock()
	defer r.mu.Unlock()
	
	// Check if filter already registered
	if _, exists := r.filters[name]; exists {
		return fmt.Errorf("filter '%s' already registered", name)
	}
	
	// Add filter
	r.filters[name] = filter
	r.enabled[name] = true // Enabled by default
	r.needsReorder = true
	
	return nil
}

// Unregister removes a filter from the registry
// Returns error if filter doesn't exist
func (r *FilterRegistry) Unregister(name string) error {
	if name == "" {
		return fmt.Errorf("filter name cannot be empty")
	}
	
	r.mu.Lock()
	defer r.mu.Unlock()
	
	// Check if filter exists
	if _, exists := r.filters[name]; !exists {
		return fmt.Errorf("filter '%s' not found", name)
	}
	
	// Remove filter
	delete(r.filters, name)
	delete(r.enabled, name)
	r.needsReorder = true
	
	return nil
}

// Enable enables or disables a registered filter
// Returns error if filter doesn't exist
func (r *FilterRegistry) Enable(name string, enabled bool) error {
	if name == "" {
		return fmt.Errorf("filter name cannot be empty")
	}
	
	r.mu.Lock()
	defer r.mu.Unlock()
	
	// Check if filter exists
	if _, exists := r.filters[name]; !exists {
		return fmt.Errorf("filter '%s' not found", name)
	}
	
	// Update enabled state
	if r.enabled[name] != enabled {
		r.enabled[name] = enabled
		r.needsReorder = true
	}
	
	return nil
}

// IsEnabled returns whether a filter is enabled
// Returns false if filter doesn't exist
func (r *FilterRegistry) IsEnabled(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	enabled, exists := r.enabled[name]
	return exists && enabled
}

// Get returns a filter by name
// Returns nil if filter doesn't exist or is disabled
func (r *FilterRegistry) Get(name string) TrafficFilter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	filter, exists := r.filters[name]
	if !exists || !r.enabled[name] {
		return nil
	}
	
	return filter
}

// List returns all registered filter names
func (r *FilterRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	names := make([]string, 0, len(r.filters))
	for name := range r.filters {
		names = append(names, name)
	}
	
	// Sort for consistent ordering
	sort.Strings(names)
	return names
}

// ListEnabled returns all enabled filter names
func (r *FilterRegistry) ListEnabled() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	names := make([]string, 0, len(r.filters))
	for name, enabled := range r.enabled {
		if enabled {
			names = append(names, name)
		}
	}
	
	// Sort for consistent ordering
	sort.Strings(names)
	return names
}

// Count returns the total number of registered filters
func (r *FilterRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	return len(r.filters)
}

// CountEnabled returns the number of enabled filters
func (r *FilterRegistry) CountEnabled() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	count := 0
	for _, enabled := range r.enabled {
		if enabled {
			count++
		}
	}
	
	return count
}

// Clear removes all filters from the registry
func (r *FilterRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	r.filters = make(map[string]TrafficFilter)
	r.enabled = make(map[string]bool)
	r.orderedFilters = make([]TrafficFilter, 0)
	r.needsReorder = false
}

// getOrderedFilters returns filters sorted by priority (lower number = higher priority)
// This is a private method for future execution phases
// Phase 2.2.A: Only used internally for testing, no execution yet
func (r *FilterRegistry) getOrderedFilters() []TrafficFilter {
	r.mu.RLock()
	needsReorder := r.needsReorder
	if !needsReorder && len(r.orderedFilters) > 0 {
		defer r.mu.RUnlock()
		return r.orderedFilters // Return cached version
	}
	r.mu.RUnlock()
	
	// Need to rebuild ordered list
	r.mu.Lock()
	defer r.mu.Unlock()
	
	// Double-check after acquiring write lock
	if !r.needsReorder && len(r.orderedFilters) > 0 {
		return r.orderedFilters
	}
	
	// Collect enabled filters
	enabledFilters := make([]TrafficFilter, 0, len(r.filters))
	for name, filter := range r.filters {
		if r.enabled[name] {
			enabledFilters = append(enabledFilters, filter)
		}
	}
	
	// Sort by priority (lower number = higher priority)
	sort.Slice(enabledFilters, func(i, j int) bool {
		return enabledFilters[i].GetPriority() < enabledFilters[j].GetPriority()
	})
	
	// Cache the result
	r.orderedFilters = enabledFilters
	r.needsReorder = false
	
	return r.orderedFilters
}

// GetPriorities returns a map of filter names to their priorities (for debugging)
func (r *FilterRegistry) GetPriorities() map[string]int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	priorities := make(map[string]int)
	for name, filter := range r.filters {
		priorities[name] = filter.GetPriority()
	}
	
	return priorities
}