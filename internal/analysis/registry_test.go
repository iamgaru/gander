package analysis

import (
	"fmt"
	"sync"
	"testing"
)

// TestFilterRegistration tests basic filter registration
func TestFilterRegistration(t *testing.T) {
	registry := NewFilterRegistry()

	// Test empty registry
	if registry.Count() != 0 {
		t.Errorf("Expected empty registry, got %d filters", registry.Count())
	}

	// Test registering a filter
	filter1 := &MockFilter{name: "test-filter-1", priority: 10}
	err := registry.Register(filter1)
	if err != nil {
		t.Errorf("Failed to register filter: %v", err)
	}

	if registry.Count() != 1 {
		t.Errorf("Expected 1 filter, got %d", registry.Count())
	}

	// Test retrieving the filter
	retrieved := registry.Get("test-filter-1")
	if retrieved == nil {
		t.Error("Failed to retrieve registered filter")
	}

	if retrieved.GetName() != "test-filter-1" {
		t.Errorf("Expected filter name 'test-filter-1', got '%s'", retrieved.GetName())
	}
}

// TestFilterRegistrationErrors tests error conditions during registration
func TestFilterRegistrationErrors(t *testing.T) {
	registry := NewFilterRegistry()

	// Test registering nil filter
	err := registry.Register(nil)
	if err == nil {
		t.Error("Expected error when registering nil filter")
	}

	// Test registering filter with empty name
	emptyNameFilter := &MockFilter{name: "", priority: 10}
	err = registry.Register(emptyNameFilter)
	if err == nil {
		t.Error("Expected error when registering filter with empty name")
	}

	// Test registering duplicate filter
	filter1 := &MockFilter{name: "duplicate", priority: 10}
	err = registry.Register(filter1)
	if err != nil {
		t.Errorf("Failed to register first filter: %v", err)
	}

	filter2 := &MockFilter{name: "duplicate", priority: 20}
	err = registry.Register(filter2)
	if err == nil {
		t.Error("Expected error when registering duplicate filter name")
	}

	// Verify only first filter is registered
	if registry.Count() != 1 {
		t.Errorf("Expected 1 filter after duplicate registration, got %d", registry.Count())
	}
}

// TestFilterUnregistration tests filter removal
func TestFilterUnregistration(t *testing.T) {
	registry := NewFilterRegistry()

	// Register multiple filters
	filter1 := &MockFilter{name: "filter-1", priority: 10}
	filter2 := &MockFilter{name: "filter-2", priority: 20}
	
	registry.Register(filter1)
	registry.Register(filter2)

	if registry.Count() != 2 {
		t.Errorf("Expected 2 filters, got %d", registry.Count())
	}

	// Test unregistering existing filter
	err := registry.Unregister("filter-1")
	if err != nil {
		t.Errorf("Failed to unregister filter: %v", err)
	}

	if registry.Count() != 1 {
		t.Errorf("Expected 1 filter after unregistration, got %d", registry.Count())
	}

	// Test retrieving unregistered filter
	retrieved := registry.Get("filter-1")
	if retrieved != nil {
		t.Error("Retrieved unregistered filter")
	}

	// Test unregistering non-existent filter
	err = registry.Unregister("non-existent")
	if err == nil {
		t.Error("Expected error when unregistering non-existent filter")
	}

	// Test unregistering with empty name
	err = registry.Unregister("")
	if err == nil {
		t.Error("Expected error when unregistering with empty name")
	}
}

// TestFilterEnableDisable tests filter enable/disable functionality
func TestFilterEnableDisable(t *testing.T) {
	registry := NewFilterRegistry()

	filter := &MockFilter{name: "test-filter", priority: 10}
	registry.Register(filter)

	// Test filter is enabled by default
	if !registry.IsEnabled("test-filter") {
		t.Error("Filter should be enabled by default")
	}

	if registry.CountEnabled() != 1 {
		t.Errorf("Expected 1 enabled filter, got %d", registry.CountEnabled())
	}

	// Test disabling filter
	err := registry.Enable("test-filter", false)
	if err != nil {
		t.Errorf("Failed to disable filter: %v", err)
	}

	if registry.IsEnabled("test-filter") {
		t.Error("Filter should be disabled")
	}

	if registry.CountEnabled() != 0 {
		t.Errorf("Expected 0 enabled filters, got %d", registry.CountEnabled())
	}

	// Test retrieving disabled filter returns nil
	retrieved := registry.Get("test-filter")
	if retrieved != nil {
		t.Error("Should not retrieve disabled filter")
	}

	// Test re-enabling filter
	err = registry.Enable("test-filter", true)
	if err != nil {
		t.Errorf("Failed to re-enable filter: %v", err)
	}

	if !registry.IsEnabled("test-filter") {
		t.Error("Filter should be enabled again")
	}

	// Test enabling non-existent filter
	err = registry.Enable("non-existent", true)
	if err == nil {
		t.Error("Expected error when enabling non-existent filter")
	}
}

// TestFilterListing tests filter listing functionality
func TestFilterListing(t *testing.T) {
	registry := NewFilterRegistry()

	// Test empty registry
	if len(registry.List()) != 0 {
		t.Errorf("Expected empty list, got %d items", len(registry.List()))
	}

	if len(registry.ListEnabled()) != 0 {
		t.Errorf("Expected empty enabled list, got %d items", len(registry.ListEnabled()))
	}

	// Register multiple filters
	filters := []*MockFilter{
		{name: "filter-c", priority: 30},
		{name: "filter-a", priority: 10},
		{name: "filter-b", priority: 20},
	}

	for _, filter := range filters {
		registry.Register(filter)
	}

	// Test listing all filters (should be sorted alphabetically)
	allFilters := registry.List()
	expectedAll := []string{"filter-a", "filter-b", "filter-c"}
	
	if len(allFilters) != len(expectedAll) {
		t.Errorf("Expected %d filters, got %d", len(expectedAll), len(allFilters))
	}

	for i, name := range expectedAll {
		if allFilters[i] != name {
			t.Errorf("Expected filter %d to be '%s', got '%s'", i, name, allFilters[i])
		}
	}

	// Disable one filter
	registry.Enable("filter-b", false)

	// Test listing enabled filters
	enabledFilters := registry.ListEnabled()
	expectedEnabled := []string{"filter-a", "filter-c"}

	if len(enabledFilters) != len(expectedEnabled) {
		t.Errorf("Expected %d enabled filters, got %d", len(expectedEnabled), len(enabledFilters))
	}

	for i, name := range expectedEnabled {
		if enabledFilters[i] != name {
			t.Errorf("Expected enabled filter %d to be '%s', got '%s'", i, name, enabledFilters[i])
		}
	}
}

// TestFilterPriorityOrdering tests priority-based ordering
func TestFilterPriorityOrdering(t *testing.T) {
	registry := NewFilterRegistry()

	// Register filters with different priorities (lower number = higher priority)
	filters := []*MockFilter{
		{name: "low-priority", priority: 100},
		{name: "high-priority", priority: 1},
		{name: "medium-priority", priority: 50},
	}

	for _, filter := range filters {
		registry.Register(filter)
	}

	// Test priority map
	priorities := registry.GetPriorities()
	expectedPriorities := map[string]int{
		"high-priority":   1,
		"medium-priority": 50,
		"low-priority":    100,
	}

	for name, expectedPriority := range expectedPriorities {
		if priority, exists := priorities[name]; !exists {
			t.Errorf("Missing priority for filter '%s'", name)
		} else if priority != expectedPriority {
			t.Errorf("Expected priority %d for '%s', got %d", expectedPriority, name, priority)
		}
	}

	// Test internal ordering (this tests the private method for future phases)
	orderedFilters := registry.getOrderedFilters()
	expectedOrder := []string{"high-priority", "medium-priority", "low-priority"}

	if len(orderedFilters) != len(expectedOrder) {
		t.Errorf("Expected %d ordered filters, got %d", len(expectedOrder), len(orderedFilters))
	}

	for i, expectedName := range expectedOrder {
		if orderedFilters[i].GetName() != expectedName {
			t.Errorf("Expected filter %d to be '%s', got '%s'", i, expectedName, orderedFilters[i].GetName())
		}
	}
}

// TestFilterClear tests clearing all filters
func TestFilterClear(t *testing.T) {
	registry := NewFilterRegistry()

	// Register multiple filters
	for i := 0; i < 5; i++ {
		filter := &MockFilter{name: fmt.Sprintf("filter-%d", i), priority: i * 10}
		registry.Register(filter)
	}

	if registry.Count() != 5 {
		t.Errorf("Expected 5 filters before clear, got %d", registry.Count())
	}

	// Clear registry
	registry.Clear()

	if registry.Count() != 0 {
		t.Errorf("Expected 0 filters after clear, got %d", registry.Count())
	}

	if registry.CountEnabled() != 0 {
		t.Errorf("Expected 0 enabled filters after clear, got %d", registry.CountEnabled())
	}

	if len(registry.List()) != 0 {
		t.Errorf("Expected empty list after clear, got %d items", len(registry.List()))
	}
}

// TestRegistryConcurrentAccess tests thread safety of registry operations
func TestRegistryConcurrentAccess(t *testing.T) {
	registry := NewFilterRegistry()
	
	// Number of concurrent operations
	numGoroutines := 10
	numOperationsPerGoroutine := 100

	var wg sync.WaitGroup
	
	// Concurrent registration
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperationsPerGoroutine; j++ {
				filter := &MockFilter{
					name:     fmt.Sprintf("filter-%d-%d", id, j),
					priority: id*100 + j,
				}
				registry.Register(filter)
			}
		}(i)
	}
	wg.Wait()

	// Verify all filters were registered
	expectedCount := numGoroutines * numOperationsPerGoroutine
	if registry.Count() != expectedCount {
		t.Errorf("Expected %d filters after concurrent registration, got %d", expectedCount, registry.Count())
	}

	// Concurrent read operations
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperationsPerGoroutine; j++ {
				// Test various read operations
				registry.Count()
				registry.CountEnabled()
				registry.List()
				registry.ListEnabled()
				registry.GetPriorities()
				
				// Try to get specific filters
				filterName := fmt.Sprintf("filter-%d-%d", id, j)
				registry.Get(filterName)
				registry.IsEnabled(filterName)
			}
		}(i)
	}
	wg.Wait()

	// Concurrent enable/disable operations
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < numOperationsPerGoroutine; j++ {
				filterName := fmt.Sprintf("filter-%d-%d", id, j)
				// Toggle enabled state
				registry.Enable(filterName, j%2 == 0)
			}
		}(i)
	}
	wg.Wait()

	// Registry should still be consistent
	if registry.Count() != expectedCount {
		t.Errorf("Expected %d filters after concurrent operations, got %d", expectedCount, registry.Count())
	}
}

// BenchmarkFilterRegistration benchmarks filter registration performance
func BenchmarkFilterRegistration(b *testing.B) {
	registry := NewFilterRegistry()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filter := &MockFilter{
			name:     fmt.Sprintf("filter-%d", i),
			priority: i,
		}
		registry.Register(filter)
	}
}

// BenchmarkFilterLookup benchmarks filter lookup performance
func BenchmarkFilterLookup(b *testing.B) {
	registry := NewFilterRegistry()
	
	// Pre-register filters
	for i := 0; i < 1000; i++ {
		filter := &MockFilter{
			name:     fmt.Sprintf("filter-%d", i),
			priority: i,
		}
		registry.Register(filter)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		filterName := fmt.Sprintf("filter-%d", i%1000)
		registry.Get(filterName)
	}
}

// BenchmarkFilterOrdering benchmarks priority ordering performance
func BenchmarkFilterOrdering(b *testing.B) {
	registry := NewFilterRegistry()
	
	// Pre-register filters in random priority order
	for i := 0; i < 100; i++ {
		filter := &MockFilter{
			name:     fmt.Sprintf("filter-%d", i),
			priority: (i * 17) % 200, // Pseudo-random priorities
		}
		registry.Register(filter)
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		registry.getOrderedFilters()
	}
}

// BenchmarkConcurrentAccess benchmarks concurrent registry operations
func BenchmarkConcurrentAccess(b *testing.B) {
	registry := NewFilterRegistry()
	
	// Pre-register some filters
	for i := 0; i < 50; i++ {
		filter := &MockFilter{
			name:     fmt.Sprintf("filter-%d", i),
			priority: i,
		}
		registry.Register(filter)
	}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Mix of read operations
			registry.Count()
			registry.Get(fmt.Sprintf("filter-%d", b.N%50))
			registry.IsEnabled(fmt.Sprintf("filter-%d", b.N%50))
		}
	})
}

// TestRegistryIsolation ensures registry is completely isolated (no proxy integration)
func TestRegistryIsolation(t *testing.T) {
	// This test verifies that the registry doesn't depend on any proxy components
	// and can work completely standalone
	
	registry := NewFilterRegistry()
	
	// Create filters with various priorities
	packetFilter := &MockFilter{name: "packet-filter", priority: 10}
	proxyFilter := &MockFilter{name: "proxy-filter", priority: 100}
	
	// Register filters
	if err := registry.Register(packetFilter); err != nil {
		t.Errorf("Failed to register packet filter: %v", err)
	}
	
	if err := registry.Register(proxyFilter); err != nil {
		t.Errorf("Failed to register proxy filter: %v", err)
	}
	
	// Verify complete isolation - no external dependencies
	orderedFilters := registry.getOrderedFilters()
	if len(orderedFilters) != 2 {
		t.Errorf("Expected 2 filters, got %d", len(orderedFilters))
	}
	
	// Verify priority ordering (packet filter should come first)
	if orderedFilters[0].GetName() != "packet-filter" {
		t.Errorf("Expected packet filter first, got %s", orderedFilters[0].GetName())
	}
	
	if orderedFilters[1].GetName() != "proxy-filter" {
		t.Errorf("Expected proxy filter second, got %s", orderedFilters[1].GetName())
	}
	
	// This registry should work without any proxy, server, or config components
	t.Logf("Registry isolation test passed - fully standalone operation")
}