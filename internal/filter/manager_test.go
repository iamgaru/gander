package filter

import (
	"context"
	"net"
	"testing"
)

// Mock implementations for testing
type mockPacketFilter struct {
	name   string
	result FilterResult
	err    error
}

func (m *mockPacketFilter) Name() string {
	return m.name
}

func (m *mockPacketFilter) Priority() int {
	return 100
}

func (m *mockPacketFilter) ShouldFilter(_ context.Context, filterCtx *FilterContext) (FilterResult, error) {
	return m.result, m.err
}

type mockInspectionFilter struct {
	name   string
	result FilterResult
	err    error
}

func (m *mockInspectionFilter) Name() string {
	return m.name
}

func (m *mockInspectionFilter) Priority() int {
	return 100
}

func (m *mockInspectionFilter) ShouldFilter(_ context.Context, filterCtx *FilterContext) (FilterResult, error) {
	return m.result, m.err
}

func (m *mockInspectionFilter) InspectRequest(_ context.Context, filterCtx *FilterContext) (FilterResult, error) {
	return m.result, m.err
}

func (m *mockInspectionFilter) InspectResponse(ctx context.Context, filterCtx *FilterContext) (FilterResult, error) {
	return m.result, m.err
}

type mockFilterProvider struct {
	name              string
	packetFilters     []PacketFilter
	inspectionFilters []InspectionFilter
	shutdownCalled    bool
}

func (m *mockFilterProvider) Name() string {
	return m.name
}

func (m *mockFilterProvider) Initialize(_ map[string]interface{}) error {
	return nil
}

func (m *mockFilterProvider) GetPacketFilters() []PacketFilter {
	return m.packetFilters
}

func (m *mockFilterProvider) GetInspectionFilters() []InspectionFilter {
	return m.inspectionFilters
}

func (m *mockFilterProvider) Shutdown() error {
	m.shutdownCalled = true
	return nil
}

type mockFilterHook struct {
	name         string
	beforeCalled bool
	afterCalled  bool
	beforeError  error
	afterError   error
}

func (m *mockFilterHook) Name() string {
	return m.name
}

func (m *mockFilterHook) OnBeforeFilter(ctx context.Context, filterCtx *FilterContext) error {
	m.beforeCalled = true
	return m.beforeError
}

func (m *mockFilterHook) OnAfterFilter(ctx context.Context, filterCtx *FilterContext, result FilterResult) error {
	m.afterCalled = true
	return m.afterError
}

func TestNewManager(t *testing.T) {
	manager := NewManager(true)

	if manager == nil {
		t.Fatal("NewManager() returned nil")
	}
	if manager.enableDebug != true {
		t.Error("Debug flag not set correctly")
	}
	if manager.providers == nil {
		t.Error("Providers map not initialized")
	}
	if manager.registry == nil {
		t.Error("Registry not initialized")
	}
}

func TestRegisterProvider(t *testing.T) {
	manager := NewManager(false)

	packetFilter := &mockPacketFilter{name: "test-packet", result: FilterAllow}
	inspectionFilter := &mockInspectionFilter{name: "test-inspection", result: FilterAllow}

	provider := &mockFilterProvider{
		name:              "test-provider",
		packetFilters:     []PacketFilter{packetFilter},
		inspectionFilters: []InspectionFilter{inspectionFilter},
	}

	// Test successful registration
	err := manager.RegisterProvider("test-provider", provider)
	if err != nil {
		t.Fatalf("RegisterProvider() failed: %v", err)
	}

	// Test duplicate registration
	err = manager.RegisterProvider("test-provider", provider)
	if err == nil {
		t.Error("RegisterProvider() should fail for duplicate provider")
	}

	// Verify filters were added
	if len(manager.packetFilters) != 1 {
		t.Errorf("Expected 1 packet filter, got %d", len(manager.packetFilters))
	}
	if len(manager.inspectionFilters) != 1 {
		t.Errorf("Expected 1 inspection filter, got %d", len(manager.inspectionFilters))
	}

	// Verify provider is stored
	storedProvider, exists := manager.providers["test-provider"]
	if !exists {
		t.Error("Provider not stored in providers map")
	}
	if storedProvider != provider {
		t.Error("Stored provider doesn't match registered provider")
	}
}

func TestUnregisterProvider(t *testing.T) {
	manager := NewManager(false)

	provider := &mockFilterProvider{
		name:              "test-provider",
		packetFilters:     []PacketFilter{&mockPacketFilter{name: "test", result: FilterAllow}},
		inspectionFilters: []InspectionFilter{&mockInspectionFilter{name: "test", result: FilterAllow}},
	}

	// Register first
	err := manager.RegisterProvider("test-provider", provider)
	if err != nil {
		t.Fatalf("RegisterProvider() failed: %v", err)
	}

	// Test successful unregistration
	err = manager.UnregisterProvider("test-provider")
	if err != nil {
		t.Fatalf("UnregisterProvider() failed: %v", err)
	}

	// Verify provider shutdown was called
	if !provider.shutdownCalled {
		t.Error("Provider Shutdown() was not called")
	}

	// Verify provider removed
	_, exists := manager.providers["test-provider"]
	if exists {
		t.Error("Provider still exists after unregistration")
	}

	// Test unregistering non-existent provider
	err = manager.UnregisterProvider("non-existent")
	if err == nil {
		t.Error("UnregisterProvider() should fail for non-existent provider")
	}
}

func TestProcessPacket(t *testing.T) {
	tests := []struct {
		name           string
		filter         *mockPacketFilter
		expectedResult FilterResult
		expectedError  bool
	}{
		{
			name:           "Allow filter",
			filter:         &mockPacketFilter{name: "allow", result: FilterAllow},
			expectedResult: FilterAllow,
			expectedError:  false,
		},
		{
			name:           "Block filter",
			filter:         &mockPacketFilter{name: "block", result: FilterBlock},
			expectedResult: FilterBlock,
			expectedError:  false,
		},
		{
			name:           "Inspect filter",
			filter:         &mockPacketFilter{name: "inspect", result: FilterInspect},
			expectedResult: FilterInspect,
			expectedError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewManager(false)
			provider := &mockFilterProvider{
				name:          "test",
				packetFilters: []PacketFilter{tt.filter},
			}

			err := manager.RegisterProvider("test", provider)
			if err != nil {
				t.Fatalf("RegisterProvider() failed: %v", err)
			}

			ctx := context.Background()
			filterCtx := &FilterContext{
				ClientIP:   net.ParseIP("192.168.1.100"),
				ServerAddr: "example.com:443",
				Domain:     "example.com",
				Protocol:   "HTTPS",
			}

			decision, err := manager.ProcessPacket(ctx, filterCtx)

			if tt.expectedError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectedError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if decision.Result != tt.expectedResult {
				t.Errorf("Expected result %s, got %s", tt.expectedResult.String(), decision.Result.String())
			}
		})
	}
}

func TestProcessRequest(t *testing.T) {
	manager := NewManager(false)
	inspectionFilter := &mockInspectionFilter{name: "test-inspect", result: FilterInspect}
	provider := &mockFilterProvider{
		name:              "test",
		inspectionFilters: []InspectionFilter{inspectionFilter},
	}

	err := manager.RegisterProvider("test", provider)
	if err != nil {
		t.Fatalf("RegisterProvider() failed: %v", err)
	}

	ctx := context.Background()
	filterCtx := &FilterContext{
		ClientIP:    net.ParseIP("192.168.1.100"),
		Domain:      "example.com",
		IsRequest:   true,
		RequestData: []byte("GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"),
	}

	decision, err := manager.ProcessRequest(ctx, filterCtx)
	if err != nil {
		t.Fatalf("ProcessRequest() failed: %v", err)
	}

	if decision.Result != FilterInspect {
		t.Errorf("Expected FilterInspect, got %s", decision.Result.String())
	}
	if decision.FilterName != "test-inspect" {
		t.Errorf("Expected filter name 'test-inspect', got '%s'", decision.FilterName)
	}
}

func TestProcessResponse(t *testing.T) {
	manager := NewManager(false)
	inspectionFilter := &mockInspectionFilter{name: "test-inspect", result: FilterBlock}
	provider := &mockFilterProvider{
		name:              "test",
		inspectionFilters: []InspectionFilter{inspectionFilter},
	}

	err := manager.RegisterProvider("test", provider)
	if err != nil {
		t.Fatalf("RegisterProvider() failed: %v", err)
	}

	ctx := context.Background()
	filterCtx := &FilterContext{
		ClientIP:     net.ParseIP("192.168.1.100"),
		Domain:       "example.com",
		IsRequest:    false,
		ResponseData: []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"),
	}

	decision, err := manager.ProcessResponse(ctx, filterCtx)
	if err != nil {
		t.Fatalf("ProcessResponse() failed: %v", err)
	}

	if decision.Result != FilterBlock {
		t.Errorf("Expected FilterBlock, got %s", decision.Result.String())
	}
}

func TestAddHook(t *testing.T) {
	manager := NewManager(false)
	hook := &mockFilterHook{name: "test-hook"}

	manager.AddHook(hook)

	if len(manager.hooks) != 1 {
		t.Errorf("Expected 1 hook, got %d", len(manager.hooks))
	}
	if manager.hooks[0] != hook {
		t.Error("Hook not added correctly")
	}
}

func TestHookExecution(t *testing.T) {
	manager := NewManager(false)
	hook := &mockFilterHook{name: "test-hook"}
	manager.AddHook(hook)

	// Add a simple filter that allows everything
	filter := &mockPacketFilter{name: "allow", result: FilterAllow}
	provider := &mockFilterProvider{
		name:          "test",
		packetFilters: []PacketFilter{filter},
	}
	_ = manager.RegisterProvider("test", provider)

	ctx := context.Background()
	filterCtx := &FilterContext{
		ClientIP: net.ParseIP("192.168.1.100"),
		Domain:   "example.com",
	}

	_, err := manager.ProcessPacket(ctx, filterCtx)
	if err != nil {
		t.Fatalf("ProcessPacket() failed: %v", err)
	}

	if !hook.beforeCalled {
		t.Error("OnBeforeFilter was not called")
	}
	if !hook.afterCalled {
		t.Error("OnAfterFilter was not called")
	}
}

func TestGetProviders(t *testing.T) {
	manager := NewManager(false)
	provider1 := &mockFilterProvider{name: "provider1"}
	provider2 := &mockFilterProvider{name: "provider2"}

	_ = manager.RegisterProvider("provider1", provider1)
	_ = manager.RegisterProvider("provider2", provider2)

	providers := manager.GetProviders()
	if len(providers) != 2 {
		t.Errorf("Expected 2 providers, got %d", len(providers))
	}

	if providers["provider1"] != provider1 {
		t.Error("Provider1 not returned correctly")
	}
	if providers["provider2"] != provider2 {
		t.Error("Provider2 not returned correctly")
	}
}

func TestGetStats(t *testing.T) {
	manager := NewManager(false)

	stats := manager.GetStats()
	if stats == nil {
		t.Error("GetStats() returned nil")
	}

	// Stats should be a map with string keys
	if _, ok := stats["providers"]; !ok {
		t.Error("Stats should include providers count")
	}
}

func TestShutdown(t *testing.T) {
	manager := NewManager(false)
	provider1 := &mockFilterProvider{name: "provider1"}
	provider2 := &mockFilterProvider{name: "provider2"}

	_ = manager.RegisterProvider("provider1", provider1)
	_ = manager.RegisterProvider("provider2", provider2)

	err := manager.Shutdown()
	if err != nil {
		t.Fatalf("Shutdown() failed: %v", err)
	}

	if !provider1.shutdownCalled {
		t.Error("Provider1 Shutdown() was not called")
	}
	if !provider2.shutdownCalled {
		t.Error("Provider2 Shutdown() was not called")
	}
}

// Priority filter mocks
type highPriorityFilter struct {
	*mockPacketFilter
}

func (h *highPriorityFilter) Priority() int {
	return 200
}

type lowPriorityFilter struct {
	*mockPacketFilter
}

func (l *lowPriorityFilter) Priority() int {
	return 50
}

func TestFilterPriority(t *testing.T) {
	manager := NewManager(false)

	// Create filters with different priorities
	highFilter := &highPriorityFilter{&mockPacketFilter{name: "high", result: FilterBlock}}
	lowFilter := &lowPriorityFilter{&mockPacketFilter{name: "low", result: FilterAllow}}

	provider := &mockFilterProvider{
		name:          "test",
		packetFilters: []PacketFilter{lowFilter, highFilter}, // Add in reverse order
	}

	_ = manager.RegisterProvider("test", provider)

	ctx := context.Background()
	filterCtx := &FilterContext{
		ClientIP: net.ParseIP("192.168.1.100"),
		Domain:   "example.com",
	}

	decision, err := manager.ProcessPacket(ctx, filterCtx)
	if err != nil {
		t.Fatalf("ProcessPacket() failed: %v", err)
	}

	// High priority filter should execute first and block
	if decision.Result != FilterBlock {
		t.Errorf("Expected FilterBlock from high priority filter, got %s", decision.Result.String())
	}
	if decision.FilterName != "high" {
		t.Errorf("Expected filter name 'high', got '%s'", decision.FilterName)
	}
}

// Benchmark tests for performance validation
func BenchmarkProcessPacket(b *testing.B) {
	manager := NewManager(false)
	filter := &mockPacketFilter{name: "bench", result: FilterAllow}
	provider := &mockFilterProvider{
		name:          "bench",
		packetFilters: []PacketFilter{filter},
	}
	_ = manager.RegisterProvider("bench", provider)

	ctx := context.Background()
	filterCtx := &FilterContext{
		ClientIP: net.ParseIP("192.168.1.100"),
		Domain:   "example.com",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = manager.ProcessPacket(ctx, filterCtx)
	}
}

func BenchmarkRegisterProvider(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		manager := NewManager(false)
		provider := &mockFilterProvider{name: "bench"}
		_ = manager.RegisterProvider("bench", provider)
	}
}
