package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/iamgaru/gander/internal/config"
	"github.com/iamgaru/gander/internal/filter"
	"github.com/iamgaru/gander/internal/filter/providers"
	"github.com/iamgaru/gander/internal/logging"
	"github.com/iamgaru/gander/internal/proxy"
)

func main() {
	// Check command line arguments
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <config-file>\n", os.Args[0])
		os.Exit(1)
	}

	configFile := os.Args[1]

	// Load configuration
	loader := config.NewLoader()
	cfg, err := loader.Load(configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Parse log level from config
	logLevel := logging.LevelInfo
	switch cfg.Logging.LogLevel {
	case "error":
		logLevel = logging.LevelError
	case "warn":
		logLevel = logging.LevelWarn
	case "info":
		logLevel = logging.LevelInfo
	case "debug":
		logLevel = logging.LevelDebug
	}

	// Initialize logging system
	logConfig := logging.Config{
		LogFile:      cfg.Logging.LogFile,
		EnableDebug:  cfg.Logging.EnableDebug,
		LogLevel:     logLevel,
		ConsoleLevel: logging.LevelInfo, // Only show info and errors on console
	}

	if err := logging.InitGlobalLogger(logConfig); err != nil {
		log.Fatalf("Failed to initialize logging: %v", err)
	}
	defer func() {
		_ = logging.CloseGlobalLogger()
	}()

	// Initialize filter manager
	filterManager := filter.NewManager(cfg.Logging.EnableDebug)

	// Initialize and register built-in filter providers
	if err := initializeFilterProviders(filterManager, cfg); err != nil {
		logging.Error("Failed to initialize filter providers: %v", err)
		os.Exit(1)
	}

	// Create and start proxy server
	server, err := proxy.NewServer(cfg, filterManager)
	if err != nil {
		logging.Error("Failed to create proxy server: %v", err)
		os.Exit(1)
	}

	// Set up config file watcher
	configWatcher, err := config.NewConfigWatcher(configFile, loader)
	if err != nil {
		logging.Error("Failed to create config watcher: %v", err)
		os.Exit(1)
	}

	// Add callback for config changes
	configWatcher.AddCallback(func(_, newConfig *config.Config) error {
		logging.Info("Configuration reloading...")

		// Reload server configuration
		if err := server.ReloadConfig(newConfig); err != nil {
			return fmt.Errorf("failed to reload server config: %w", err)
		}

		// Reinitialize filter providers with new config
		if err := reinitializeFilterProviders(filterManager, newConfig); err != nil {
			return fmt.Errorf("failed to reinitialize filter providers: %w", err)
		}

		logging.Info("Configuration reloaded successfully")
		return nil
	})

	// Start config watcher
	if err := configWatcher.Start(cfg); err != nil {
		logging.Error("Failed to start config watcher: %v", err)
		os.Exit(1)
	}
	defer func() { _ = configWatcher.Stop() }()

	// Start the server
	if err := server.Start(); err != nil {
		logging.Error("Failed to start proxy server: %v", err)
		os.Exit(1)
	}

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start statistics reporting goroutine
	go reportStatistics(server)

	// Show startup info on console
	logging.Info("Gander started successfully on %s", cfg.Proxy.ListenAddr)

	// Log detailed configuration to file only
	logging.Debug("Configuration: Proxy=%s, Debug=%t, AutoCert=%t, UpstreamSniff=%t",
		cfg.Proxy.ListenAddr, cfg.Logging.EnableDebug, cfg.TLS.AutoGenerate, cfg.TLS.UpstreamCertSniff)

	// Wait for shutdown signal
	<-sigCh
	logging.Info("Shutting down...")

	// Graceful shutdown
	if err := server.Stop(); err != nil {
		logging.Error("Error during shutdown: %v", err)
	} else {
		logging.Info("Stopped")
	}
}

// initializeFilterProviders initializes and registers filter providers
func initializeFilterProviders(manager *filter.Manager, cfg *config.Config) error {
	// Initialize domain provider
	domainProvider := providers.NewDomainFilterProvider()

	// Configure domain provider with legacy rules (backward compatibility)
	domainConfig := map[string]interface{}{
		"inspect_domains": cfg.Rules.InspectDomains,
		"bypass_domains":  cfg.Rules.BypassDomains,
		"enable_debug":    cfg.Logging.EnableDebug,
	}

	if err := domainProvider.Initialize(domainConfig); err != nil {
		return fmt.Errorf("failed to initialize domain provider: %w", err)
	}

	if err := manager.RegisterProvider("domain", domainProvider); err != nil {
		return fmt.Errorf("failed to register domain provider: %w", err)
	}

	// Initialize IP provider
	ipProvider := providers.NewIPFilterProvider()

	// Configure IP provider with legacy rules (backward compatibility)
	ipConfig := map[string]interface{}{
		"inspect_ips":  cfg.Rules.InspectIPs,
		"bypass_ips":   cfg.Rules.BypassIPs,
		"enable_debug": cfg.Logging.EnableDebug,
	}

	if err := ipProvider.Initialize(ipConfig); err != nil {
		return fmt.Errorf("failed to initialize IP provider: %w", err)
	}

	if err := manager.RegisterProvider("ip", ipProvider); err != nil {
		return fmt.Errorf("failed to register IP provider: %w", err)
	}

	// Log filter system initialization to file
	providers := manager.GetProviders()
	totalPacketFilters := 0
	totalInspectionFilters := 0

	for name, provider := range providers {
		packetFilters := len(provider.GetPacketFilters())
		inspectionFilters := len(provider.GetInspectionFilters())
		totalPacketFilters += packetFilters
		totalInspectionFilters += inspectionFilters

		logging.Debug("Registered filter provider '%s': %d packet filters, %d inspection filters",
			name, packetFilters, inspectionFilters)
	}

	logging.Debug("Filter system initialized: %d providers, %d packet filters, %d inspection filters",
		len(providers), totalPacketFilters, totalInspectionFilters)

	// Log domain and IP filter details if debug is enabled
	if cfg.Logging.EnableDebug {
		logFilterDetails(cfg)
	}

	return nil
}

// logFilterDetails logs detailed filter configuration
func logFilterDetails(cfg *config.Config) {
	// Count domain types
	inspectDomains := len(cfg.Rules.InspectDomains)
	bypassDomains := len(cfg.Rules.BypassDomains)
	inspectWildcards := 0
	bypassWildcards := 0

	for _, domain := range cfg.Rules.InspectDomains {
		if len(domain) > 0 && domain[0] == '*' {
			inspectWildcards++
		}
	}

	for _, domain := range cfg.Rules.BypassDomains {
		if len(domain) > 0 && domain[0] == '*' {
			bypassWildcards++
		}
	}

	// Count IP types
	inspectIPs := len(cfg.Rules.InspectIPs)
	bypassIPs := len(cfg.Rules.BypassIPs)
	inspectCIDRs := 0
	bypassCIDRs := 0

	for _, ip := range cfg.Rules.InspectIPs {
		if containsCIDR(ip) {
			inspectCIDRs++
		}
	}

	for _, ip := range cfg.Rules.BypassIPs {
		if containsCIDR(ip) {
			bypassCIDRs++
		}
	}

	logging.Debug("Domain filter: %d inspect domains (%d wildcards), %d bypass domains (%d wildcards)",
		inspectDomains, inspectWildcards, bypassDomains, bypassWildcards)
	logging.Debug("IP filter: %d inspect IPs (%d CIDRs), %d bypass IPs (%d CIDRs)",
		inspectIPs, inspectCIDRs, bypassIPs, bypassCIDRs)
}

// containsCIDR checks if an IP string contains CIDR notation
func containsCIDR(ip string) bool {
	for _, char := range ip {
		if char == '/' {
			return true
		}
	}
	return false
}

// reinitializeFilterProviders reinitializes filter providers with new configuration
func reinitializeFilterProviders(manager *filter.Manager, cfg *config.Config) error {
	// Create provider configs from legacy rules
	providerConfigs := map[string]interface{}{
		"domain": map[string]interface{}{
			"inspect_domains": cfg.Rules.InspectDomains,
			"bypass_domains":  cfg.Rules.BypassDomains,
			"enable_debug":    cfg.Logging.EnableDebug,
		},
		"ip": map[string]interface{}{
			"inspect_ips":  cfg.Rules.InspectIPs,
			"bypass_ips":   cfg.Rules.BypassIPs,
			"enable_debug": cfg.Logging.EnableDebug,
		},
	}

	return manager.ReloadProviders(providerConfigs)
}

// reportStatistics periodically reports server statistics
func reportStatistics(server *proxy.Server) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := server.GetStats()

		if proxyStats, ok := stats["proxy"].(proxy.ProxyStatsSnapshot); ok {
			// Essential stats on console every 60s
			logging.Stats(true, "%d connections, %d active, %.1f MB transferred",
				proxyStats.TotalConnections,
				proxyStats.ActiveConnections,
				float64(proxyStats.BytesTransferred)/(1024*1024))

			// Detailed stats to file only
			logging.Stats(false, "Detailed: %d total, %d active, %d inspected, %d bytes",
				proxyStats.TotalConnections,
				proxyStats.ActiveConnections,
				proxyStats.InspectedConnections,
				proxyStats.BytesTransferred)
		}

		if captureStats, ok := stats["capture"]; ok {
			logging.Debug("Capture Statistics: %+v", captureStats)
		}

		if certStats, ok := stats["certs"]; ok {
			logging.Debug("Certificate Statistics: %+v", certStats)
		}
	}
}
