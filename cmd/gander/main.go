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

	// Initialize filter manager
	filterManager := filter.NewManager(cfg.Logging.EnableDebug)

	// Initialize and register built-in filter providers
	if err := initializeFilterProviders(filterManager, cfg); err != nil {
		log.Fatalf("Failed to initialize filter providers: %v", err)
	}

	// Create and start proxy server
	server, err := proxy.NewServer(cfg, filterManager)
	if err != nil {
		log.Fatalf("Failed to create proxy server: %v", err)
	}

	// Start the server
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start proxy server: %v", err)
	}

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start statistics reporting goroutine
	go reportStatistics(server)

	log.Println("Gander proxy server started successfully")
	log.Printf("Configuration: Proxy=%s, Debug=%t, AutoCert=%t, UpstreamSniff=%t",
		cfg.Proxy.ListenAddr, cfg.Logging.EnableDebug, cfg.TLS.AutoGenerate, cfg.TLS.UpstreamCertSniff)

	// Wait for shutdown signal
	<-sigCh
	log.Println("Received shutdown signal, stopping server...")

	// Graceful shutdown
	if err := server.Stop(); err != nil {
		log.Printf("Error during server shutdown: %v", err)
	}

	log.Println("Gander proxy server stopped")
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

	// Log filter system initialization
	providers := manager.GetProviders()
	totalPacketFilters := 0
	totalInspectionFilters := 0

	for name, provider := range providers {
		packetFilters := len(provider.GetPacketFilters())
		inspectionFilters := len(provider.GetInspectionFilters())
		totalPacketFilters += packetFilters
		totalInspectionFilters += inspectionFilters

		log.Printf("Registered filter provider '%s': %d packet filters, %d inspection filters",
			name, packetFilters, inspectionFilters)
	}

	log.Printf("Filter system initialized: %d providers, %d packet filters, %d inspection filters",
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

	log.Printf("Domain filter: %d inspect domains (%d wildcards), %d bypass domains (%d wildcards)",
		inspectDomains, inspectWildcards, bypassDomains, bypassWildcards)
	log.Printf("IP filter: %d inspect IPs (%d CIDRs), %d bypass IPs (%d CIDRs)",
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

// reportStatistics periodically reports server statistics
func reportStatistics(server *proxy.Server) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := server.GetStats()

		if proxyStats, ok := stats["proxy"].(proxy.ProxyStats); ok {
			log.Printf("Statistics: %d total connections, %d active, %d inspected, %.2f MB transferred",
				proxyStats.TotalConnections,
				proxyStats.ActiveConnections,
				proxyStats.InspectedConnections,
				float64(proxyStats.BytesTransferred)/(1024*1024))
		}

		if captureStats, ok := stats["capture"]; ok {
			log.Printf("Capture Statistics: %+v", captureStats)
		}

		if certStats, ok := stats["certs"]; ok {
			log.Printf("Certificate Statistics: %+v", certStats)
		}
	}
}
