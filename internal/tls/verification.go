package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"path/filepath"
	"strings"
)

// TLSVerificationContext defines the purpose of a TLS connection for smart verification
type TLSVerificationContext string

const (
	// TLSContextRelay is for actual data relay operations (requires secure verification)
	TLSContextRelay TLSVerificationContext = "relay"

	// TLSContextSniffing is for certificate analysis only (allows insecure for info gathering)
	TLSContextSniffing TLSVerificationContext = "sniffing"

	// TLSContextPooling is for connection pool operations (requires secure verification)
	TLSContextPooling TLSVerificationContext = "pooling"

	// TLSContextHealthCheck is for health check operations (requires secure verification)
	TLSContextHealthCheck TLSVerificationContext = "healthcheck"
)

// SmartTLSConfig creates TLS configurations with context-aware security
type SmartTLSConfig struct {
	debugMode bool
}

// NewSmartTLSConfig creates a new smart TLS configuration manager
func NewSmartTLSConfig(debugMode bool) *SmartTLSConfig {
	return &SmartTLSConfig{
		debugMode: debugMode,
	}
}

// isDevelopmentDomain checks if a domain appears to be for development/testing
func (s *SmartTLSConfig) isDevelopmentDomain(domain string) bool {
	// Remove port if present
	if idx := strings.LastIndex(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	developmentPatterns := []string{
		"localhost",
		"127.0.0.1",
		"::1",                                          // IPv6 localhost
		"*.local",                                      // mDNS domains
		"*.dev",                                        // Development domains
		"*.test",                                       // Test domains
		"*.internal",                                   // Internal domains
		"*.lan",                                        // Local network
		"192.168.*",                                    // Private IP ranges
		"10.*",                                         // Private IP ranges
		"172.16.*",                                     // Private IP ranges start
		"172.17.*", "172.18.*", "172.19.*", "172.20.*", // Private IP ranges
		"172.21.*", "172.22.*", "172.23.*", "172.24.*", // Private IP ranges
		"172.25.*", "172.26.*", "172.27.*", "172.28.*", // Private IP ranges
		"172.29.*", "172.30.*", "172.31.*", // Private IP ranges end
	}

	for _, pattern := range developmentPatterns {
		if matched, _ := filepath.Match(pattern, domain); matched {
			return true
		}
	}

	return false
}

// shouldAllowInsecureTLS determines if insecure TLS should be allowed for a given context
func (s *SmartTLSConfig) shouldAllowInsecureTLS(domain string, context TLSVerificationContext) bool {
	// Always allow insecure for certificate sniffing (information gathering only)
	if context == TLSContextSniffing {
		return true
	}

	// If debug mode is enabled, be permissive (preserves existing testing workflow)
	if s.debugMode {
		log.Printf("Debug mode enabled - allowing insecure TLS for %s (context: %s)", domain, context)
		return true
	}

	// Even in production, allow insecure for obvious development domains
	if s.isDevelopmentDomain(domain) {
		log.Printf("Development domain detected (%s) - allowing insecure TLS (context: %s)", domain, context)
		return true
	}

	// For everything else, require secure TLS
	return false
}

// CreateTLSConfig creates a TLS configuration with smart security defaults
func (s *SmartTLSConfig) CreateTLSConfig(domain string, context TLSVerificationContext) *tls.Config {
	if s.shouldAllowInsecureTLS(domain, context) {
		return &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         domain,
		}
	}

	// Create secure TLS configuration for production domains
	return &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         domain,
		RootCAs:            getSystemCAs(), // Uses system's trusted CA bundle
		MinVersion:         tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,    // Fastest
			tls.CurveP256, // Widely supported
		},
		CipherSuites: []uint16{
			// Prioritize AES-GCM and ChaCha20 for performance
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}
}

// CreateTLSConfigWithSessionCache creates a TLS configuration with session caching support
func (s *SmartTLSConfig) CreateTLSConfigWithSessionCache(domain string, context TLSVerificationContext, sessionCache tls.ClientSessionCache) *tls.Config {
	config := s.CreateTLSConfig(domain, context)
	if sessionCache != nil {
		config.ClientSessionCache = sessionCache
	}
	return config
}

// getSystemCAs returns the system's certificate authority bundle
// Returns nil to let Go use the system default CA bundle automatically
func getSystemCAs() *x509.CertPool {
	// Returning nil tells Go to use the system's default CA bundle
	// This works across Windows, macOS, and Linux without additional configuration
	return nil
}

// ConnectWithSmartVerification attempts to connect with appropriate TLS verification
// This provides a fallback strategy for certificate sniffing operations
func (s *SmartTLSConfig) ConnectWithSmartVerification(network, address string, context TLSVerificationContext) (*tls.Conn, error) {
	// Extract domain from address for verification decisions
	domain := address
	if idx := strings.LastIndex(address, ":"); idx != -1 {
		domain = address[:idx]
	}

	// Get the appropriate TLS configuration
	tlsConfig := s.CreateTLSConfig(domain, context)

	// Attempt connection
	conn, err := tls.Dial(network, address, tlsConfig)
	if err != nil {
		// For certificate sniffing, provide helpful error context
		if context == TLSContextSniffing {
			return nil, fmt.Errorf("TLS connection failed for certificate sniffing %s: %w\n"+
				"This is normal for sites with invalid certificates during analysis", address, err)
		}

		// For production contexts, provide security-focused error message
		if s.isDevelopmentDomain(domain) {
			return nil, fmt.Errorf("TLS connection failed to development domain %s: %w\n"+
				"Consider using HTTP for local development or adding certificates to system CA store", address, err)
		} else {
			return nil, fmt.Errorf("secure TLS connection failed to %s: %w\n"+
				"This could indicate an invalid certificate on the upstream server.\n"+
				"For testing with invalid certificates, enable debug mode in configuration", address, err)
		}
	}

	return conn, nil
}

// ValidateTLSContext ensures the context is valid
func ValidateTLSContext(context TLSVerificationContext) error {
	switch context {
	case TLSContextRelay, TLSContextSniffing, TLSContextPooling, TLSContextHealthCheck:
		return nil
	default:
		return fmt.Errorf("invalid TLS verification context: %s", context)
	}
}

// GetContextDescription returns a human-readable description of the TLS context
func GetContextDescription(context TLSVerificationContext) string {
	switch context {
	case TLSContextRelay:
		return "data relay operations (secure verification required)"
	case TLSContextSniffing:
		return "certificate analysis (insecure allowed for information gathering)"
	case TLSContextPooling:
		return "connection pooling (secure verification required)"
	case TLSContextHealthCheck:
		return "health check operations (secure verification required)"
	default:
		return "unknown context"
	}
}
