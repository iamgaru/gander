package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DefaultCertManager implements the CertificateProvider interface
type DefaultCertManager struct {
	*CertificateManager
}

// NewCertificateManager creates a new certificate manager
func NewCertificateManager(enableDebug bool) *DefaultCertManager {
	return &DefaultCertManager{
		CertificateManager: &CertificateManager{
			certCache:   make(map[string]*Certificate),
			enableDebug: enableDebug,
			stats:       NewCertStats(),
		},
	}
}

// Initialize initializes the certificate manager
func (cm *DefaultCertManager) Initialize(config *CertConfig) error {
	cm.config = config

	// Set defaults
	if config.KeySize == 0 {
		config.KeySize = 2048
	}
	if config.ValidDays == 0 {
		config.ValidDays = 365
	}
	if config.CacheMaxSize == 0 {
		config.CacheMaxSize = 1000
	}
	if config.CacheExpiryHours == 0 {
		config.CacheExpiryHours = 24
	}

	// Create certificate directory
	if err := os.MkdirAll(config.CertDir, 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Load CA certificate and key if auto-generation is enabled
	if config.AutoGenerate {
		if err := cm.LoadCA(); err != nil {
			return fmt.Errorf("failed to load CA: %w", err)
		}
	}

	if cm.enableDebug {
		log.Printf("Certificate manager initialized with auto-generate=%t, upstream-sniff=%t",
			config.AutoGenerate, config.UpstreamCertSniff)
	}

	return nil
}

// LoadCA loads the CA certificate and key
func (cm *DefaultCertManager) LoadCA() error {
	startTime := time.Now()
	defer func() {
		cm.stats.mutex.Lock()
		cm.stats.CALoadTime = time.Since(startTime).Milliseconds()
		cm.stats.mutex.Unlock()
	}()

	// Load CA certificate
	caCertPEM, err := os.ReadFile(cm.config.CAFile)
	if err != nil {
		return fmt.Errorf("failed to read CA cert file: %w", err)
	}

	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Load CA private key
	caKeyPEM, err := os.ReadFile(cm.config.CAKeyFile)
	if err != nil {
		return fmt.Errorf("failed to read CA key file: %w", err)
	}

	keyBlock, _ := pem.Decode(caKeyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}

	caKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS8 format
		if caKey8, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err2 == nil {
			caKey = caKey8.(*rsa.PrivateKey)
		} else {
			return fmt.Errorf("failed to parse CA private key: %w", err)
		}
	}

	// Create TLS certificate
	caTLSCert := &tls.Certificate{
		Certificate: [][]byte{caCert.Raw},
		PrivateKey:  caKey,
	}

	cm.caCert = caCert
	cm.caKey = caKey
	cm.caTLSCert = caTLSCert

	if cm.enableDebug {
		log.Printf("Loaded CA certificate: Subject=%s, Valid until=%s",
			caCert.Subject.CommonName, caCert.NotAfter.Format("2006-01-02"))
	}

	return nil
}

// GetCertificate gets or generates a certificate for the given domain
func (cm *DefaultCertManager) GetCertificate(domain string) (*Certificate, error) {
	// Clean domain name
	domain = strings.ToLower(strings.TrimSpace(domain))

	// Check cache first
	cm.cacheMutex.RLock()
	if cert, exists := cm.certCache[domain]; exists {
		if time.Now().Before(cert.ExpiresAt) {
			cm.cacheMutex.RUnlock()
			cm.stats.IncrementCacheHit()
			return cert, nil
		}
		// Certificate expired
		cm.cacheMutex.RUnlock()
		cm.cacheMutex.Lock()
		delete(cm.certCache, domain)
		cm.stats.mutex.Lock()
		cm.stats.ExpiredCerts++
		cm.stats.mutex.Unlock()
		cm.cacheMutex.Unlock()
	} else {
		cm.cacheMutex.RUnlock()
	}

	cm.stats.IncrementCacheMiss()

	// Generate new certificate
	var upstreamInfo *UpstreamCertInfo
	if cm.config.UpstreamCertSniff {
		if info, err := cm.SniffUpstreamCert(domain, 443); err == nil {
			upstreamInfo = info
			cm.stats.IncrementUpstreamSniff()
		} else if cm.enableDebug {
			log.Printf("Failed to sniff upstream cert for %s: %v", domain, err)
		}
	}

	cert, err := cm.GenerateCertificate(domain, upstreamInfo)
	if err != nil {
		return nil, err
	}

	// Cache the certificate
	cm.cacheMutex.Lock()
	cm.certCache[domain] = cert
	cm.stats.mutex.Lock()
	cm.stats.CachedCerts = int64(len(cm.certCache))
	cm.stats.mutex.Unlock()
	cm.cacheMutex.Unlock()

	return cert, nil
}

// GetTLSCertificate gets a TLS certificate for the given domain
func (cm *DefaultCertManager) GetTLSCertificate(domain string) (*tls.Certificate, error) {
	cert, err := cm.GetCertificate(domain)
	if err != nil {
		return nil, err
	}
	return cert.TLSCert, nil
}

// GenerateCertificate generates a new certificate for the domain
func (cm *DefaultCertManager) GenerateCertificate(domain string, template *UpstreamCertInfo) (*Certificate, error) {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime).Milliseconds()
		cm.stats.mutex.Lock()
		// Update average generation time
		if cm.stats.GeneratedCerts > 0 {
			cm.stats.AvgGenTime = (cm.stats.AvgGenTime + duration) / 2
		} else {
			cm.stats.AvgGenTime = duration
		}
		cm.stats.mutex.Unlock()
	}()

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, cm.config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   domain,
			Organization: []string{cm.config.Organization},
			Country:      []string{cm.config.Country},
			Province:     []string{cm.config.Province},
			Locality:     []string{cm.config.Locality},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(cm.config.ValidDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add Subject Alternative Names
	certTemplate.DNSNames = []string{domain}

	// Handle wildcards
	if strings.HasPrefix(domain, "*.") {
		baseDomain := domain[2:]
		certTemplate.DNSNames = append(certTemplate.DNSNames, baseDomain)
	}

	// If we have upstream certificate info, use it to enhance the certificate
	if template != nil {
		if cm.enableDebug {
			log.Printf("Using upstream cert template for %s: CN=%s, SANs=%v, Org=%v",
				domain, template.CommonName, template.SubjectAltNames, template.Organization)
		}

		// Use upstream organization if available
		if len(template.Organization) > 0 {
			certTemplate.Subject.Organization = template.Organization
		}
		if len(template.OrganizationalUnit) > 0 {
			certTemplate.Subject.OrganizationalUnit = template.OrganizationalUnit
		}
		if len(template.Country) > 0 {
			certTemplate.Subject.Country = template.Country
		}
		if len(template.Province) > 0 {
			certTemplate.Subject.Province = template.Province
		}
		if len(template.Locality) > 0 {
			certTemplate.Subject.Locality = template.Locality
		}

		// Add upstream SANs
		for _, san := range template.SubjectAltNames {
			found := false
			for _, existing := range certTemplate.DNSNames {
				if existing == san {
					found = true
					break
				}
			}
			if !found {
				certTemplate.DNSNames = append(certTemplate.DNSNames, san)
			}
		}
	}

	// Check if domain is an IP address
	if ip := net.ParseIP(domain); ip != nil {
		certTemplate.IPAddresses = []net.IP{ip}
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, cm.caCert, &privateKey.PublicKey, cm.caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse generated certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated certificate: %w", err)
	}

	// Create TLS certificate
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
	}

	// Save certificate to disk if configured
	if cm.config.CertDir != "" {
		if err := cm.saveCertificateToDisk(domain, certDER, privateKey); err != nil {
			log.Printf("Failed to save certificate to disk: %v", err)
		}
	}

	managedCert := &Certificate{
		Domain:     domain,
		Cert:       cert,
		PrivateKey: privateKey,
		TLSCert:    tlsCert,
		ExpiresAt:  cert.NotAfter,
		CreatedAt:  time.Now(),
		SNI:        cert.DNSNames,
		Issuer:     cert.Issuer.CommonName,
		Subject:    cert.Subject.CommonName,
		IsCA:       false,
	}

	cm.stats.IncrementGenerated()

	if cm.enableDebug {
		log.Printf("Generated certificate for %s: Subject=%s, SANs=%v, Valid until=%s",
			domain, cert.Subject.CommonName, cert.DNSNames, cert.NotAfter.Format("2006-01-02"))
	}

	return managedCert, nil
}

// saveCertificateToDisk saves a certificate and key to disk
func (cm *DefaultCertManager) saveCertificateToDisk(domain string, certDER []byte, privateKey *rsa.PrivateKey) error {
	// Create safe filename
	safeFilename := strings.ReplaceAll(domain, "*", "wildcard")
	safeFilename = strings.ReplaceAll(safeFilename, ":", "_")

	// Save certificate
	certPath := filepath.Join(cm.config.CertDir, fmt.Sprintf("%s.crt", safeFilename))
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Save private key
	keyPath := filepath.Join(cm.config.CertDir, fmt.Sprintf("%s.key", safeFilename))
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// SniffUpstreamCert retrieves certificate information from upstream server
func (cm *DefaultCertManager) SniffUpstreamCert(domain string, port int) (*UpstreamCertInfo, error) {
	// Connect to upstream server
	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:%d", domain, port), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         domain,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to upstream: %w", err)
	}
	defer conn.Close()

	// Get peer certificates
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates returned from upstream")
	}

	cert := certs[0]

	info := &UpstreamCertInfo{
		Domain:             domain,
		CommonName:         cert.Subject.CommonName,
		SubjectAltNames:    cert.DNSNames,
		Organization:       cert.Subject.Organization,
		OrganizationalUnit: cert.Subject.OrganizationalUnit,
		Country:            cert.Subject.Country,
		Province:           cert.Subject.Province,
		Locality:           cert.Subject.Locality,
		Issuer:             cert.Issuer.CommonName,
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
	}

	// Determine key size
	if pubKey, ok := cert.PublicKey.(*rsa.PublicKey); ok {
		info.KeySize = pubKey.Size() * 8
	}

	return info, nil
}

// GetStats returns certificate management statistics
func (cm *DefaultCertManager) GetStats() *CertStats {
	stats := cm.stats.GetStats()

	// Add current cache size
	cm.cacheMutex.RLock()
	stats.CachedCerts = int64(len(cm.certCache))
	cm.cacheMutex.RUnlock()

	return &stats
}

// ClearCache clears expired certificates from cache
func (cm *DefaultCertManager) ClearCache() int {
	cm.cacheMutex.Lock()
	defer cm.cacheMutex.Unlock()

	cleared := 0
	now := time.Now()

	for domain, cert := range cm.certCache {
		if now.After(cert.ExpiresAt) {
			delete(cm.certCache, domain)
			cleared++
		}
	}

	if cleared > 0 {
		cm.stats.mutex.Lock()
		cm.stats.ExpiredCerts += int64(cleared)
		cm.stats.CachedCerts = int64(len(cm.certCache))
		cm.stats.mutex.Unlock()

		if cm.enableDebug {
			log.Printf("Cleared %d expired certificates from cache", cleared)
		}
	}

	return cleared
}

// Shutdown cleanly shuts down the certificate manager
func (cm *DefaultCertManager) Shutdown() error {
	// Clear cache
	cm.cacheMutex.Lock()
	cm.certCache = make(map[string]*Certificate)
	cm.cacheMutex.Unlock()

	if cm.enableDebug {
		stats := cm.GetStats()
		log.Printf("Certificate manager shutdown: Generated=%d, CacheHits=%d, CacheMisses=%d",
			stats.GeneratedCerts, stats.CacheHits, stats.CacheMisses)
	}

	return nil
}
