package cert

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"
)

// Certificate represents a managed certificate
type Certificate struct {
	Domain     string
	Cert       *x509.Certificate
	PrivateKey interface{}
	TLSCert    *tls.Certificate
	ExpiresAt  time.Time
	CreatedAt  time.Time
	SNI        []string
	Issuer     string
	Subject    string
	IsCA       bool
}

// CertificateManager manages certificate generation, caching, and validation
type CertificateManager struct {
	// Cache for generated certificates
	certCache  map[string]*Certificate
	cacheMutex sync.RWMutex

	// CA certificate and key for signing
	caCert    *x509.Certificate
	caKey     interface{}
	caTLSCert *tls.Certificate

	// Configuration
	config      *CertConfig
	enableDebug bool

	// Statistics
	stats *CertStats
}

// CertConfig holds certificate configuration
type CertConfig struct {
	CertFile          string `json:"cert_file"`
	KeyFile           string `json:"key_file"`
	CAFile            string `json:"ca_file"`
	CAKeyFile         string `json:"ca_key_file"`
	CertDir           string `json:"cert_dir"`
	AutoGenerate      bool   `json:"auto_generate"`
	ValidDays         int    `json:"valid_days"`
	UpstreamCertSniff bool   `json:"upstream_cert_sniff"`
	KeySize           int    `json:"key_size"`
	Organization      string `json:"organization"`
	Country           string `json:"country"`
	Province          string `json:"province"`
	Locality          string `json:"locality"`
	CustomCommonName  string `json:"custom_common_name"`
	CacheMaxSize      int    `json:"cache_max_size"`
	CacheExpiryHours  int    `json:"cache_expiry_hours"`
}

// CertStats tracks certificate management statistics
type CertStats struct {
	GeneratedCerts int64 `json:"generated_certs"`
	CachedCerts    int64 `json:"cached_certs"`
	CacheHits      int64 `json:"cache_hits"`
	CacheMisses    int64 `json:"cache_misses"`
	ExpiredCerts   int64 `json:"expired_certs"`
	UpstreamSniffs int64 `json:"upstream_sniffs"`
	CALoadTime     int64 `json:"ca_load_time_ms"`
	AvgGenTime     int64 `json:"avg_generation_time_ms"`
	mutex          sync.RWMutex
}

// UpstreamCertInfo contains information from upstream certificate sniffing
type UpstreamCertInfo struct {
	Domain             string
	CommonName         string
	SubjectAltNames    []string
	Organization       []string
	OrganizationalUnit []string
	Country            []string
	Province           []string
	Locality           []string
	Issuer             string
	NotBefore          time.Time
	NotAfter           time.Time
	KeySize            int
	SignatureAlgorithm string
}

// CertificateProvider defines the interface for certificate management
type CertificateProvider interface {
	// Initialize initializes the certificate provider
	Initialize(config *CertConfig) error

	// GetCertificate gets or generates a certificate for the given domain
	GetCertificate(domain string) (*Certificate, error)

	// GetTLSCertificate gets a TLS certificate for the given domain
	GetTLSCertificate(domain string) (*tls.Certificate, error)

	// GenerateCertificate generates a new certificate for the domain
	GenerateCertificate(domain string, template *UpstreamCertInfo) (*Certificate, error)

	// SniffUpstreamCert retrieves certificate information from upstream server
	SniffUpstreamCert(domain string, port int) (*UpstreamCertInfo, error)

	// LoadCA loads the CA certificate and key
	LoadCA() error

	// GetStats returns certificate management statistics
	GetStats() *CertStatsSnapshot

	// ClearCache clears expired certificates from cache
	ClearCache() int

	// Shutdown cleanly shuts down the certificate manager
	Shutdown() error
}

// NewCertStats creates a new certificate statistics tracker
func NewCertStats() *CertStats {
	return &CertStats{}
}

// IncrementGenerated safely increments generated certificates count
func (cs *CertStats) IncrementGenerated() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.GeneratedCerts++
}

// IncrementCacheHit safely increments cache hits
func (cs *CertStats) IncrementCacheHit() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.CacheHits++
}

// IncrementCacheMiss safely increments cache misses
func (cs *CertStats) IncrementCacheMiss() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.CacheMisses++
}

// IncrementUpstreamSniff safely increments upstream certificate sniffs
func (cs *CertStats) IncrementUpstreamSniff() {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	cs.UpstreamSniffs++
}

// CertStatsSnapshot represents a snapshot of certificate statistics without mutex
type CertStatsSnapshot struct {
	GeneratedCerts int64 `json:"generated_certs"`
	CachedCerts    int64 `json:"cached_certs"`
	CacheHits      int64 `json:"cache_hits"`
	CacheMisses    int64 `json:"cache_misses"`
	ExpiredCerts   int64 `json:"expired_certs"`
	UpstreamSniffs int64 `json:"upstream_sniffs"`
	CALoadTime     int64 `json:"ca_load_time_ms"`
	AvgGenTime     int64 `json:"avg_generation_time_ms"`
}

// GetStats returns a copy of current statistics
func (cs *CertStats) GetStats() CertStatsSnapshot {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()
	return CertStatsSnapshot{
		GeneratedCerts: cs.GeneratedCerts,
		CachedCerts:    cs.CachedCerts,
		CacheHits:      cs.CacheHits,
		CacheMisses:    cs.CacheMisses,
		ExpiredCerts:   cs.ExpiredCerts,
		UpstreamSniffs: cs.UpstreamSniffs,
		CALoadTime:     cs.CALoadTime,
		AvgGenTime:     cs.AvgGenTime,
	}
}
