package cert

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
)

// PreGenerationManager handles background certificate pre-generation
type PreGenerationManager struct {
	certManager     CertificateProvider
	config          *PreGenerationConfig
	popularDomains  []string
	domainFrequency map[string]int
	frequencyMutex  sync.RWMutex
	preGenQueue     chan string
	workers         []*preGenWorker
	shutdown        chan struct{}
	wg              sync.WaitGroup
	stats           *PreGenerationStats
	enableDebug     bool
}

// PreGenerationConfig contains configuration for certificate pre-generation
type PreGenerationConfig struct {
	Enabled            bool          `json:"enabled"`
	WorkerCount        int           `json:"worker_count"`
	QueueSize          int           `json:"queue_size"`
	PopularDomainCount int           `json:"popular_domain_count"`
	FrequencyThreshold int           `json:"frequency_threshold"`
	PreGenInterval     time.Duration `json:"pregen_interval"`
	DomainTTL          time.Duration `json:"domain_ttl"`
	StaticDomains      []string      `json:"static_domains"`
	EnableFreqTracking bool          `json:"enable_frequency_tracking"`
	MaxConcurrentGens  int           `json:"max_concurrent_generations"`
}

// PreGenerationStats tracks pre-generation performance
type PreGenerationStats struct {
	mutex              sync.RWMutex
	TotalPreGenerated  int64
	CacheHitsSaved     int64
	QueuedDomains      int64
	FailedGenerations  int64
	AverageGenTime     time.Duration
	PopularDomainCount int
	FrequencyMapSize   int
	WorkerUtilization  float64
	LastPreGenBatch    time.Time
}

// PreGenerationStatsSnapshot represents a snapshot of pregeneration statistics without mutex
type PreGenerationStatsSnapshot struct {
	TotalPreGenerated  int64
	CacheHitsSaved     int64
	QueuedDomains      int64
	FailedGenerations  int64
	AverageGenTime     time.Duration
	PopularDomainCount int
	FrequencyMapSize   int
	WorkerUtilization  float64
	LastPreGenBatch    time.Time
}

// preGenWorker handles certificate generation in background
type preGenWorker struct {
	id      int
	manager *PreGenerationManager
	quit    chan struct{}
}

// NewPreGenerationManager creates a new certificate pre-generation manager
func NewPreGenerationManager(certManager CertificateProvider, config *PreGenerationConfig, enableDebug bool) *PreGenerationManager {
	if config.WorkerCount == 0 {
		config.WorkerCount = 2
	}
	if config.QueueSize == 0 {
		config.QueueSize = 1000
	}
	if config.PopularDomainCount == 0 {
		config.PopularDomainCount = 100
	}
	if config.FrequencyThreshold == 0 {
		config.FrequencyThreshold = 5
	}
	if config.PreGenInterval == 0 {
		config.PreGenInterval = 10 * time.Minute
	}
	if config.DomainTTL == 0 {
		config.DomainTTL = 24 * time.Hour
	}
	if config.MaxConcurrentGens == 0 {
		config.MaxConcurrentGens = 10
	}

	mgr := &PreGenerationManager{
		certManager:     certManager,
		config:          config,
		domainFrequency: make(map[string]int),
		preGenQueue:     make(chan string, config.QueueSize),
		workers:         make([]*preGenWorker, config.WorkerCount),
		shutdown:        make(chan struct{}),
		stats:           &PreGenerationStats{},
		enableDebug:     enableDebug,
	}

	// Create workers
	for i := 0; i < config.WorkerCount; i++ {
		mgr.workers[i] = &preGenWorker{
			id:      i,
			manager: mgr,
			quit:    make(chan struct{}),
		}
	}

	return mgr
}

// Start begins the pre-generation background processes
func (pgm *PreGenerationManager) Start() error {
	if !pgm.config.Enabled {
		if pgm.enableDebug {
			log.Printf("Certificate pre-generation disabled")
		}
		return nil
	}

	// Start workers
	for _, worker := range pgm.workers {
		pgm.wg.Add(1)
		go worker.start()
	}

	// Start domain analysis
	if pgm.config.EnableFreqTracking {
		go pgm.domainAnalysisWorker()
	}

	// Start periodic pre-generation
	go pgm.periodicPreGeneration()

	// Pre-generate static domains immediately
	if len(pgm.config.StaticDomains) > 0 {
		go pgm.preGenerateStaticDomains()
	}

	if pgm.enableDebug {
		log.Printf("Certificate pre-generation started with %d workers", len(pgm.workers))
	}

	return nil
}

// Stop gracefully stops the pre-generation manager
func (pgm *PreGenerationManager) Stop() error {
	if !pgm.config.Enabled {
		return nil
	}

	close(pgm.shutdown)
	close(pgm.preGenQueue)

	// Stop all workers
	for _, worker := range pgm.workers {
		close(worker.quit)
	}

	pgm.wg.Wait()

	if pgm.enableDebug {
		log.Printf("Certificate pre-generation stopped")
	}

	return nil
}

// RecordDomainAccess records that a domain was accessed for frequency tracking
func (pgm *PreGenerationManager) RecordDomainAccess(domain string) {
	if !pgm.config.Enabled || !pgm.config.EnableFreqTracking {
		return
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return
	}

	pgm.frequencyMutex.Lock()
	pgm.domainFrequency[domain]++
	frequency := pgm.domainFrequency[domain]
	pgm.frequencyMutex.Unlock()

	// Queue for pre-generation if it crosses threshold
	if frequency == pgm.config.FrequencyThreshold {
		select {
		case pgm.preGenQueue <- domain:
			pgm.stats.mutex.Lock()
			pgm.stats.QueuedDomains++
			pgm.stats.mutex.Unlock()

			if pgm.enableDebug {
				log.Printf("Queued domain for pre-generation: %s (frequency: %d)", domain, frequency)
			}
		default:
			// Queue is full, skip
			if pgm.enableDebug {
				log.Printf("Pre-generation queue full, skipping: %s", domain)
			}
		}
	}
}

// RequestPreGeneration manually requests pre-generation of a domain
func (pgm *PreGenerationManager) RequestPreGeneration(domain string) error {
	if !pgm.config.Enabled {
		return fmt.Errorf("pre-generation disabled")
	}

	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return fmt.Errorf("invalid domain")
	}

	select {
	case pgm.preGenQueue <- domain:
		pgm.stats.mutex.Lock()
		pgm.stats.QueuedDomains++
		pgm.stats.mutex.Unlock()

		if pgm.enableDebug {
			log.Printf("Manually queued domain for pre-generation: %s", domain)
		}
		return nil
	default:
		return fmt.Errorf("pre-generation queue is full")
	}
}

// preGenerateStaticDomains pre-generates certificates for configured static domains
func (pgm *PreGenerationManager) preGenerateStaticDomains() {
	for _, domain := range pgm.config.StaticDomains {
		select {
		case pgm.preGenQueue <- domain:
			if pgm.enableDebug {
				log.Printf("Queued static domain for pre-generation: %s", domain)
			}
		case <-pgm.shutdown:
			return
		}
	}
}

// domainAnalysisWorker analyzes domain frequency and updates popular domains
func (pgm *PreGenerationManager) domainAnalysisWorker() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pgm.updatePopularDomains()
		case <-pgm.shutdown:
			return
		}
	}
}

// updatePopularDomains updates the list of popular domains based on frequency
func (pgm *PreGenerationManager) updatePopularDomains() {
	pgm.frequencyMutex.RLock()

	// Create a slice of domain-frequency pairs
	type domainFreq struct {
		domain string
		freq   int
	}

	domains := make([]domainFreq, 0, len(pgm.domainFrequency))
	for domain, freq := range pgm.domainFrequency {
		if freq >= pgm.config.FrequencyThreshold {
			domains = append(domains, domainFreq{domain: domain, freq: freq})
		}
	}
	pgm.frequencyMutex.RUnlock()

	// Sort by frequency (descending)
	sort.Slice(domains, func(i, j int) bool {
		return domains[i].freq > domains[j].freq
	})

	// Take top N domains
	count := pgm.config.PopularDomainCount
	if len(domains) < count {
		count = len(domains)
	}

	newPopular := make([]string, count)
	for i := 0; i < count; i++ {
		newPopular[i] = domains[i].domain
	}

	pgm.popularDomains = newPopular

	// Update stats
	pgm.stats.mutex.Lock()
	pgm.stats.PopularDomainCount = len(pgm.popularDomains)
	pgm.stats.FrequencyMapSize = len(pgm.domainFrequency)
	pgm.stats.mutex.Unlock()

	if pgm.enableDebug && len(newPopular) > 0 {
		log.Printf("Updated popular domains list: %d domains, top 5: %v",
			len(newPopular), newPopular[:min(5, len(newPopular))])
	}
}

// periodicPreGeneration performs periodic pre-generation of popular domains
func (pgm *PreGenerationManager) periodicPreGeneration() {
	ticker := time.NewTicker(pgm.config.PreGenInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			pgm.preGeneratePopularDomains()
		case <-pgm.shutdown:
			return
		}
	}
}

// preGeneratePopularDomains queues popular domains for pre-generation
func (pgm *PreGenerationManager) preGeneratePopularDomains() {
	if len(pgm.popularDomains) == 0 {
		return
	}

	queuedCount := 0
	for _, domain := range pgm.popularDomains {
		select {
		case pgm.preGenQueue <- domain:
			queuedCount++
		default:
			// Queue is full
			break
		}
	}

	pgm.stats.mutex.Lock()
	pgm.stats.QueuedDomains += int64(queuedCount)
	pgm.stats.LastPreGenBatch = time.Now()
	pgm.stats.mutex.Unlock()

	if pgm.enableDebug && queuedCount > 0 {
		log.Printf("Queued %d popular domains for pre-generation", queuedCount)
	}
}

// GetStats returns current pre-generation statistics
func (pgm *PreGenerationManager) GetStats() PreGenerationStatsSnapshot {
	pgm.stats.mutex.RLock()
	defer pgm.stats.mutex.RUnlock()

	// Calculate worker utilization
	activeWorkers := 0
	for _, worker := range pgm.workers {
		// This is a simplified check - in practice you'd track worker state
		select {
		case <-worker.quit:
			// Worker is stopped
		default:
			activeWorkers++
		}
	}

	workerUtilization := float64(0)
	if len(pgm.workers) > 0 {
		workerUtilization = float64(activeWorkers) / float64(len(pgm.workers))
	}

	// Create snapshot without copying mutex
	stats := PreGenerationStatsSnapshot{
		TotalPreGenerated:  pgm.stats.TotalPreGenerated,
		CacheHitsSaved:     pgm.stats.CacheHitsSaved,
		QueuedDomains:      pgm.stats.QueuedDomains,
		FailedGenerations:  pgm.stats.FailedGenerations,
		AverageGenTime:     pgm.stats.AverageGenTime,
		PopularDomainCount: pgm.stats.PopularDomainCount,
		FrequencyMapSize:   pgm.stats.FrequencyMapSize,
		WorkerUtilization:  workerUtilization,
		LastPreGenBatch:    pgm.stats.LastPreGenBatch,
	}

	return stats
}

// GetPopularDomains returns the current list of popular domains
func (pgm *PreGenerationManager) GetPopularDomains() []string {
	result := make([]string, len(pgm.popularDomains))
	copy(result, pgm.popularDomains)
	return result
}

// GetDomainFrequencies returns a copy of the domain frequency map
func (pgm *PreGenerationManager) GetDomainFrequencies() map[string]int {
	pgm.frequencyMutex.RLock()
	defer pgm.frequencyMutex.RUnlock()

	result := make(map[string]int)
	for domain, freq := range pgm.domainFrequency {
		result[domain] = freq
	}
	return result
}

// ClearFrequencyData clears the domain frequency tracking data
func (pgm *PreGenerationManager) ClearFrequencyData() {
	pgm.frequencyMutex.Lock()
	pgm.domainFrequency = make(map[string]int)
	pgm.popularDomains = nil
	pgm.frequencyMutex.Unlock()

	pgm.stats.mutex.Lock()
	pgm.stats.PopularDomainCount = 0
	pgm.stats.FrequencyMapSize = 0
	pgm.stats.mutex.Unlock()

	if pgm.enableDebug {
		log.Printf("Cleared domain frequency data")
	}
}

// Worker methods

// start begins the worker's processing loop
func (w *preGenWorker) start() {
	defer w.manager.wg.Done()

	if w.manager.enableDebug {
		log.Printf("Pre-generation worker %d started", w.id)
	}

	for {
		select {
		case domain, ok := <-w.manager.preGenQueue:
			if !ok {
				// Channel closed
				if w.manager.enableDebug {
					log.Printf("Pre-generation worker %d stopping (channel closed)", w.id)
				}
				return
			}

			w.processPreGeneration(domain)

		case <-w.quit:
			if w.manager.enableDebug {
				log.Printf("Pre-generation worker %d stopping (quit signal)", w.id)
			}
			return
		}
	}
}

// processPreGeneration handles pre-generation of a single domain
func (w *preGenWorker) processPreGeneration(domain string) {
	startTime := time.Now()

	if w.manager.enableDebug {
		log.Printf("Worker %d pre-generating certificate for: %s", w.id, domain)
	}

	// Check if certificate already exists and is still valid
	if cert, err := w.manager.certManager.GetCertificate(domain); err == nil {
		if time.Until(cert.ExpiresAt) > 24*time.Hour {
			// Certificate exists and has plenty of time left
			w.manager.stats.mutex.Lock()
			w.manager.stats.CacheHitsSaved++
			w.manager.stats.mutex.Unlock()

			if w.manager.enableDebug {
				log.Printf("Worker %d skipped %s (certificate already valid until %v)",
					w.id, domain, cert.ExpiresAt)
			}
			return
		}
	}

	// Generate the certificate
	_, err := w.manager.certManager.GetCertificate(domain)
	duration := time.Since(startTime)

	w.manager.stats.mutex.Lock()
	if err != nil {
		w.manager.stats.FailedGenerations++
		if w.manager.enableDebug {
			log.Printf("Worker %d failed to pre-generate certificate for %s: %v", w.id, domain, err)
		}
	} else {
		w.manager.stats.TotalPreGenerated++

		// Update average generation time
		if w.manager.stats.AverageGenTime == 0 {
			w.manager.stats.AverageGenTime = duration
		} else {
			w.manager.stats.AverageGenTime = time.Duration(
				(int64(w.manager.stats.AverageGenTime) + int64(duration)) / 2)
		}

		if w.manager.enableDebug {
			log.Printf("Worker %d pre-generated certificate for %s in %v", w.id, domain, duration)
		}
	}
	w.manager.stats.mutex.Unlock()
}

// BulkPreGeneration handles bulk pre-generation of multiple domains
type BulkPreGeneration struct {
	manager     *PreGenerationManager
	concurrency int
}

// NewBulkPreGeneration creates a bulk pre-generation handler
func NewBulkPreGeneration(manager *PreGenerationManager) *BulkPreGeneration {
	return &BulkPreGeneration{
		manager:     manager,
		concurrency: manager.config.MaxConcurrentGens,
	}
}

// PreGenerateDomains pre-generates certificates for a list of domains
func (bpg *BulkPreGeneration) PreGenerateDomains(ctx context.Context, domains []string) error {
	if !bpg.manager.config.Enabled {
		return fmt.Errorf("pre-generation disabled")
	}

	// Use semaphore to limit concurrency
	sem := make(chan struct{}, bpg.concurrency)
	var wg sync.WaitGroup
	var errors []string
	var errorsMutex sync.Mutex

	for _, domain := range domains {
		domain := domain // Capture for goroutine

		wg.Add(1)
		go func() {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			if _, err := bpg.manager.certManager.GetCertificate(domain); err != nil {
				errorsMutex.Lock()
				errors = append(errors, fmt.Sprintf("%s: %v", domain, err))
				errorsMutex.Unlock()
			}
		}()
	}

	wg.Wait()

	if len(errors) > 0 {
		return fmt.Errorf("failed to pre-generate %d certificates: %v", len(errors), errors[:min(5, len(errors))])
	}

	return nil
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
