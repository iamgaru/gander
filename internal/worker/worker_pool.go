package worker

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// WorkerPool manages a pool of workers for handling connections asynchronously
type WorkerPool struct {
	workerCount int
	jobQueue    chan *Job
	workers     []*Worker
	shutdown    chan struct{}
	wg          sync.WaitGroup
	stats       *WorkerPoolStats
	enableDebug bool
	started     int32
}

// Job represents work to be done by a worker
type Job struct {
	ID         string
	Connection net.Conn
	Handler    ConnectionHandler
	Context    context.Context
	StartTime  time.Time
}

// ConnectionHandler defines the interface for handling connections
type ConnectionHandler interface {
	HandleConnection(conn net.Conn) error
}

// Worker represents a single worker goroutine
type Worker struct {
	id       int
	pool     *WorkerPool
	jobQueue chan *Job
	quit     chan struct{}
	stats    *WorkerStats
}

// WorkerPoolStats tracks worker pool performance
type WorkerPoolStats struct {
	mutex           sync.RWMutex
	TotalJobs       int64
	ProcessedJobs   int64
	FailedJobs      int64
	QueuedJobs      int64
	ActiveWorkers   int32
	IdleWorkers     int32
	AverageLatency  int64
	MaxQueueSize    int
	CurrentQueueLen int
}

// WorkerPoolStatsSnapshot represents a snapshot of worker pool statistics without mutex
type WorkerPoolStatsSnapshot struct {
	TotalJobs       int64
	ProcessedJobs   int64
	FailedJobs      int64
	QueuedJobs      int64
	ActiveWorkers   int32
	IdleWorkers     int32
	AverageLatency  int64
	MaxQueueSize    int
	CurrentQueueLen int
}

// WorkerStats tracks individual worker performance
type WorkerStats struct {
	JobsProcessed int64
	JobsFailed    int64
	TotalWorkTime time.Duration
	LastJobTime   time.Time
	IsActive      bool
	mutex         sync.RWMutex
}

// WorkerStatsSnapshot represents a snapshot of worker statistics without mutex
type WorkerStatsSnapshot struct {
	JobsProcessed int64
	JobsFailed    int64
	TotalWorkTime time.Duration
	LastJobTime   time.Time
	IsActive      bool
}

// WorkerPoolConfig contains configuration for the worker pool
type WorkerPoolConfig struct {
	WorkerCount     int
	QueueSize       int
	EnableDebug     bool
	JobTimeout      time.Duration
	ShutdownTimeout time.Duration
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(config *WorkerPoolConfig) *WorkerPool {
	if config.WorkerCount == 0 {
		config.WorkerCount = runtime.NumCPU() * 2
	}
	if config.QueueSize == 0 {
		config.QueueSize = config.WorkerCount * 100
	}
	if config.JobTimeout == 0 {
		config.JobTimeout = 30 * time.Second
	}
	if config.ShutdownTimeout == 0 {
		config.ShutdownTimeout = 10 * time.Second
	}

	pool := &WorkerPool{
		workerCount: config.WorkerCount,
		jobQueue:    make(chan *Job, config.QueueSize),
		workers:     make([]*Worker, config.WorkerCount),
		shutdown:    make(chan struct{}),
		enableDebug: config.EnableDebug,
		stats: &WorkerPoolStats{
			MaxQueueSize: config.QueueSize,
		},
	}

	// Create workers
	for i := 0; i < config.WorkerCount; i++ {
		worker := &Worker{
			id:       i,
			pool:     pool,
			jobQueue: pool.jobQueue,
			quit:     make(chan struct{}),
			stats:    &WorkerStats{},
		}
		pool.workers[i] = worker
	}

	return pool
}

// Start initializes and starts all workers
func (wp *WorkerPool) Start() error {
	if !atomic.CompareAndSwapInt32(&wp.started, 0, 1) {
		return fmt.Errorf("worker pool already started")
	}

	// Start all workers
	for _, worker := range wp.workers {
		wp.wg.Add(1)
		go worker.start()
		atomic.AddInt32(&wp.stats.IdleWorkers, 1)
	}

	// Start queue monitoring
	go wp.monitorQueue()

	if wp.enableDebug {
		fmt.Printf("Worker pool started with %d workers, queue size %d\n",
			wp.workerCount, cap(wp.jobQueue))
	}

	return nil
}

// Submit submits a job to the worker pool
func (wp *WorkerPool) Submit(job *Job) error {
	if atomic.LoadInt32(&wp.started) == 0 {
		return fmt.Errorf("worker pool not started")
	}

	select {
	case wp.jobQueue <- job:
		atomic.AddInt64(&wp.stats.TotalJobs, 1)
		atomic.AddInt64(&wp.stats.QueuedJobs, 1)

		if wp.enableDebug {
			fmt.Printf("Job %s queued for processing\n", job.ID)
		}
		return nil
	default:
		// Queue is full
		atomic.AddInt64(&wp.stats.FailedJobs, 1)
		return fmt.Errorf("worker pool queue is full")
	}
}

// SubmitConnection is a convenience method for submitting connection jobs
func (wp *WorkerPool) SubmitConnection(conn net.Conn, handler ConnectionHandler) error {
	job := &Job{
		ID:         fmt.Sprintf("conn-%s-%d", conn.RemoteAddr().String(), time.Now().UnixNano()),
		Connection: conn,
		Handler:    handler,
		Context:    context.Background(),
		StartTime:  time.Now(),
	}

	return wp.Submit(job)
}

// SubmitConnectionWithContext submits a connection job with context
func (wp *WorkerPool) SubmitConnectionWithContext(ctx context.Context, conn net.Conn, handler ConnectionHandler) error {
	job := &Job{
		ID:         fmt.Sprintf("conn-%s-%d", conn.RemoteAddr().String(), time.Now().UnixNano()),
		Connection: conn,
		Handler:    handler,
		Context:    ctx,
		StartTime:  time.Now(),
	}

	return wp.Submit(job)
}

// Stop gracefully stops the worker pool
func (wp *WorkerPool) Stop(timeout time.Duration) error {
	if !atomic.CompareAndSwapInt32(&wp.started, 1, 0) {
		return nil // Already stopped
	}

	if wp.enableDebug {
		fmt.Printf("Stopping worker pool...\n")
	}

	// Signal shutdown
	close(wp.shutdown)

	// Close job queue to prevent new jobs
	close(wp.jobQueue)

	// Wait for workers to finish with timeout
	done := make(chan struct{})
	go func() {
		wp.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		if wp.enableDebug {
			fmt.Printf("Worker pool stopped gracefully\n")
		}
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("worker pool stop timeout after %v", timeout)
	}
}

// GetStats returns current worker pool statistics
func (wp *WorkerPool) GetStats() WorkerPoolStatsSnapshot {
	wp.stats.mutex.RLock()
	defer wp.stats.mutex.RUnlock()

	stats := WorkerPoolStatsSnapshot{
		TotalJobs:       wp.stats.TotalJobs,
		ProcessedJobs:   wp.stats.ProcessedJobs,
		FailedJobs:      wp.stats.FailedJobs,
		QueuedJobs:      wp.stats.QueuedJobs,
		ActiveWorkers:   atomic.LoadInt32(&wp.stats.ActiveWorkers),
		IdleWorkers:     atomic.LoadInt32(&wp.stats.IdleWorkers),
		AverageLatency:  wp.stats.AverageLatency,
		MaxQueueSize:    wp.stats.MaxQueueSize,
		CurrentQueueLen: len(wp.jobQueue),
	}

	return stats
}

// GetWorkerStats returns statistics for all workers
func (wp *WorkerPool) GetWorkerStats() []WorkerStatsSnapshot {
	stats := make([]WorkerStatsSnapshot, len(wp.workers))
	for i, worker := range wp.workers {
		worker.stats.mutex.RLock()
		stats[i] = WorkerStatsSnapshot{
			JobsProcessed: worker.stats.JobsProcessed,
			JobsFailed:    worker.stats.JobsFailed,
			TotalWorkTime: worker.stats.TotalWorkTime,
			LastJobTime:   worker.stats.LastJobTime,
			IsActive:      worker.stats.IsActive,
		}
		worker.stats.mutex.RUnlock()
	}
	return stats
}

// monitorQueue monitors the job queue and updates statistics
func (wp *WorkerPool) monitorQueue() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			queueLen := len(wp.jobQueue)
			wp.stats.mutex.Lock()
			wp.stats.CurrentQueueLen = queueLen
			wp.stats.mutex.Unlock()

			if wp.enableDebug && queueLen > cap(wp.jobQueue)/2 {
				fmt.Printf("Worker pool queue is %d%% full (%d/%d)\n",
					(queueLen*100)/cap(wp.jobQueue), queueLen, cap(wp.jobQueue))
			}

		case <-wp.shutdown:
			return
		}
	}
}

// Worker methods

// start begins the worker's job processing loop
func (w *Worker) start() {
	defer w.pool.wg.Done()

	if w.pool.enableDebug {
		fmt.Printf("Worker %d started\n", w.id)
	}

	for {
		select {
		case job, ok := <-w.jobQueue:
			if !ok {
				// Channel closed, worker should exit
				if w.pool.enableDebug {
					fmt.Printf("Worker %d stopping (channel closed)\n", w.id)
				}
				return
			}

			w.processJob(job)

		case <-w.quit:
			if w.pool.enableDebug {
				fmt.Printf("Worker %d stopping (quit signal)\n", w.id)
			}
			return
		}
	}
}

// processJob processes a single job
func (w *Worker) processJob(job *Job) {
	startTime := time.Now()

	// Update worker stats
	atomic.AddInt32(&w.pool.stats.IdleWorkers, -1)
	atomic.AddInt32(&w.pool.stats.ActiveWorkers, 1)

	w.stats.mutex.Lock()
	w.stats.IsActive = true
	w.stats.mutex.Unlock()

	defer func() {
		// Update stats when job completes
		atomic.AddInt32(&w.pool.stats.ActiveWorkers, -1)
		atomic.AddInt32(&w.pool.stats.IdleWorkers, 1)
		atomic.AddInt64(&w.pool.stats.QueuedJobs, -1)
		atomic.AddInt64(&w.pool.stats.ProcessedJobs, 1)

		w.stats.mutex.Lock()
		w.stats.IsActive = false
		w.stats.JobsProcessed++
		w.stats.TotalWorkTime += time.Since(startTime)
		w.stats.LastJobTime = time.Now()
		w.stats.mutex.Unlock()

		// Update average latency
		latency := time.Since(job.StartTime).Milliseconds()
		w.updateAverageLatency(latency)

		if job.Connection != nil {
			job.Connection.Close()
		}

		if w.pool.enableDebug {
			fmt.Printf("Worker %d completed job %s in %v\n",
				w.id, job.ID, time.Since(startTime))
		}
	}()

	// Create context with timeout if needed
	ctx := job.Context
	if ctx == nil {
		ctx = context.Background()
	}

	// Process the job
	if err := w.executeJob(ctx, job); err != nil {
		atomic.AddInt64(&w.pool.stats.FailedJobs, 1)

		w.stats.mutex.Lock()
		w.stats.JobsFailed++
		w.stats.mutex.Unlock()

		if w.pool.enableDebug {
			fmt.Printf("Worker %d job %s failed: %v\n", w.id, job.ID, err)
		}
	}
}

// executeJob executes the actual job logic
func (w *Worker) executeJob(ctx context.Context, job *Job) error {
	if job.Handler == nil {
		return fmt.Errorf("no handler provided for job %s", job.ID)
	}

	// Create a context with timeout
	jobCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	// Execute the handler in a goroutine to respect context cancellation
	errChan := make(chan error, 1)
	go func() {
		errChan <- job.Handler.HandleConnection(job.Connection)
	}()

	select {
	case err := <-errChan:
		return err
	case <-jobCtx.Done():
		return fmt.Errorf("job %s timed out", job.ID)
	}
}

// updateAverageLatency updates the average latency using exponential moving average
func (w *Worker) updateAverageLatency(latency int64) {
	w.pool.stats.mutex.Lock()
	defer w.pool.stats.mutex.Unlock()

	if w.pool.stats.AverageLatency == 0 {
		w.pool.stats.AverageLatency = latency
	} else {
		// Exponential moving average with alpha = 0.1
		w.pool.stats.AverageLatency = int64(0.9*float64(w.pool.stats.AverageLatency) + 0.1*float64(latency))
	}
}

// stop stops the worker
func (w *Worker) stop() {
	close(w.quit)
}

// AdaptiveWorkerPool provides dynamic worker scaling based on load
type AdaptiveWorkerPool struct {
	*WorkerPool
	minWorkers         int
	maxWorkers         int
	scaleUpThreshold   float64
	scaleDownThreshold float64
	scalingMutex       sync.Mutex
	lastScaleTime      time.Time
	scaleInterval      time.Duration
}

// NewAdaptiveWorkerPool creates a worker pool that can scale based on load
func NewAdaptiveWorkerPool(config *WorkerPoolConfig, minWorkers, maxWorkers int) *AdaptiveWorkerPool {
	pool := NewWorkerPool(config)

	return &AdaptiveWorkerPool{
		WorkerPool:         pool,
		minWorkers:         minWorkers,
		maxWorkers:         maxWorkers,
		scaleUpThreshold:   0.8, // Scale up when 80% busy
		scaleDownThreshold: 0.3, // Scale down when 30% busy
		scaleInterval:      30 * time.Second,
	}
}

// Start starts the adaptive worker pool with monitoring
func (awp *AdaptiveWorkerPool) Start() error {
	if err := awp.WorkerPool.Start(); err != nil {
		return err
	}

	// Start adaptive scaling monitor
	go awp.scaleMonitor()

	return nil
}

// scaleMonitor monitors load and adjusts worker count
func (awp *AdaptiveWorkerPool) scaleMonitor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			awp.checkAndScale()
		case <-awp.shutdown:
			return
		}
	}
}

// checkAndScale evaluates current load and scales workers if needed
func (awp *AdaptiveWorkerPool) checkAndScale() {
	awp.scalingMutex.Lock()
	defer awp.scalingMutex.Unlock()

	// Don't scale too frequently
	if time.Since(awp.lastScaleTime) < awp.scaleInterval {
		return
	}

	stats := awp.GetStats()
	currentWorkers := len(awp.workers)

	// Calculate utilization
	totalWorkers := stats.ActiveWorkers + stats.IdleWorkers
	if totalWorkers == 0 {
		return
	}

	utilization := float64(stats.ActiveWorkers) / float64(totalWorkers)
	queueUtilization := float64(stats.CurrentQueueLen) / float64(stats.MaxQueueSize)

	if awp.enableDebug {
		fmt.Printf("Adaptive pool: %d workers, %.2f%% util, %.2f%% queue\n",
			currentWorkers, utilization*100, queueUtilization*100)
	}

	// Scale up if utilization is high or queue is filling up
	if (utilization > awp.scaleUpThreshold || queueUtilization > 0.5) && currentWorkers < awp.maxWorkers {
		awp.scaleUp()
		awp.lastScaleTime = time.Now()
	}

	// Scale down if utilization is low
	if utilization < awp.scaleDownThreshold && queueUtilization < 0.1 && currentWorkers > awp.minWorkers {
		awp.scaleDown()
		awp.lastScaleTime = time.Now()
	}
}

// scaleUp adds more workers
func (awp *AdaptiveWorkerPool) scaleUp() {
	newWorkerCount := len(awp.workers) + 1
	if newWorkerCount > awp.maxWorkers {
		return
	}

	worker := &Worker{
		id:       len(awp.workers),
		pool:     awp.WorkerPool,
		jobQueue: awp.jobQueue,
		quit:     make(chan struct{}),
		stats:    &WorkerStats{},
	}

	awp.workers = append(awp.workers, worker)
	awp.wg.Add(1)
	go worker.start()

	atomic.AddInt32(&awp.stats.IdleWorkers, 1)

	if awp.enableDebug {
		fmt.Printf("Scaled up to %d workers\n", len(awp.workers))
	}
}

// scaleDown removes workers (simplified - in practice this is more complex)
func (awp *AdaptiveWorkerPool) scaleDown() {
	if len(awp.workers) <= awp.minWorkers {
		return
	}

	// This is a simplified scale down - in production you'd want to gracefully
	// stop specific workers rather than just reducing the count
	if awp.enableDebug {
		fmt.Printf("Would scale down from %d workers (simplified implementation)\n", len(awp.workers))
	}
}
