package config

import (
	"fmt"
	"log"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ConfigWatcher watches a configuration file for changes and triggers reloads
type ConfigWatcher struct {
	configFile string
	loader     *Loader
	watcher    *fsnotify.Watcher
	stopCh     chan struct{}
	callbacks  []ConfigChangeCallback
	mu         sync.RWMutex
	debounce   time.Duration
	lastReload time.Time
}

// ConfigChangeCallback is called when the config file changes
type ConfigChangeCallback func(oldConfig, newConfig *Config) error

// NewConfigWatcher creates a new config file watcher
func NewConfigWatcher(configFile string, loader *Loader) (*ConfigWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %w", err)
	}

	return &ConfigWatcher{
		configFile: configFile,
		loader:     loader,
		watcher:    watcher,
		stopCh:     make(chan struct{}),
		callbacks:  make([]ConfigChangeCallback, 0),
		debounce:   2 * time.Second, // Debounce rapid file changes
	}, nil
}

// AddCallback adds a callback function to be called when config changes
func (cw *ConfigWatcher) AddCallback(callback ConfigChangeCallback) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	cw.callbacks = append(cw.callbacks, callback)
}

// Start starts watching the config file for changes
func (cw *ConfigWatcher) Start(currentConfig *Config) error {
	// Add the config file to the watcher
	absPath, err := filepath.Abs(cw.configFile)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	if err := cw.watcher.Add(absPath); err != nil {
		return fmt.Errorf("failed to watch config file: %w", err)
	}

	log.Printf("Config watcher started for file: %s", absPath)

	// Start the watch loop
	go cw.watchLoop(currentConfig)

	return nil
}

// Stop stops the config file watcher
func (cw *ConfigWatcher) Stop() error {
	close(cw.stopCh)
	return cw.watcher.Close()
}

// watchLoop is the main watch loop that handles file system events
func (cw *ConfigWatcher) watchLoop(currentConfig *Config) {
	for {
		select {
		case event, ok := <-cw.watcher.Events:
			if !ok {
				return
			}

			// Only process write events and ignore temporary files
			if event.Op&fsnotify.Write == fsnotify.Write {
				if filepath.Base(event.Name) == filepath.Base(cw.configFile) {
					cw.handleConfigChange(currentConfig)
				}
			}

		case err, ok := <-cw.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Config watcher error: %v", err)

		case <-cw.stopCh:
			return
		}
	}
}

// handleConfigChange processes a config file change event
func (cw *ConfigWatcher) handleConfigChange(currentConfig *Config) {
	// Debounce rapid changes (editors often write files multiple times)
	now := time.Now()
	if now.Sub(cw.lastReload) < cw.debounce {
		return
	}
	cw.lastReload = now

	log.Printf("Config file changed, reloading...")

	// Load the new configuration
	newConfig, err := cw.loader.Load(cw.configFile)
	if err != nil {
		log.Printf("Failed to reload config: %v", err)
		return
	}

	// Call all registered callbacks
	cw.mu.RLock()
	callbacks := make([]ConfigChangeCallback, len(cw.callbacks))
	copy(callbacks, cw.callbacks)
	cw.mu.RUnlock()

	for _, callback := range callbacks {
		if err := callback(currentConfig, newConfig); err != nil {
			log.Printf("Config change callback error: %v", err)
			return
		}
	}

	log.Printf("Config successfully reloaded")
}

// SetDebounceTime sets the debounce time for config file changes
func (cw *ConfigWatcher) SetDebounceTime(duration time.Duration) {
	cw.debounce = duration
}
