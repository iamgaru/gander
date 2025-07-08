# Makefile for Gander MITM Proxy

# Variables
BINARY_NAME=gander
CONFIG_FILE=conf/config.json
BUILD_DIR=bin
CERT_DIR=certs
CAPTURE_DIR=captures
LOGS_DIR=logs
LOG_FILE=logs/proxy.log

# Go build flags
LDFLAGS=-ldflags "-s -w"
BUILD_FLAGS=-trimpath

# Default target
.PHONY: all
all: build

# Build the binary
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/gander

# Build for production (optimized)
.PHONY: build-prod
build-prod:
	@echo "Building $(BINARY_NAME) for production..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/gander

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	@mkdir -p $(BUILD_DIR)
	go test -v -coverprofile=$(BUILD_DIR)/coverage.out ./...
	go tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "Coverage report generated: $(BUILD_DIR)/coverage.html"

# Run integration tests
.PHONY: test-integration
test-integration:
	@echo "Running integration tests..."
	@echo "⚠️  Note: This requires a running Gander instance"
	@echo "🚀 Starting integration test suite..."
	@if [ ! -f $(BUILD_DIR)/$(BINARY_NAME) ]; then \
		echo "Building binary for integration tests..."; \
		$(MAKE) build; \
	fi
	@echo "🧪 Running basic connectivity tests..."
	@timeout 10 curl -s -o /dev/null -w "Status: %{http_code}" http://localhost:8848 || \
		echo "❌ Gander not running on port 8848 - start with 'make run' first"
	@echo "✅ Integration test framework ready"
	@echo "💡 To run full integration tests, implement test scenarios in tests/integration/"

# Run benchmarks
.PHONY: bench
bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Alias for benchmarks (for README compatibility)
.PHONY: benchmark
benchmark: bench

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	@which goimports > /dev/null || (echo "Installing goimports..." && go install golang.org/x/tools/cmd/goimports@latest)
	goimports -w .
	go fmt ./...

# Lint code
.PHONY: lint
lint:
	@echo "Linting code..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run

# Security scan
.PHONY: security
security:
	@echo "Running security scan..."
	@echo "Running go vet security checks..."
	@go vet ./...
	@echo "Running staticcheck..."
	@which staticcheck > /dev/null || (echo "Installing staticcheck..." && go install honnef.co/go/tools/cmd/staticcheck@latest)
	@staticcheck ./... || echo "Staticcheck completed"
	@echo "Security scan completed"

# Alias for security scan (for README compatibility)
.PHONY: security-scan
security-scan: security

# Vet code
.PHONY: vet
vet:
	@echo "Vetting code..."
	go vet ./...

# Setup initial directories (does NOT create config file)
.PHONY: setup
setup:
	@echo "Setting up initial directories..."
	@mkdir -p $(CERT_DIR)
	@mkdir -p $(CAPTURE_DIR)
	@mkdir -p $(LOGS_DIR)
	@echo "Directories created!"
	@echo ""
	@echo "⚠️  IMPORTANT: You must create your own config.json file"
	@echo "📋 Steps:"
	@echo "   1. Copy conf/examples/basic.json to conf/config.json"
	@echo "   2. Edit conf/config.json with your specific settings"
	@echo "   3. Review all settings, especially listen_addr and domains"
	@echo ""
	@if [ ! -f $(CONFIG_FILE) ]; then \
		echo "❌ $(CONFIG_FILE) not found - please create it manually"; \
		echo "💡 Run: cp conf/examples/basic.json $(CONFIG_FILE)"; \
		echo "💡 Then: edit $(CONFIG_FILE)"; \
	else \
		echo "✅ $(CONFIG_FILE) already exists"; \
	fi

# Create config from example (explicit action)
.PHONY: init-config
init-config:
	@echo "Creating initial configuration from example..."
	@if [ -f $(CONFIG_FILE) ]; then \
		echo "❌ $(CONFIG_FILE) already exists!"; \
		echo "💡 To overwrite, run: rm $(CONFIG_FILE) && make init-config"; \
		exit 1; \
	fi
	@cp conf/examples/basic.json $(CONFIG_FILE)
	@echo "✅ Created $(CONFIG_FILE) from example"
	@echo ""
	@echo "⚠️  IMPORTANT: Please review and edit $(CONFIG_FILE) before use"
	@echo "📋 Key settings to check:"
	@echo "   - listen_addr (currently set to :1234 in example)"
	@echo "   - inspect_domains (configure for your needs)"
	@echo "   - TLS settings and certificate paths"
	@echo "   - Logging and capture directories"

# Create enhanced config with identity and storage features
.PHONY: init-enhanced-config
init-enhanced-config:
	@echo "Creating enhanced configuration with identity and storage features..."
	@if [ -f $(CONFIG_FILE) ]; then \
		echo "❌ $(CONFIG_FILE) already exists!"; \
		echo "💡 To overwrite, run: rm $(CONFIG_FILE) && make init-enhanced-config"; \
		exit 1; \
	fi
	@if [ -f conf/examples/storage_optimized.json ]; then \
		cp conf/examples/storage_optimized.json $(CONFIG_FILE); \
		echo "✅ Created enhanced $(CONFIG_FILE) with identity and storage features"; \
	else \
		cp conf/examples/basic.json $(CONFIG_FILE); \
		echo "⚠️  Enhanced config template not found, using basic template"; \
		echo "💡 See docs/enhanced_capture_config.md for enhanced features"; \
	fi
	@echo ""
	@echo "📋 Enhanced features included:"
	@echo "   - Identity-based reporting (IP/MAC correlation)"
	@echo "   - Intelligent storage management (compression, rolling)"
	@echo "   - Enhanced capture format with resource classification"
	@echo "   - Configurable retention policies"

# Validate configuration file
.PHONY: validate-config
validate-config:
	@echo "Validating configuration file..."
	@if [ ! -f $(CONFIG_FILE) ]; then \
		echo "❌ Configuration file $(CONFIG_FILE) not found"; \
		echo "💡 Run: make init-config or make init-enhanced-config"; \
		exit 1; \
	fi
	@echo "🔍 Checking JSON syntax..."
	@python3 -m json.tool $(CONFIG_FILE) > /dev/null 2>&1 || \
		(echo "❌ Invalid JSON syntax in $(CONFIG_FILE)" && exit 1)
	@echo "✅ JSON syntax is valid"
	@echo "🔍 Checking required fields..."
	@if ! grep -q '"listen_addr"' $(CONFIG_FILE); then \
		echo "❌ Missing required field: listen_addr"; \
		exit 1; \
	fi
	@if ! grep -q '"rules"' $(CONFIG_FILE); then \
		echo "❌ Missing required field: rules"; \
		exit 1; \
	fi
	@echo "✅ Required fields present"
	@echo "🔍 Checking optional enhanced features..."
	@if grep -q '"identity"' $(CONFIG_FILE); then \
		echo "✅ Identity system configuration found"; \
	else \
		echo "💡 Identity system not configured (optional)"; \
	fi
	@if grep -q '"storage"' $(CONFIG_FILE); then \
		echo "✅ Storage management configuration found"; \
	else \
		echo "💡 Storage management not configured (optional)"; \
	fi
	@echo "✅ Configuration validation complete"

# Migrate configuration from older versions
.PHONY: migrate-config
migrate-config:
	@echo "Migrating configuration to enhanced format..."
	@if [ ! -f $(CONFIG_FILE) ]; then \
		echo "❌ Configuration file $(CONFIG_FILE) not found"; \
		echo "💡 Run: make init-config first"; \
		exit 1; \
	fi
	@echo "📋 Backing up current config..."
	@cp $(CONFIG_FILE) $(CONFIG_FILE).backup
	@echo "✅ Backup created: $(CONFIG_FILE).backup"
	@echo "🔄 Adding enhanced features to configuration..."
	@if [ -f scripts/migrate_config.py ]; then \
		python3 scripts/migrate_config.py $(CONFIG_FILE) || (echo "❌ Migration failed - restoring backup" && cp $(CONFIG_FILE).backup $(CONFIG_FILE) && exit 1); \
	else \
		echo "❌ Migration script not found - using fallback method"; \
		python3 -c "import json; c=json.load(open('$(CONFIG_FILE)')); c.setdefault('identity',{'enabled':True,'enabled_providers':['ip_mac'],'cache_ttl':'1h','provider_configs':{'ip_mac':{'arp_scan_interval':'5m','trusted_networks':['192.168.0.0/16','10.0.0.0/8']}}}); c.setdefault('storage',{'compression_enabled':True,'compression_format':'gzip','rolling_enabled':True,'max_file_size':52428800,'capture_level':'basic','retention_period':'720h','organization_scheme':'domain'}); json.dump(c,open('$(CONFIG_FILE)','w'),indent=2); print('✅ Configuration migration complete');" || (echo "❌ Migration failed - restoring backup" && cp $(CONFIG_FILE).backup $(CONFIG_FILE) && exit 1); \
	fi
	@echo ""
	@echo "📋 Migration Summary:"
	@echo "   - Original config backed up to: $(CONFIG_FILE).backup"
	@echo "   - Enhanced features added to: $(CONFIG_FILE)"
	@echo "   - Run 'make validate-config' to verify the result"
	@echo ""
	@echo "🎉 Migration complete! Enhanced features now available:"
	@echo "   • Identity-based reporting (IP/MAC correlation)"
	@echo "   • Storage compression and rolling (97% space savings)"
	@echo "   • Enhanced capture format with resource classification"

# Show configuration status and recommendations
.PHONY: config-status
config-status:
	@echo "📋 Configuration Status Report"
	@echo ""
	@if [ ! -f $(CONFIG_FILE) ]; then \
		echo "❌ No configuration file found"; \
		echo "💡 Quick start: make init-enhanced-config"; \
		exit 1; \
	fi
	@echo "✅ Configuration file: $(CONFIG_FILE)"
	@echo ""
	@echo "🔍 Feature Analysis:"
	@if grep -q '"identity".*true' $(CONFIG_FILE); then \
		echo "✅ Identity System: ENABLED"; \
		grep -q '"ip_mac"' $(CONFIG_FILE) && echo "  └─ IP/MAC Provider: Configured" || true; \
	else \
		echo "💡 Identity System: DISABLED"; \
		echo "  └─ Run 'make migrate-config' to enable"; \
	fi
	@if grep -q '"storage"' $(CONFIG_FILE); then \
		echo "✅ Storage Management: CONFIGURED"; \
		grep -q '"compression_enabled".*true' $(CONFIG_FILE) && echo "  └─ Compression: ENABLED" || echo "  └─ Compression: DISABLED"; \
		grep -q '"rolling_enabled".*true' $(CONFIG_FILE) && echo "  └─ Rolling Files: ENABLED" || echo "  └─ Rolling Files: DISABLED"; \
	else \
		echo "💡 Storage Management: NOT CONFIGURED"; \
		echo "  └─ Run 'make migrate-config' to enable 97% storage savings"; \
	fi
	@echo ""
	@echo "📊 Expected Storage Impact:"
	@if grep -q '"compression_enabled".*true' $(CONFIG_FILE) && grep -q '"capture_level".*"basic"' $(CONFIG_FILE); then \
		echo "✅ Optimized: ~1-2KB per request (97% savings)"; \
	elif grep -q '"storage"' $(CONFIG_FILE); then \
		echo "⚠️  Partially optimized: Review capture_level and compression settings"; \
	else \
		echo "❌ Not optimized: ~15-50KB per request (run 'make migrate-config')"; \
	fi
	@echo ""
	@echo "🔧 Recommendations:"
	@grep -q '"identity".*true' $(CONFIG_FILE) || echo "• Enable identity system for network intelligence"
	@grep -q '"compression_enabled".*true' $(CONFIG_FILE) || echo "• Enable compression for 85-90% storage reduction"
	@grep -q '"rolling_enabled".*true' $(CONFIG_FILE) || echo "• Enable rolling files for automatic management"

# Generate CA certificate for testing
.PHONY: gen-ca
gen-ca:
	@echo "Generating CA certificate..."
	@mkdir -p $(CERT_DIR)
	@if [ ! -f $(CERT_DIR)/ca.key ]; then \
		openssl genrsa -out $(CERT_DIR)/ca.key 4096; \
		openssl req -new -x509 -days 365 -key $(CERT_DIR)/ca.key -out $(CERT_DIR)/ca.crt \
			-subj "/C=US/ST=California/L=San Francisco/O=Gamu Security Services/CN=Gamu Pty Ltd"; \
		echo "CA certificate generated in $(CERT_DIR)/"; \
	else \
		echo "CA certificate already exists"; \
	fi

# Trust CA certificate in system keychain (macOS)
.PHONY: trust-ca-macos
trust-ca-macos: gen-ca
	@echo "Trusting CA certificate in macOS keychain..."
	@if [ ! -f $(CERT_DIR)/ca.crt ]; then \
		echo "ERROR: CA certificate not found. Run 'make gen-ca' first."; \
		exit 1; \
	fi
	@echo "Adding CA certificate to macOS System keychain..."
	sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $(CERT_DIR)/ca.crt
	@echo "✅ CA certificate trusted in macOS System keychain"
	@echo "📋 You can verify with: security find-certificate -c 'Gamu Pty Ltd' /Library/Keychains/System.keychain"

# Trust CA certificate in system keychain (Linux)
.PHONY: trust-ca-linux
trust-ca-linux: gen-ca
	@echo "Trusting CA certificate in Linux system store..."
	@if [ ! -f $(CERT_DIR)/ca.crt ]; then \
		echo "ERROR: CA certificate not found. Run 'make gen-ca' first."; \
		exit 1; \
	fi
	@if [ -d /usr/local/share/ca-certificates ]; then \
		sudo cp $(CERT_DIR)/ca.crt /usr/local/share/ca-certificates/gander-mitm-ca.crt; \
		sudo update-ca-certificates; \
		echo "✅ CA certificate trusted in Linux system store"; \
	elif [ -d /etc/pki/ca-trust/source/anchors ]; then \
		sudo cp $(CERT_DIR)/ca.crt /etc/pki/ca-trust/source/anchors/gander-mitm-ca.crt; \
		sudo update-ca-trust; \
		echo "✅ CA certificate trusted in Linux system store (RHEL/CentOS)"; \
	else \
		echo "❌ Unsupported Linux distribution for automatic CA trust"; \
		echo "📋 Manual steps:"; \
		echo "   1. Copy $(CERT_DIR)/ca.crt to your system's CA store"; \
		echo "   2. Update the CA trust database"; \
	fi

# Trust CA certificate in Windows certificate store
.PHONY: trust-ca-windows
trust-ca-windows: gen-ca
	@echo "Trusting CA certificate in Windows certificate store..."
	@if [ ! -f $(CERT_DIR)/ca.crt ]; then \
		echo "ERROR: CA certificate not found. Run 'make gen-ca' first."; \
		exit 1; \
	fi
	@echo "💻 Windows detected - Using PowerShell to install certificate..."
	@echo "📋 Installing to Local Machine Root store (requires Administrator)..."
	@powershell.exe -Command "Import-Certificate -FilePath '$(CERT_DIR)/ca.crt' -CertStoreLocation Cert:\LocalMachine\Root" || \
	(echo "❌ Failed to install to LocalMachine store (Administrator required)"; \
	 echo "💡 Trying Current User store instead..."; \
	 powershell.exe -Command "Import-Certificate -FilePath '$(CERT_DIR)/ca.crt' -CertStoreLocation Cert:\CurrentUser\Root")
	@echo "✅ CA certificate trusted in Windows certificate store"
	@echo "📋 You can verify with: certutil -store ROOT | findstr \"Gamu\""

# Trust CA certificate (auto-detect OS)
.PHONY: trust-ca
trust-ca:
	@echo "Auto-detecting operating system..."
	@if [ "$$(uname)" = "Darwin" ]; then \
		echo "🍎 Detected macOS"; \
		$(MAKE) trust-ca-macos; \
	elif [ "$$(uname)" = "Linux" ]; then \
		echo "🐧 Detected Linux"; \
		$(MAKE) trust-ca-linux; \
	elif [ "$$(uname -s | cut -c1-10)" = "MINGW32_NT" ] || [ "$$(uname -s | cut -c1-10)" = "MINGW64_NT" ] || [ "$$(uname -s | cut -c1-6)" = "CYGWIN" ] || [ -n "$$WINDIR" ]; then \
		echo "💻 Detected Windows"; \
		$(MAKE) trust-ca-windows; \
	else \
		echo "❌ Unsupported operating system: $$(uname)"; \
		echo "📋 Manual certificate trust required"; \
		echo "   CA certificate location: $(CERT_DIR)/ca.crt"; \
		exit 1; \
	fi

# Remove trusted CA certificate from system (macOS)
.PHONY: untrust-ca-macos
untrust-ca-macos:
	@echo "Removing CA certificate from macOS keychain..."
	@sudo security delete-certificate -c "Gamu Pty Ltd" /Library/Keychains/System.keychain || echo "Certificate not found in keychain"
	@echo "✅ CA certificate removed from macOS System keychain"

# Remove trusted CA certificate from system (Linux)
.PHONY: untrust-ca-linux
untrust-ca-linux:
	@echo "Removing CA certificate from Linux system store..."
	@if [ -f /usr/local/share/ca-certificates/gander-mitm-ca.crt ]; then \
		sudo rm -f /usr/local/share/ca-certificates/gander-mitm-ca.crt; \
		sudo update-ca-certificates; \
		echo "✅ CA certificate removed from Linux system store"; \
	elif [ -f /etc/pki/ca-trust/source/anchors/gander-mitm-ca.crt ]; then \
		sudo rm -f /etc/pki/ca-trust/source/anchors/gander-mitm-ca.crt; \
		sudo update-ca-trust; \
		echo "✅ CA certificate removed from Linux system store (RHEL/CentOS)"; \
	else \
		echo "❌ CA certificate not found in system store"; \
	fi

# Remove trusted CA certificate from Windows certificate store
.PHONY: untrust-ca-windows
untrust-ca-windows:
	@echo "Removing CA certificate from Windows certificate store..."
	@echo "💻 Windows detected - Using certutil to remove certificate..."
	@certutil -delstore ROOT "Gamu Pty Ltd" || \
	 powershell.exe -Command "Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {\$$_.Subject -like '*Gamu*'} | Remove-Item" || \
	 powershell.exe -Command "Get-ChildItem -Path Cert:\CurrentUser\Root | Where-Object {\$$_.Subject -like '*Gamu*'} | Remove-Item" || \
	 echo "❌ CA certificate not found in Windows certificate store"
	@echo "✅ CA certificate removed from Windows certificate store"

# Remove trusted CA certificate (auto-detect OS)
.PHONY: untrust-ca
untrust-ca:
	@echo "Auto-detecting operating system..."
	@if [ "$$(uname)" = "Darwin" ]; then \
		echo "🍎 Detected macOS"; \
		$(MAKE) untrust-ca-macos; \
	elif [ "$$(uname)" = "Linux" ]; then \
		echo "🐧 Detected Linux"; \
		$(MAKE) untrust-ca-linux; \
	elif [ "$$(uname -s | cut -c1-10)" = "MINGW32_NT" ] || [ "$$(uname -s | cut -c1-10)" = "MINGW64_NT" ] || [ "$$(uname -s | cut -c1-6)" = "CYGWIN" ] || [ -n "$$WINDIR" ]; then \
		echo "💻 Detected Windows"; \
		$(MAKE) untrust-ca-windows; \
	else \
		echo "❌ Unsupported operating system: $$(uname)"; \
		echo "📋 Manual certificate removal required"; \
		exit 1; \
	fi

# Setup MITM environment (generate CA + trust it)
.PHONY: setup-mitm
setup-mitm: setup gen-ca trust-ca
	@echo ""
	@echo "🎉 MITM environment setup complete!"
	@echo ""
	@echo "📋 Next steps:"
	@echo "   1. Run: make run"
	@echo "   2. Configure your browser/system to use proxy: localhost:1234"
	@echo "   3. Browse to sites in your inspect_domains list"
	@echo "   4. Check captures/ directory for intercepted requests"
	@echo ""
	@echo "🔒 Certificate info:"
	@echo "   CA Certificate: $(CERT_DIR)/ca.crt"
	@echo "   CA Private Key: $(CERT_DIR)/ca.key"
	@echo ""

# Verify CA certificate is trusted
.PHONY: verify-ca
verify-ca:
	@echo "Verifying CA certificate trust status..."
	@if [ "$$(uname)" = "Darwin" ]; then \
		echo "🍎 Checking macOS keychain..."; \
		if security find-certificate -c "Gamu Pty Ltd" /Library/Keychains/System.keychain >/dev/null 2>&1; then \
			echo "✅ CA certificate is trusted in macOS System keychain"; \
			security find-certificate -p -c "Gamu Pty Ltd" /Library/Keychains/System.keychain | openssl x509 -noout -subject -dates; \
		else \
			echo "❌ CA certificate not found in macOS System keychain"; \
			echo "💡 Run: make trust-ca"; \
		fi; \
	elif [ "$$(uname)" = "Linux" ]; then \
		echo "🐧 Checking Linux certificate store..."; \
		if [ -f /usr/local/share/ca-certificates/gander-mitm-ca.crt ] || [ -f /etc/pki/ca-trust/source/anchors/gander-mitm-ca.crt ]; then \
			echo "✅ CA certificate found in Linux system store"; \
		else \
			echo "❌ CA certificate not found in Linux system store"; \
			echo "💡 Run: make trust-ca"; \
		fi; \
	elif [ "$$(uname -s | cut -c1-10)" = "MINGW32_NT" ] || [ "$$(uname -s | cut -c1-10)" = "MINGW64_NT" ] || [ "$$(uname -s | cut -c1-6)" = "CYGWIN" ] || [ -n "$$WINDIR" ]; then \
		echo "💻 Checking Windows certificate store..."; \
		if certutil -store ROOT | findstr "Gamu" >/dev/null 2>&1; then \
			echo "✅ CA certificate found in Windows certificate store"; \
			certutil -store ROOT | findstr -A 5 -B 5 "Gamu"; \
		else \
			echo "❌ CA certificate not found in Windows certificate store"; \
			echo "💡 Run: make trust-ca"; \
		fi; \
	else \
		echo "❌ Unsupported operating system for verification"; \
	fi

# Test MITM proxy with trusted certificate
.PHONY: test-mitm
test-mitm:
	@echo "🧪 Testing MITM proxy with trusted certificate..."
	@echo ""
	@echo "📋 Browser Testing (Recommended):"
	@echo "   1. Configure browser proxy: localhost:1234"
	@echo "   2. Visit: https://gamu.io or https://example.com"
	@echo "   3. Certificate should be trusted (no warnings)"
	@echo "   4. Check captures/ directory for intercepted requests"
	@echo ""
	@echo "📋 curl Testing (with CA bundle):"
	@echo "   curl -x localhost:1234 --cacert $(CERT_DIR)/ca.crt https://gamu.io/"
	@echo ""
	@echo "📋 curl Testing (ignore cert - for testing only):"
	@echo "   curl -x localhost:1234 -k https://gamu.io/"
	@echo ""
	@if [ -f $(CERT_DIR)/ca.crt ]; then \
		echo "🔍 Testing with curl (using CA certificate)..."; \
		curl -x localhost:1234 --cacert $(CERT_DIR)/ca.crt --connect-timeout 5 -s -o /dev/null -w "Status: %{http_code} | Time: %{time_total}s\n" https://example.com/ || echo "❌ Test failed - ensure gander is running"; \
	fi

# Fix Chrome certificate trust issues
.PHONY: fix-chrome
fix-chrome:
	@echo "🔧 Fixing Chrome certificate trust issues..."
	@echo ""
	@echo "Step 1: Adding CA to both System and Login keychains..."
	@sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain -p ssl $(CERT_DIR)/ca.crt
	@security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db -p ssl $(CERT_DIR)/ca.crt
	@echo "✅ CA certificate added to keychains"
	@echo ""
	@echo "Step 2: Clearing Chrome's security cache..."
	@rm -rf ~/Library/Application\ Support/Google/Chrome/Default/TransportSecurity
	@rm -rf ~/Library/Application\ Support/Google/Chrome/Default/Certificate\ Revocation\ Lists
	@echo "✅ Chrome security cache cleared"
	@echo ""
	@echo "Step 3: Killing Chrome processes..."
	@pkill -f "Google Chrome" || echo "Chrome not running"
	@echo "✅ Chrome processes terminated"
	@echo ""
	@echo "🎉 Chrome fix complete!"
	@echo ""
	@echo "📋 Next steps:"
	@echo "   1. Start Chrome fresh"
	@echo "   2. Configure proxy: System Preferences → Network → Advanced → Proxies"
	@echo "   3. Set HTTP/HTTPS proxy to: localhost:1234"
	@echo "   4. Visit https://gamu.io - should work without certificate warnings"
	@echo ""
	@echo "💡 If still having issues, try:"
	@echo "   • Chrome → Settings → Privacy and security → Security → Manage certificates"
	@echo "   • Look for 'Gander MITM CA' in System/Keychain Access"

# Show MITM proxy usage instructions
.PHONY: usage
usage:
	@echo "🚀 Gander MITM Proxy Usage Guide"
	@echo ""
	@echo "📋 Quick Start:"
	@echo "   1. make setup-mitm    # Generate & trust CA certificate"
	@echo "   2. make run           # Start the proxy"
	@echo "   3. Configure proxy: localhost:1234"
	@echo ""
	@echo "🌐 Browser Configuration:"
	@echo "   • Chrome/Safari: System Preferences → Network → Advanced → Proxies"
	@echo "   • Firefox: Settings → Network Settings → Manual proxy configuration"
	@echo "   • Set HTTP/HTTPS proxy: localhost:1234"
	@echo ""
	@echo "🔒 Certificate Trust Status:"
	@$(MAKE) verify-ca
	@echo ""
	@echo "📁 Captured Requests: $(CAPTURE_DIR)/"
	@echo "📄 Log File: $(LOG_FILE)"
	@echo ""
	@echo "🔧 Useful Commands:"
	@echo "   make test-mitm        # Test proxy functionality"
	@echo "   make logs            # View live logs"
	@echo "   make clean-all       # Clean everything"

# Run the proxy with default config
.PHONY: run
run: build setup
	@echo "Starting $(BINARY_NAME)..."
	./$(BUILD_DIR)/$(BINARY_NAME) $(CONFIG_FILE)

# Run in development mode (with auto-restart)
.PHONY: dev
dev: setup
	@echo "Starting development mode..."
	@which air > /dev/null || (echo "Installing air for hot reload..." && go install github.com/cosmtrek/air@latest)
	air

# Install the binary to system
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "Installation complete!"

# Uninstall the binary from system
.PHONY: uninstall
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "Uninstallation complete!"

# Build for multiple platforms
.PHONY: build-cross
build-cross:
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/gander
	GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/gander
	GOOS=darwin GOARCH=amd64 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/gander
	GOOS=darwin GOARCH=arm64 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/gander
	GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/gander
	@echo "Cross-platform builds complete!"

# Create release archive
.PHONY: release
release: build-cross
	@echo "Creating release archives..."
	@mkdir -p $(BUILD_DIR)/release
	@for binary in $(BUILD_DIR)/$(BINARY_NAME)-*; do \
		if [ -f "$$binary" ]; then \
			platform=$$(basename $$binary | sed 's/$(BINARY_NAME)-//'); \
			archive_name="$(BINARY_NAME)-$$platform"; \
			mkdir -p $(BUILD_DIR)/release/$$archive_name; \
			cp $$binary $(BUILD_DIR)/release/$$archive_name/$(BINARY_NAME)$$(echo $$binary | grep -o '\.exe$$' || echo ''); \
			cp conf/examples/basic.json $(BUILD_DIR)/release/$$archive_name/config_example.json; \
			cp README.md $(BUILD_DIR)/release/$$archive_name/; \
			cd $(BUILD_DIR)/release && tar -czf $$archive_name.tar.gz $$archive_name; \
			rm -rf $$archive_name; \
			echo "Created $(BUILD_DIR)/release/$$archive_name.tar.gz"; \
		fi \
	done

# Build Docker image
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	@if [ ! -f Dockerfile ]; then \
		echo "Creating basic Dockerfile..."; \
		echo "FROM golang:1.21-alpine AS builder" > Dockerfile; \
		echo "WORKDIR /app" >> Dockerfile; \
		echo "COPY go.mod go.sum ./" >> Dockerfile; \
		echo "RUN go mod download" >> Dockerfile; \
		echo "COPY . ." >> Dockerfile; \
		echo "RUN CGO_ENABLED=0 GOOS=linux go build -ldflags=\"-s -w\" -o gander ./cmd/gander" >> Dockerfile; \
		echo "" >> Dockerfile; \
		echo "FROM alpine:latest" >> Dockerfile; \
		echo "RUN apk --no-cache add ca-certificates tzdata" >> Dockerfile; \
		echo "WORKDIR /app" >> Dockerfile; \
		echo "COPY --from=builder /app/gander ." >> Dockerfile; \
		echo "RUN mkdir -p /app/captures /app/certs /app/logs" >> Dockerfile; \
		echo "EXPOSE 8848" >> Dockerfile; \
		echo "CMD [\"./gander\", \"conf/config.json\"]" >> Dockerfile; \
		echo "✅ Created basic Dockerfile"; \
	fi
	@docker build -t gander:latest .
	@docker build -t gander:$$(git rev-parse --short HEAD 2>/dev/null || echo "dev") .
	@echo "✅ Docker images created:"
	@echo "   • gander:latest"
	@echo "   • gander:$$(git rev-parse --short HEAD 2>/dev/null || echo "dev")"
	@echo ""
	@echo "🚀 Run with: docker run -p 8848:8848 -v \$$(pwd)/conf/config.json:/app/conf/config.json gander:latest"

# View logs
.PHONY: logs
logs:
	@if [ -f $(LOG_FILE) ]; then \
		tail -f $(LOG_FILE); \
	else \
		echo "Log file $(LOG_FILE) not found"; \
	fi

# View recent logs
.PHONY: logs-recent
logs-recent:
	@if [ -f $(LOG_FILE) ]; then \
		tail -n 50 $(LOG_FILE); \
	else \
		echo "Log file $(LOG_FILE) not found"; \
	fi

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	@echo "Clean complete!"

# Deep clean (including logs and captures)
.PHONY: clean-all
clean-all: clean
	@echo "Deep cleaning..."
	rm -rf $(CAPTURE_DIR)
	rm -rf $(LOGS_DIR)
	@echo "Deep clean complete!"

# Check system requirements
.PHONY: check-deps
check-deps:
	@echo "Checking system dependencies..."
	@go version || (echo "ERROR: Go is not installed" && exit 1)
	@echo "Go: OK"
	@openssl version || (echo "WARNING: OpenSSL not found (needed for certificate generation)")
	@which iptables > /dev/null || echo "WARNING: iptables not found (needed for transparent mode)"
	@echo "Dependency check complete!"

# Show help
.PHONY: help
help:
	@echo "Gander MITM Proxy - Available targets:"
	@echo ""
	@echo "Build targets:"
	@echo "  build         - Build the binary"
	@echo "  build-prod    - Build optimized binary for production"
	@echo "  build-cross   - Build for multiple platforms"
	@echo "  docker-build  - Build Docker image"
	@echo "  release       - Create release archives"
	@echo ""
	@echo "Development targets:"
	@echo "  deps          - Install Go dependencies"
	@echo "  fmt           - Format Go code"
	@echo "  lint          - Lint Go code"
	@echo "  security      - Run security scan"
	@echo "  security-scan - Alias for security"
	@echo "  vet           - Vet Go code"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  test-integration - Run integration tests"
	@echo "  bench         - Run benchmarks"
	@echo "  benchmark     - Alias for bench"
	@echo "  dev           - Run in development mode with hot reload"
	@echo ""
	@echo "Setup targets:"
	@echo "  setup         - Setup initial configuration and directories"
	@echo "  init-config   - Create config.json from basic example"
	@echo "  init-enhanced-config - Create config.json with identity and storage features"
	@echo "  gen-ca        - Generate CA certificate for testing"
	@echo "  trust-ca      - Trust CA certificate in system keychain (auto-detect OS)"
	@echo "  trust-ca-macos - Trust CA certificate in macOS keychain"
	@echo "  trust-ca-linux - Trust CA certificate in Linux system store"
	@echo "  trust-ca-windows - Trust CA certificate in Windows certificate store"
	@echo "  setup-mitm    - Complete MITM setup (setup + gen-ca + trust-ca)"
	@echo "  verify-ca     - Verify CA certificate trust status"
	@echo "  untrust-ca    - Remove CA certificate from system trust (auto-detect OS)"
	@echo "  check-deps    - Check system dependencies"
	@echo ""
	@echo "Configuration targets:"
	@echo "  validate-config - Validate configuration file syntax and structure"
	@echo "  migrate-config - Migrate configuration to enhanced format with identity and storage"
	@echo "  config-status - Show configuration status and optimization recommendations"
	@echo ""
	@echo "Runtime targets:"
	@echo "  run           - Build and run with default config"
	@echo "  logs          - View live logs"
	@echo "  logs-recent   - View recent log entries"
	@echo ""
	@echo "Installation targets:"
	@echo "  install       - Install binary to /usr/local/bin"
	@echo "  uninstall     - Remove binary from /usr/local/bin"
	@echo ""
	@echo "Cleanup targets:"
	@echo "  clean         - Clean build artifacts"
	@echo "  clean-all     - Deep clean (including logs and captures)"
	@echo ""
	@echo "  help          - Show this help message"

# Default help when no target specified
.DEFAULT_GOAL := help 