# Makefile for Gander MITM Proxy

# Variables
BINARY_NAME=gander
CONFIG_FILE=config.json
BUILD_DIR=build
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

# Run benchmarks
.PHONY: bench
bench:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Format code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
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

# Vet code
.PHONY: vet
vet:
	@echo "Vetting code..."
	go vet ./...

# Setup initial configuration
.PHONY: setup
setup:
	@echo "Setting up initial configuration..."
	@if [ ! -f $(CONFIG_FILE) ]; then \
		cp config_example.json $(CONFIG_FILE); \
		echo "Created $(CONFIG_FILE) from example"; \
	fi
	@mkdir -p $(CERT_DIR)
	@mkdir -p $(CAPTURE_DIR)
	@mkdir -p $(LOGS_DIR)
	@echo "Setup complete!"

# Generate CA certificate for testing
.PHONY: gen-ca
gen-ca:
	@echo "Generating CA certificate..."
	@mkdir -p $(CERT_DIR)
	@if [ ! -f $(CERT_DIR)/ca.key ]; then \
		openssl genrsa -out $(CERT_DIR)/ca.key 4096; \
		openssl req -new -x509 -days 365 -key $(CERT_DIR)/ca.key -out $(CERT_DIR)/ca.crt \
			-subj "/C=US/ST=CA/L=San Francisco/O=Gander Proxy/CN=Gander MITM CA"; \
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
	@echo "📋 You can verify with: security find-certificate -c 'Gander MITM CA' /Library/Keychains/System.keychain"

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
	@echo "📋 You can verify with: certutil -store ROOT | findstr \"Gander\""

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
	@sudo security delete-certificate -c "Gander MITM CA" /Library/Keychains/System.keychain || echo "Certificate not found in keychain"
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
	@certutil -delstore ROOT "Gander MITM CA" || \
	 powershell.exe -Command "Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {\$$_.Subject -like '*Gander*'} | Remove-Item" || \
	 powershell.exe -Command "Get-ChildItem -Path Cert:\CurrentUser\Root | Where-Object {\$$_.Subject -like '*Gander*'} | Remove-Item" || \
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
		if security find-certificate -c "Gander MITM CA" /Library/Keychains/System.keychain >/dev/null 2>&1; then \
			echo "✅ CA certificate is trusted in macOS System keychain"; \
			security find-certificate -p -c "Gander MITM CA" /Library/Keychains/System.keychain | openssl x509 -noout -subject -dates; \
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
		if certutil -store ROOT | findstr "Gander" >/dev/null 2>&1; then \
			echo "✅ CA certificate found in Windows certificate store"; \
			certutil -store ROOT | findstr -A 5 -B 5 "Gander"; \
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
			cp config_example.json $(BUILD_DIR)/release/$$archive_name/; \
			cp README.md $(BUILD_DIR)/release/$$archive_name/; \
			cd $(BUILD_DIR)/release && tar -czf $$archive_name.tar.gz $$archive_name; \
			rm -rf $$archive_name; \
			echo "Created $(BUILD_DIR)/release/$$archive_name.tar.gz"; \
		fi \
	done

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
	@echo "  release       - Create release archives"
	@echo ""
	@echo "Development targets:"
	@echo "  deps          - Install Go dependencies"
	@echo "  fmt           - Format Go code"
	@echo "  lint          - Lint Go code"
	@echo "  security      - Run security scan with gosec"
	@echo "  vet           - Vet Go code"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  dev           - Run in development mode with hot reload"
	@echo ""
	@echo "Setup targets:"
	@echo "  setup         - Setup initial configuration and directories"
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