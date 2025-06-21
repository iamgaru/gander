# Makefile for Gander MITM Proxy

# Variables
BINARY_NAME=gander
CONFIG_FILE=config.json
BUILD_DIR=build
CERT_DIR=certs
CAPTURE_DIR=captures
LOG_FILE=proxy.log

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
	go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .

# Build for production (optimized)
.PHONY: build-prod
build-prod:
	@echo "Building $(BINARY_NAME) for production..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .

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
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

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
	@echo "Setup complete!"

# Generate CA certificate for testing
.PHONY: gen-ca
gen-ca:
	@echo "Generating CA certificate..."
	@mkdir -p $(CERT_DIR)
	@if [ ! -f $(CERT_DIR)/ca.key ]; then \
		openssl genrsa -out $(CERT_DIR)/ca.key 4096; \
		openssl req -new -x509 -days 365 -key $(CERT_DIR)/ca.key -out $(CERT_DIR)/ca.crt \
			-subj "/C=US/ST=CA/L=San Francisco/O=Gander Proxy/CN=Gander Proxy CA"; \
		echo "CA certificate generated in $(CERT_DIR)/"; \
	else \
		echo "CA certificate already exists"; \
	fi

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
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 .
	GOOS=darwin GOARCH=amd64 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 .
	GOOS=windows GOARCH=amd64 go build $(BUILD_FLAGS) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe .
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
	rm -f coverage.out coverage.html
	@echo "Clean complete!"

# Deep clean (including logs and captures)
.PHONY: clean-all
clean-all: clean
	@echo "Deep cleaning..."
	rm -rf $(CAPTURE_DIR)
	rm -f $(LOG_FILE)
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
	@echo "  vet           - Vet Go code"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage report"
	@echo "  dev           - Run in development mode with hot reload"
	@echo ""
	@echo "Setup targets:"
	@echo "  setup         - Setup initial configuration and directories"
	@echo "  gen-ca        - Generate CA certificate for testing"
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