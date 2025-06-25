#!/bin/bash

# Test script for config file watcher functionality

echo "=== Config File Watcher Test ==="
echo "This script demonstrates real-time config reloading"
echo

# Make sure we have a CA certificate
if [ ! -f "certs/ca.crt" ]; then
    echo "Generating CA certificate..."
    make gen-ca
fi

# Start the proxy in the background
echo "Starting Gander proxy with config watching..."
./build/gander config.json &
PROXY_PID=$!

# Give the proxy time to start
sleep 3

echo "Proxy started with PID: $PROXY_PID"
echo "Watching for config changes..."
echo

# Function to cleanup on exit
cleanup() {
    echo "Stopping proxy..."
    kill $PROXY_PID 2>/dev/null
    wait $PROXY_PID 2>/dev/null
    echo "Test completed."
}

trap cleanup EXIT

# Make a backup of the original config
cp config.json config.json.backup

echo "=== Test 1: Adding a new domain to inspect list ==="
echo "Original config has these inspect domains:"
grep -A 10 "inspect_domains" config.json | head -8

echo
echo "Adding 'test.example.com' to inspect domains..."

# Use jq to add a new domain to the inspect list
if command -v jq >/dev/null 2>&1; then
    jq '.rules.inspect_domains += ["test.example.com"]' config.json > config.json.tmp && mv config.json.tmp config.json
else
    # Fallback if jq is not available
    sed 's/"www.youtube.com"/"www.youtube.com", "test.example.com"/' config.json > config.json.tmp && mv config.json.tmp config.json
fi

echo "Config updated! Check the proxy logs above for reload messages."
sleep 3

echo
echo "=== Test 2: Changing debug setting ==="
echo "Current debug setting:"
grep "enable_debug" config.json

echo
echo "Toggling debug setting..."

if grep -q '"enable_debug": true' config.json; then
    sed 's/"enable_debug": true/"enable_debug": false/' config.json > config.json.tmp && mv config.json.tmp config.json
    echo "Debug disabled"
else
    sed 's/"enable_debug": false/"enable_debug": true/' config.json > config.json.tmp && mv config.json.tmp config.json
    echo "Debug enabled"
fi

echo "Config updated! Check the proxy logs above for reload messages."
sleep 3

echo
echo "=== Test 3: Changing certificate details ==="
echo "Updating certificate common name..."

if command -v jq >/dev/null 2>&1; then
    jq '.tls.custom_details.common_name = "Updated Gamu Safe Browsing"' config.json > config.json.tmp && mv config.json.tmp config.json
else
    sed 's/"Gamu Safe Browsing"/"Updated Gamu Safe Browsing"/' config.json > config.json.tmp && mv config.json.tmp config.json
fi

echo "Certificate config updated! Check the proxy logs above for reload messages."
sleep 3

echo
echo "=== Restoring original config ==="
mv config.json.backup config.json
echo "Original config restored! Check the proxy logs above for final reload."

sleep 2
echo
echo "Test completed. The proxy will be stopped now." 