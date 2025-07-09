#!/usr/bin/env python3
"""
Gander Configuration Migration Script
Migrates basic configuration to enhanced format with identity and storage features.
"""

import json
import sys
import os
from pathlib import Path

def migrate_config(config_file):
    """Migrate configuration to enhanced format"""
    
    # Load existing config
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"❌ Configuration file {config_file} not found")
        return False
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON in {config_file}: {e}")
        return False
    
    # Track what we add
    identity_added = False
    storage_added = False
    
    # Add identity system if not present
    if 'identity' not in config:
        config['identity'] = {
            'enabled': True,
            'enabled_providers': ['ip_mac'],
            'cache_ttl': '1h',
            'provider_configs': {
                'ip_mac': {
                    'arp_scan_interval': '5m',
                    'trusted_networks': ['192.168.0.0/16', '10.0.0.0/8']
                }
            }
        }
        identity_added = True
        print('✅ Added identity system configuration')
    else:
        print('✅ Identity system already configured')
    
    # Add storage management if not present
    if 'storage' not in config:
        config['storage'] = {
            'compression_enabled': True,
            'compression_format': 'gzip',
            'rolling_enabled': True,
            'max_file_size': 52428800,  # 50MB
            'capture_level': 'basic',
            'retention_period': '720h',  # 30 days
            'organization_scheme': 'domain'
        }
        storage_added = True
        print('✅ Added storage management configuration')
    else:
        print('✅ Storage management already configured')
    
    # Write updated config
    try:
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        print('✅ Configuration migration complete')
        return True
    except Exception as e:
        print(f'❌ Failed to write configuration: {e}')
        return False

def main():
    if len(sys.argv) != 2:
        print("Usage: migrate_config.py <config_file>")
        sys.exit(1)
    
    config_file = sys.argv[1]
    
    if not migrate_config(config_file):
        sys.exit(1)

if __name__ == '__main__':
    main() 