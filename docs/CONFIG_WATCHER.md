# Config File Watcher

Gander includes a real-time configuration file watcher that automatically reloads the proxy settings when the config file changes. This feature allows you to modify the proxy behavior without restarting the server.

## Features

- **Real-time monitoring**: Automatically detects changes to the configuration file
- **Hot reloading**: Updates proxy settings without interrupting active connections
- **Debounced updates**: Prevents rapid reloads from multiple file writes (2-second debounce)
- **Error handling**: Reverts to previous config if reload fails
- **Comprehensive logging**: Logs all reload attempts and results

## What Gets Reloaded

The config watcher can reload the following settings:

### Filter Rules
- Inspect domains list (`rules.inspect_domains`)
- Bypass domains list (`rules.bypass_domains`) 
- Inspect source IPs (`rules.inspect_source_ips`)
- Bypass source IPs (`rules.bypass_source_ips`)

### Certificate Settings
- Certificate details (`tls.custom_details`)
- Upstream certificate sniffing (`tls.upstream_cert_sniff`)
- Certificate validity period (`tls.valid_days`)

### Logging Settings
- Debug mode (`logging.enable_debug`)
- Capture directory (`logging.capture_dir`)

## Usage

The config watcher starts automatically when you run Gander:

```bash
./build/gander config.json
```

You'll see a log message indicating the watcher has started:

```
2025/06/25 14:33:01 Config watcher started for file: /path/to/config.json
```

## Making Configuration Changes

Simply edit your `config.json` file and save it. The changes will be applied automatically:

```bash
# Edit the config file
nano config.json

# Changes are applied automatically - no restart needed!
```

## Example Log Output

When you modify the config file, you'll see logs like this:

```
2025/06/25 14:33:15 Config file changed, reloading...
2025/06/25 14:33:15 Reloading server configuration...
2025/06/25 14:33:15 Reloaded filter provider 'domain'
2025/06/25 14:33:15 Reloaded filter provider 'ip'
2025/06/25 14:33:15 Server configuration reloaded successfully
2025/06/25 14:33:15 Configuration successfully reloaded
```

## Testing the Config Watcher

Use the included test script to see the config watcher in action:

```bash
./test_config_watcher.sh
```

This script will:
1. Start the proxy with config watching
2. Make several configuration changes
3. Show the real-time reload messages
4. Restore the original configuration

## Technical Details

### File Watching Implementation
- Uses the `fsnotify` library for cross-platform file system events
- Monitors `WRITE` events on the config file
- Ignores temporary files created by editors

### Debouncing
- 2-second debounce period to handle editors that write files multiple times
- Only the final write event triggers a reload

### Error Handling
- Configuration validation before applying changes
- Automatic rollback to previous config if reload fails
- Detailed error logging for troubleshooting

### Thread Safety
- All config updates are thread-safe
- Uses proper locking to prevent race conditions
- Active connections continue uninterrupted during reloads

## Limitations

### Settings That Require Restart
Some settings cannot be hot-reloaded and require a full restart:

- Listen address (`proxy.listen_addr`)
- TLS certificate files (`tls.cert_file`, `tls.key_file`, `tls.ca_file`)
- Buffer sizes (`proxy.buffer_size`)

### File System Considerations
- The config file must be writable by the user running Gander
- Network file systems may have delayed or missed events
- Some editors create temporary files that are ignored

## Troubleshooting

### Config Watcher Not Starting
```
Failed to create config watcher: permission denied
```
- Check file permissions on the config file and directory
- Ensure the user has read access to the config file

### Reload Failures
```
Failed to reload config: validation error
```
- Check the config file syntax with `jq . config.json`
- Review the error message for specific validation issues
- The previous config remains active on failure

### Missing Reload Events
- Some editors use atomic writes that may not trigger events
- Try touching the file: `touch config.json`
- Check if your editor creates backup files

## Best Practices

1. **Test changes**: Use the test script to verify config watcher functionality
2. **Validate JSON**: Check syntax before saving: `jq . config.json`
3. **Monitor logs**: Watch the proxy logs when making changes
4. **Gradual changes**: Make one change at a time for easier troubleshooting
5. **Backup configs**: Keep known-good configurations for quick rollback

## Security Considerations

- Config file changes are logged for audit purposes
- Failed reload attempts are logged with error details
- Only the file owner should have write access to the config file
- Consider using file system monitoring tools for additional security 