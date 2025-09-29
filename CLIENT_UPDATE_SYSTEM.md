# Client Update System

## Overview

The Client Update System allows you to push software updates to pfSense firewall clients remotely via the AI console. This automates the distribution process that was previously done manually with `distribute.py`.

## Features

- **AI Console Integration**: Update clients using natural language commands
- **Automated Bundle Creation**: Creates fresh client bundles with latest code
- **Remote Deployment**: Uploads and deploys via SSH automatically
- **Service Management**: Stops old client, installs new files, restarts service
- **Progress Monitoring**: Track update status and completion
- **Force Restart Option**: Option to force restart even if update fails

## Usage

### AI Console Commands

You can now use natural language commands in the AI console to update clients:

```
update opus-1
push client update to opus-1
update client software on opus-1
update opus-1 with force restart
```

### Programmatic Usage

```python
from ai_command_center import AICommandCenter

ai_center = AICommandCenter(hq_url, openai_api_key)

# Basic update
result = await ai_center.update_client("opus-1")

# Update with force restart
result = await ai_center.update_client("opus-1", force_restart=True)
```

## System Architecture

### Components

1. **AICommandCenter** (`hq/ai_command_center.py`)
   - New `update_client()` function tool
   - Handles AI function calls for client updates
   - Resolves client names to IDs

2. **ClientUpdater** (`hq/client_updater.py`)
   - Creates client bundles using existing `make_client_bundle.bat`
   - Manages SSH connections and file uploads
   - Executes remote deployment scripts

3. **HTTP Server** (`hq/http_server.py`)
   - Special handling for `update_client` commands
   - Executes updates server-side instead of client-side
   - Tracks command status and progress

### Update Process Flow

1. **Command Initiation**: AI console receives update request
2. **Bundle Creation**: Creates fresh ZIP with latest client files
3. **Command Storage**: Stores update command in database
4. **Server Execution**: HTTP server executes update immediately
5. **SSH Upload**: Uploads bundle and deployment script via SCP
6. **Remote Deployment**: Executes deployment script on pfSense
7. **Service Restart**: Stops old client, installs new files, starts client
8. **Status Update**: Updates command status with results

## Files Updated

### Core Implementation
- `hq/ai_command_center.py` - Added `update_client` function tool and method
- `hq/http_server.py` - Added special handling for update_client commands
- `hq/client_updater.py` - New module for client update logic

### Client Files Deployed
- `client/pfsense_client.py` - Main client script
- `client/psutil_stub.py` - FreeBSD compatibility stub
- `config/client_config.yaml` - Client configuration template
- `restart_client.sh` - Client restart script

## Configuration

### SSH Connection
Currently uses hardcoded connection info:
- Host: `103.26.150.122` (pfSense IP)
- User: `root`
- Password: From `secrets.txt`

### Bundle Contents
The system uses the existing bundle creation process:
- Runs `make_client_bundle.bat`
- Creates timestamped ZIP files in `dist/`
- Includes all necessary client files and scripts

## Security Considerations

- **SSH Authentication**: Uses password authentication (consider key-based auth)
- **File Permissions**: Sets appropriate permissions on deployed files
- **Service Management**: Properly stops/starts services to avoid conflicts
- **Cleanup**: Removes temporary files after deployment

## Error Handling

- **Bundle Creation Failures**: Reports if bundle creation fails
- **SSH Connection Issues**: Handles connection timeouts and auth failures
- **Deployment Errors**: Captures and reports remote script execution errors
- **Client Resolution**: Validates client exists before attempting update

## Monitoring

### Command Status
Check update progress via HTTP API:
```bash
curl "http://localhost:8000/command/status?command_id=<command_id>"
```

### Response Format
```json
{
  "command_id": "uuid",
  "client_id": "client_id",
  "command_type": "update_client",
  "status": "completed|failed|in_progress",
  "progress": {
    "success": true,
    "message": "Client updated successfully",
    "output": "deployment script output"
  }
}
```

## Testing

### Test Scripts
- `test_client_update.py` - Tests AI Command Center integration
- `test_client_updater.py` - Tests ClientUpdater functionality
- `test_complete_update_workflow.py` - End-to-end workflow test

### Manual Testing
1. Start HQ server: `python hq/http_server.py`
2. Use AI console: "update opus-1"
3. Monitor command status via API
4. Verify client reconnects with updated code

## Troubleshooting

### Common Issues

1. **Bundle Creation Fails**
   - Ensure `make_client_bundle.bat` exists and is executable
   - Check PowerShell execution policy
   - Verify all source files exist

2. **SSH Connection Fails**
   - Verify pfSense IP and credentials
   - Check network connectivity
   - Ensure SSH is enabled on pfSense

3. **Deployment Script Fails**
   - Check pfSense Python installation
   - Verify file permissions
   - Review deployment script output

4. **Client Doesn't Restart**
   - Check pfSense logs: `tail -f /var/log/pfsense_client.log`
   - Verify configuration file exists
   - Check Python dependencies

### Debug Commands
```bash
# Check client status
ssh root@103.26.150.122 "ps aux | grep pfsense_client"

# View client logs
ssh root@103.26.150.122 "tail -f /var/log/pfsense_client.log"

# Manual restart
ssh root@103.26.150.122 "/usr/local/bin/restart_client.sh"
```

## Future Enhancements

- **Key-based SSH Authentication**: Replace password auth with SSH keys
- **Multiple Client Support**: Update multiple clients simultaneously
- **Rollback Capability**: Ability to rollback to previous version
- **Configuration Management**: Update client configurations remotely
- **Health Checks**: Verify client health after updates
- **Scheduled Updates**: Automatic updates on schedule
