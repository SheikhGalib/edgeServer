# IoT Edge Server

A lightweight WebSocket-based server that runs on edge devices (Raspberry Pi, Orange Pi, etc.) to provide real-time system monitoring, terminal access, and file management capabilities.

## Features

- 🖥️ **Real-time System Monitoring**: CPU, RAM, disk usage, temperature, network stats
- 💻 **Terminal Access**: Interactive terminal sessions via WebSocket
- 📁 **File Management**: Browse, read, and write files remotely
- 🚀 **Command Execution**: Execute shell commands remotely
- 📊 **Live Statistics**: Broadcast system stats to connected clients
- 🔒 **Safe Path Access**: Restricted file system access for security

## Quick Start

### 1. Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd edgeServer

# Install dependencies
pip install -r requirements.txt
```

### 2. Running on Raspberry Pi / Orange Pi

```bash
# Basic usage
python edge_server.py --device-id "raspberry-pi-living-room"

# Custom configuration
python edge_server.py \
    --device-id "my-edge-device" \
    --host 0.0.0.0 \
    --port 8080 \
    --stats-interval 5 \
    --log-level INFO
```

### 3. Running as a Service (Systemd)

Create a service file: `/etc/systemd/system/edge-server.service`

```ini
[Unit]
Description=IoT Edge Server
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/IoTdeviceManagment/edgeServer
ExecStart=/usr/bin/python3 edge_server.py --device-id raspberry-pi-main
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl enable edge-server
sudo systemctl start edge-server
sudo systemctl status edge-server
```

### 4. Auto-start Script for Raspberry Pi

Create `/home/pi/start_edge_server.sh`:

```bash
#!/bin/bash
cd /home/pi/IoTdeviceManagment/edgeServer
python3 edge_server.py --device-id "$(hostname)" --port 8080
```

Make it executable and add to startup:

```bash
chmod +x /home/pi/start_edge_server.sh
echo "@reboot /home/pi/start_edge_server.sh" | crontab -
```

## Configuration

### Command Line Arguments

- `--device-id` (required): Unique identifier for the device
- `--host` (default: 0.0.0.0): Host address to bind to
- `--port` (default: 8080): Port number to listen on
- `--stats-interval` (default: 10): How often to broadcast stats (seconds)
- `--log-level` (default: INFO): Logging level (DEBUG, INFO, WARNING, ERROR)

### Environment Variables

```bash
export EDGE_DEVICE_ID="my-device"
export EDGE_HOST="0.0.0.0"
export EDGE_PORT="8080"
export EDGE_STATS_INTERVAL="10"
```

## WebSocket API

### Client Connection

```javascript
const ws = new WebSocket("ws://raspberry-pi-ip:8080");

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log("Received:", data);
};
```

### Message Types

#### 1. Get System Statistics

```javascript
ws.send(JSON.stringify({
    type: 'get_system_stats'
}));

// Response:
{
    type: 'get_system_stats_response',
    device_id: 'raspberry-pi-main',
    data: {
        timestamp: '2025-10-08T14:30:00.000Z',
        cpu_usage: 25.5,
        memory: {
            total: 4147462144,
            available: 2987654144,
            used: 1159808000,
            percentage: 28.0
        },
        disk: {
            total: 62725623808,
            used: 15234567890,
            free: 47491055918,
            percentage: 24.3
        },
        temperature: {
            cpu_thermal: 45.2
        },
        // ... more stats
    }
}
```

#### 2. Terminal Operations

```javascript
// Create terminal session
ws.send(
  JSON.stringify({
    type: "terminal_create",
  })
);

// Execute command
ws.send(
  JSON.stringify({
    type: "terminal_execute",
    session_id: "session-uuid",
    command: "ls -la",
  })
);

// Close session
ws.send(
  JSON.stringify({
    type: "terminal_close",
    session_id: "session-uuid",
  })
);
```

#### 3. File Operations

```javascript
// List directory
ws.send(
  JSON.stringify({
    type: "file_list",
    path: "/home/pi",
  })
);

// Read file
ws.send(
  JSON.stringify({
    type: "file_read",
    path: "/home/pi/script.py",
  })
);

// Write file
ws.send(
  JSON.stringify({
    type: "file_write",
    path: "/home/pi/new_file.txt",
    content: "Hello, World!",
  })
);
```

#### 4. Execute Command

```javascript
ws.send(
  JSON.stringify({
    type: "execute_command",
    command: "uptime",
  })
);
```

### Auto-broadcast Events

The server automatically broadcasts system statistics every N seconds:

```javascript
// Automatic broadcast (every stats-interval seconds)
{
    type: 'system_stats_broadcast',
    device_id: 'raspberry-pi-main',
    data: { /* system stats */ }
}
```

## System Requirements

### Minimum Requirements

- Python 3.7+
- 512MB RAM
- Network connectivity
- Linux-based system (Raspberry Pi OS, Ubuntu, etc.)

### Tested Platforms

- ✅ Raspberry Pi 4 (Raspberry Pi OS)
- ✅ Raspberry Pi Zero W (Raspberry Pi OS Lite)
- ✅ Orange Pi Zero (Armbian)
- ✅ Ubuntu 20.04+ (x86_64, ARM64)
- ✅ Debian 11+ (ARM, x86_64)

### Hardware Support

- **CPU Monitoring**: All platforms
- **Memory Monitoring**: All platforms
- **Temperature**: Raspberry Pi, Orange Pi (thermal zones)
- **Disk Usage**: All platforms
- **Network Stats**: All platforms

## Security Considerations

### File System Access

- Restricted to `/home`, `/tmp`, and `/var/log` directories
- Path traversal protection
- File size limits for reading (1MB default)

### Network Security

- No built-in authentication (add reverse proxy with auth)
- Consider using VPN or firewall rules
- WebSocket connections are not encrypted (use WSS in production)

### Recommended Security Setup

```bash
# Firewall rules (UFW example)
sudo ufw allow from 192.168.1.0/24 to any port 8080
sudo ufw deny 8080

# Run as non-root user
sudo useradd -r -s /bin/false edge-server
```

## Monitoring and Logs

### View Logs

```bash
# Service logs
sudo journalctl -u edge-server -f

# Application logs
tail -f edge_server.log
```

### Health Check

```bash
# Check if server is running
curl -v ws://localhost:8080

# Check process
ps aux | grep edge_server
```

## Integration with IoT Management Dashboard

This edge server is designed to work with the IoT Device Management Dashboard:

1. **Registration**: Register your device in the main dashboard
2. **Connection**: The dashboard connects to this edge server via WebSocket
3. **Monitoring**: Real-time stats are displayed in the web interface
4. **Control**: Execute commands and manage files through the dashboard

### Dashboard Configuration

In your main dashboard backend, configure the edge device connection:

```json
{
  "device_id": "raspberry-pi-main",
  "edge_server_url": "ws://192.168.1.100:8080",
  "connection_type": "websocket"
}
```

## Troubleshooting

### Common Issues

1. **Permission Denied Errors**

   ```bash
   # Fix file permissions
   chmod +x edge_server.py

   # Check user permissions
   groups $USER
   ```

2. **Port Already in Use**

   ```bash
   # Find process using port
   sudo netstat -tulpn | grep :8080

   # Kill process
   sudo kill -9 <PID>
   ```

3. **Temperature Sensors Not Found**

   ```bash
   # Check thermal zones (Linux)
   ls /sys/class/thermal/

   # Install sensor tools
   sudo apt install lm-sensors
   sudo sensors-detect
   ```

4. **WebSocket Connection Failed**

   ```bash
   # Check firewall
   sudo ufw status

   # Test local connection
   telnet localhost 8080
   ```

### Debug Mode

Run with debug logging:

```bash
python edge_server.py --device-id test --log-level DEBUG
```

### Performance Tuning

For low-resource devices:

```bash
# Reduce stats interval
python edge_server.py --device-id pi-zero --stats-interval 30

# Monitor resource usage
htop
```

## API Examples

### Python Client Example

```python
import asyncio
import websockets
import json

async def connect_to_edge_server():
    uri = "ws://192.168.1.100:8080"

    async with websockets.connect(uri) as websocket:
        # Get system stats
        await websocket.send(json.dumps({
            "type": "get_system_stats"
        }))

        response = await websocket.recv()
        data = json.loads(response)
        print(f"CPU Usage: {data['data']['cpu_usage']}%")

asyncio.run(connect_to_edge_server())
```

### JavaScript/Node.js Client Example

```javascript
const WebSocket = require("ws");

const ws = new WebSocket("ws://192.168.1.100:8080");

ws.on("open", () => {
  console.log("Connected to edge server");

  // Request system stats
  ws.send(
    JSON.stringify({
      type: "get_system_stats",
    })
  );
});

ws.on("message", (data) => {
  const response = JSON.parse(data);
  console.log("Received:", response);
});
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Test on actual hardware (Raspberry Pi recommended)
4. Submit a pull request

## License

MIT License - see LICENSE file for details
