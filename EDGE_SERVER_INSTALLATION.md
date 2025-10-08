# IoT Edge Server Installation Guide

This guide will help you set up an IoT edge device to connect to the management system.

## Prerequisites

- A Linux-based device (Raspberry Pi, Orange Pi, Ubuntu, etc.)
- SSH access to the device
- Internet connection on the device
- Python 3.7+ installed

## Automatic Installation (Recommended)

When you register a device through the web interface, the system will automatically:

1. **Connect via SSH** to verify credentials
2. **Generate a unique device key** for identification
3. **Deploy the edge server** automatically
4. **Start the service** as a system daemon

The automatic process includes:

- Installing git, python3, python3-pip, python3-venv
- Cloning the edge server repository
- Setting up Python virtual environment
- Installing dependencies
- Creating systemd service for auto-start

## Manual Installation

If you prefer to install manually or the automatic installation fails:

### Step 1: Clone the Repository

```bash
git clone https://github.com/SheikhGalib/edgeServer.git
cd edgeServer
```

### Step 2: Set up Python Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Step 3: Get Your Device Key

1. Register your device through the web interface
2. Note down the generated device key (format: `device_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`)

### Step 4: Run the Edge Server

```bash
# Replace YOUR_DEVICE_KEY with the actual key from step 3
# Replace MANAGEMENT_SERVER_IP with the IP of your management server
python edge_server.py --device-id YOUR_DEVICE_KEY --api-url http://MANAGEMENT_SERVER_IP:3001
```

### Step 5: Set up Auto-Start (Optional)

Create a systemd service for automatic startup:

```bash
sudo nano /etc/systemd/system/iot-edge-server.service
```

Add the following content (replace paths and device key):

```ini
[Unit]
Description=IoT Edge Server
After=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/home/pi/edgeServer
ExecStart=/home/pi/edgeServer/venv/bin/python edge_server.py --device-id YOUR_DEVICE_KEY --api-url http://MANAGEMENT_SERVER_IP:3001
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable iot-edge-server.service
sudo systemctl start iot-edge-server.service
```

## Verification

### Check Service Status

```bash
sudo systemctl status iot-edge-server.service
```

### Check Logs

```bash
# View service logs
sudo journalctl -u iot-edge-server.service -f

# View edge server logs
tail -f ~/edgeServer/edge_server.log
```

### Check Connection Status

1. Open the management web interface
2. Navigate to "Edge Devices"
3. Your device should show:
   - **Green dot**: API connected and working
   - **Orange dot**: Device registered but API not connected
   - **Red dot**: API connection error

## Troubleshooting

### Connection Issues

1. **Check network connectivity**:

   ```bash
   ping MANAGEMENT_SERVER_IP
   curl http://MANAGEMENT_SERVER_IP:3001/api/health
   ```

2. **Check firewall settings**:

   - Ensure port 3001 is accessible from the device
   - Check if the management server firewall allows connections

3. **Verify device key**:
   - Ensure the device key matches what was generated during registration
   - Check for any typos in the command line arguments

### Service Issues

1. **Check Python environment**:

   ```bash
   cd ~/edgeServer
   source venv/bin/activate
   python --version
   pip list
   ```

2. **Manual test run**:

   ```bash
   cd ~/edgeServer
   source venv/bin/activate
   python edge_server.py --device-id YOUR_DEVICE_KEY --api-url http://MANAGEMENT_SERVER_IP:3001 --log-level DEBUG
   ```

3. **Check system resources**:
   ```bash
   free -h
   df -h
   top
   ```

## Configuration Options

The edge server accepts the following command-line arguments:

- `--device-id`: Unique device identifier (required)
- `--host`: Host to bind WebSocket server to (default: 0.0.0.0)
- `--port`: Port for WebSocket server (default: 8080)
- `--api-url`: Management API URL (default: http://localhost:3001)
- `--stats-interval`: Stats broadcast interval in seconds (default: 10)
- `--log-level`: Log level (DEBUG, INFO, WARNING, ERROR)

## Security Notes

- **SSH Keys**: In production, use SSH keys instead of passwords
- **Firewall**: Configure firewall rules to allow only necessary connections
- **Updates**: Keep the system and edge server updated regularly
- **Monitoring**: Monitor logs for any suspicious activity

## Support

If you encounter issues:

1. Check the troubleshooting section above
2. Review the logs for error messages
3. Verify network connectivity and firewall settings
4. Ensure all dependencies are properly installed

For additional help, check the management system logs and ensure the backend server is running properly.
