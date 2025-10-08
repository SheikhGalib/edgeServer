#!/usr/bin/env python3
"""
IoT Edge Server

This server runs on edge devices (Raspberry Pi, Orange Pi, etc.) to provide:
- System monitoring (CPU, RAM, Temperature, Disk usage)
- Terminal access via WebSocket
- File management capabilities
- Remote command execution
- Real-time system statistics

Usage:
    python edge_server.py --host 0.0.0.0 --port 8080 --device-id my-edge-device
"""

import asyncio
import websockets
import json
import psutil
import subprocess
import os
import argparse
import logging
from datetime import datetime
from pathlib import Path
import threading
import time
import uuid
from typing import Dict, Any, List
import tempfile
import aiohttp
import signal
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('edge_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class SystemMonitor:
    """System monitoring utilities"""

    @staticmethod
    def get_cpu_usage() -> float:
        """Get current CPU usage percentage"""
        return psutil.cpu_percent(interval=1)

    @staticmethod
    def get_memory_usage() -> Dict[str, Any]:
        """Get memory usage information"""
        memory = psutil.virtual_memory()
        return {
            'total': memory.total,
            'available': memory.available,
            'used': memory.used,
            'percentage': memory.percent
        }

    @staticmethod
    def get_disk_usage() -> Dict[str, Any]:
        """Get disk usage information"""
        disk = psutil.disk_usage('/')
        return {
            'total': disk.total,
            'used': disk.used,
            'free': disk.free,
            'percentage': round((disk.used / disk.total) * 100, 2)
        }

    @staticmethod
    def get_network_stats() -> Dict[str, Any]:
        """Get network statistics"""
        try:
            net_io = psutil.net_io_counters()
            return {
                'bytes_sent': net_io.bytes_sent,
                'bytes_recv': net_io.bytes_recv,
                'packets_sent': net_io.packets_sent,
                'packets_recv': net_io.packets_recv
            }
        except Exception:
            return {}

    @staticmethod
    def get_temperature() -> Dict[str, float]:
        """Get system temperature (if available)"""
        try:
            temps = psutil.sensors_temperatures()
            temp_data = {}

            for name, entries in temps.items():
                for entry in entries:
                    if entry.current:
                        temp_data[f"{name}_{entry.label or 'main'}"] = entry.current

            return temp_data
        except (AttributeError, Exception):
            # Fallback for systems without temperature sensors
            try:
                # Try reading from thermal zone (Linux)
                with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                    temp = int(f.read()) / 1000.0
                    return {'cpu_thermal': temp}
            except (FileNotFoundError, PermissionError, ValueError):
                return {}

    @staticmethod
    def get_process_count() -> int:
        """Get number of running processes"""
        return len(psutil.pids())

    @staticmethod
    def get_uptime() -> Dict[str, Any]:
        """Get system uptime"""
        try:
            boot_time = psutil.boot_time()
            uptime_seconds = time.time() - boot_time

            days = int(uptime_seconds // 86400)
            hours = int((uptime_seconds % 86400) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)

            return {
                'uptime_seconds': uptime_seconds,
                'uptime_formatted': f"{days}d {hours}h {minutes}m"
            }
        except Exception:
            return {}

    @classmethod
    def get_system_stats(cls) -> Dict[str, Any]:
        """Get comprehensive system statistics"""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'cpu_usage': cls.get_cpu_usage(),
            'memory': cls.get_memory_usage(),
            'disk': cls.get_disk_usage(),
            'network': cls.get_network_stats(),
            'temperature': cls.get_temperature(),
            'process_count': cls.get_process_count(),
            'uptime': cls.get_uptime()
        }


class FileManager:
    """File management utilities"""

    def __init__(self, base_path: str = "/home"):
        self.base_path = Path(base_path).resolve()
        self.allowed_paths = [self.base_path, Path("/tmp"), Path("/var/log")]

    def _is_safe_path(self, path: Path) -> bool:
        """Check if path is safe to access"""
        try:
            resolved_path = path.resolve()
            return any(
                str(resolved_path).startswith(str(allowed_path))
                for allowed_path in self.allowed_paths
            )
        except Exception:
            return False

    def list_directory(self, path: str) -> Dict[str, Any]:
        """List directory contents"""
        try:
            target_path = Path(path).resolve()

            if not self._is_safe_path(target_path):
                return {
                    'success': False,
                    'error': 'Access denied to this path'
                }

            if not target_path.exists():
                return {
                    'success': False,
                    'error': 'Path does not exist'
                }

            if not target_path.is_dir():
                return {
                    'success': False,
                    'error': 'Path is not a directory'
                }

            items = []
            for item in target_path.iterdir():
                try:
                    stat = item.stat()
                    items.append({
                        'name': item.name,
                        'path': str(item),
                        'type': 'directory' if item.is_dir() else 'file',
                        'size': stat.st_size if item.is_file() else None,
                        'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        'permissions': oct(stat.st_mode)[-3:]
                    })
                except (PermissionError, OSError):
                    items.append({
                        'name': item.name,
                        'path': str(item),
                        'type': 'unknown',
                        'error': 'Permission denied'
                    })

            return {
                'success': True,
                'path': str(target_path),
                'items': sorted(items, key=lambda x: (x['type'] != 'directory', x['name']))
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def read_file(self, path: str, max_size: int = 1024 * 1024) -> Dict[str, Any]:
        """Read file contents (with size limit)"""
        try:
            target_path = Path(path).resolve()

            if not self._is_safe_path(target_path):
                return {
                    'success': False,
                    'error': 'Access denied to this path'
                }

            if not target_path.exists() or not target_path.is_file():
                return {
                    'success': False,
                    'error': 'File does not exist'
                }

            if target_path.stat().st_size > max_size:
                return {
                    'success': False,
                    'error': f'File too large (max {max_size} bytes)'
                }

            with open(target_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()

            return {
                'success': True,
                'content': content,
                'size': len(content)
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def write_file(self, path: str, content: str) -> Dict[str, Any]:
        """Write content to file"""
        try:
            target_path = Path(path).resolve()

            if not self._is_safe_path(target_path):
                return {
                    'success': False,
                    'error': 'Access denied to this path'
                }

            # Create directory if it doesn't exist
            target_path.parent.mkdir(parents=True, exist_ok=True)

            with open(target_path, 'w', encoding='utf-8') as f:
                f.write(content)

            return {
                'success': True,
                'message': f'File written successfully: {target_path}'
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


class TerminalManager:
    """Terminal session management"""

    def __init__(self):
        self.sessions: Dict[str, subprocess.Popen] = {}

    def create_session(self, session_id: str = None) -> str:
        """Create a new terminal session"""
        if not session_id:
            session_id = str(uuid.uuid4())

        # Close existing session if any
        if session_id in self.sessions:
            self.close_session(session_id)

        # Create new bash session
        process = subprocess.Popen(
            ['/bin/bash'],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )

        self.sessions[session_id] = process
        logger.info(f"Created terminal session: {session_id}")
        return session_id

    def execute_command(self, session_id: str, command: str) -> Dict[str, Any]:
        """Execute command in terminal session"""
        try:
            if session_id not in self.sessions:
                return {
                    'success': False,
                    'error': 'Terminal session not found'
                }

            process = self.sessions[session_id]

            # Check if process is still running
            if process.poll() is not None:
                return {
                    'success': False,
                    'error': 'Terminal session has ended'
                }

            # Send command
            process.stdin.write(f"{command}\n")
            process.stdin.flush()

            # Read output (with timeout)
            output_lines = []
            start_time = time.time()

            while time.time() - start_time < 5:  # 5 second timeout
                if process.stdout.readable():
                    try:
                        line = process.stdout.readline()
                        if line:
                            output_lines.append(line.rstrip())
                        else:
                            break
                    except Exception:
                        break
                else:
                    break

            return {
                'success': True,
                'output': '\n'.join(output_lines),
                'session_id': session_id
            }

        except Exception as e:
            logger.error(
                f"Error executing command in session {session_id}: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }

    def close_session(self, session_id: str) -> bool:
        """Close terminal session"""
        try:
            if session_id in self.sessions:
                process = self.sessions[session_id]
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()

                del self.sessions[session_id]
                logger.info(f"Closed terminal session: {session_id}")
                return True
            return False
        except Exception as e:
            logger.error(f"Error closing session {session_id}: {str(e)}")
            return False

    def close_all_sessions(self):
        """Close all terminal sessions"""
        for session_id in list(self.sessions.keys()):
            self.close_session(session_id)


class EdgeServer:
    """Main edge server class"""

    def __init__(self, device_id: str, host: str = '0.0.0.0', port: int = 8080, api_url: str = 'http://172.30.30.233:3001'):
        self.device_id = device_id
        self.host = host
        self.port = port
        self.api_url = api_url
        self.clients: Dict[str, websockets.WebSocketServerProtocol] = {}
        self.system_monitor = SystemMonitor()
        self.file_manager = FileManager()
        self.terminal_manager = TerminalManager()
        self.stats_interval = 10  # seconds
        self.running = False
        self.api_connected = False

    async def register_client(self, websocket, path):
        """Register a new client connection"""
        client_id = f"client_{len(self.clients)}"
        self.clients[client_id] = websocket
        logger.info(f"Client connected: {client_id}")

        try:
            # Send initial system stats
            await self.send_to_client(websocket, {
                'type': 'system_stats',
                'data': self.system_monitor.get_system_stats(),
                'device_id': self.device_id
            })

            # Handle client messages
            async for message in websocket:
                await self.handle_message(websocket, message)

        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Client disconnected: {client_id}")
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {str(e)}")
        finally:
            if client_id in self.clients:
                del self.clients[client_id]

    async def send_to_client(self, websocket, data: Dict[str, Any]):
        """Send data to a specific client"""
        try:
            await websocket.send(json.dumps(data))
        except Exception as e:
            logger.error(f"Error sending data to client: {str(e)}")

    async def broadcast_to_all(self, data: Dict[str, Any]):
        """Broadcast data to all connected clients"""
        if self.clients:
            disconnected = []
            for client_id, websocket in self.clients.items():
                try:
                    await websocket.send(json.dumps(data))
                except Exception:
                    disconnected.append(client_id)

            # Remove disconnected clients
            for client_id in disconnected:
                del self.clients[client_id]

    async def handle_message(self, websocket, message: str):
        """Handle incoming message from client"""
        try:
            data = json.loads(message)
            message_type = data.get('type')

            logger.info(f"Received message type: {message_type}")

            response = {'type': f"{message_type}_response",
                        'device_id': self.device_id}

            if message_type == 'get_system_stats':
                response['data'] = self.system_monitor.get_system_stats()

            elif message_type == 'terminal_create':
                session_id = self.terminal_manager.create_session()
                response['data'] = {'session_id': session_id}

            elif message_type == 'terminal_execute':
                session_id = data.get('session_id')
                command = data.get('command')
                if session_id and command:
                    result = self.terminal_manager.execute_command(
                        session_id, command)
                    response['data'] = result
                else:
                    response['data'] = {'success': False,
                                        'error': 'Missing session_id or command'}

            elif message_type == 'terminal_close':
                session_id = data.get('session_id')
                if session_id:
                    success = self.terminal_manager.close_session(session_id)
                    response['data'] = {'success': success}
                else:
                    response['data'] = {'success': False,
                                        'error': 'Missing session_id'}

            elif message_type == 'file_list':
                path = data.get('path', '/home')
                response['data'] = self.file_manager.list_directory(path)

            elif message_type == 'file_read':
                path = data.get('path')
                if path:
                    response['data'] = self.file_manager.read_file(path)
                else:
                    response['data'] = {
                        'success': False, 'error': 'Missing path'}

            elif message_type == 'file_write':
                path = data.get('path')
                content = data.get('content', '')
                if path:
                    response['data'] = self.file_manager.write_file(
                        path, content)
                else:
                    response['data'] = {
                        'success': False, 'error': 'Missing path'}

            elif message_type == 'execute_command':
                command = data.get('command')
                if command:
                    try:
                        result = subprocess.run(
                            command,
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout=30
                        )
                        response['data'] = {
                            'success': True,
                            'stdout': result.stdout,
                            'stderr': result.stderr,
                            'exit_code': result.returncode
                        }
                    except subprocess.TimeoutExpired:
                        response['data'] = {
                            'success': False, 'error': 'Command timeout'}
                    except Exception as e:
                        response['data'] = {'success': False, 'error': str(e)}
                else:
                    response['data'] = {'success': False,
                                        'error': 'Missing command'}

            else:
                response['data'] = {'success': False,
                                    'error': 'Unknown message type'}

            await self.send_to_client(websocket, response)

        except json.JSONDecodeError:
            await self.send_to_client(websocket, {
                'type': 'error',
                'data': {'success': False, 'error': 'Invalid JSON'}
            })
        except Exception as e:
            logger.error(f"Error handling message: {str(e)}")
            await self.send_to_client(websocket, {
                'type': 'error',
                'data': {'success': False, 'error': str(e)}
            })

    async def stats_broadcaster(self):
        """Periodically broadcast system stats to all clients"""
        while self.running:
            try:
                stats_data = {
                    'type': 'system_stats_broadcast',
                    'data': self.system_monitor.get_system_stats(),
                    'device_id': self.device_id
                }
                await self.broadcast_to_all(stats_data)
                await asyncio.sleep(self.stats_interval)
            except Exception as e:
                logger.error(f"Error broadcasting stats: {str(e)}")
                await asyncio.sleep(self.stats_interval)

    async def register_with_api(self):
        """Register this edge server with the management API"""
        try:
            async with aiohttp.ClientSession() as session:
                # Update device API status
                async with session.patch(
                    f"{self.api_url}/api/devices/api-status/{self.device_id}",
                    json={"api_status": "connected", "server_info": {
                        "host": self.host, "port": self.port}}
                ) as response:
                    if response.status == 200:
                        self.api_connected = True
                        logger.info(
                            f"✅ Successfully registered with management API")
                        return True
                    else:
                        logger.error(
                            f"❌ Failed to register with API: {response.status}")
                        return False
        except Exception as error:
            logger.error(f"❌ API registration failed: {error}")
            return False

    async def send_heartbeat(self):
        """Send periodic heartbeat to management API"""
        while self.running and self.api_connected:
            try:
                stats = {
                    'cpu_usage': self.system_monitor.get_cpu_usage(),
                    'ram_usage': self.system_monitor.get_memory_usage(),
                    'temperature': self.system_monitor.get_temperature(),
                    'timestamp': datetime.now().isoformat()
                }

                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{self.api_url}/api/devices/heartbeat/{self.device_id}",
                        json=stats
                    ) as response:
                        if response.status != 200:
                            logger.warning(
                                f"⚠️ Heartbeat failed: {response.status}")

            except Exception as error:
                logger.error(f"💔 Heartbeat error: {error}")

            await asyncio.sleep(30)  # Send heartbeat every 30 seconds

    async def start_server(self):
        """Start the WebSocket server"""
        self.running = True
        logger.info(f"🚀 Starting Edge Server for device: {self.device_id}")
        logger.info(
            f"📡 WebSocket server starting on ws://{self.host}:{self.port}")

        # Register with management API
        logger.info(
            f"🔗 Attempting to register with management API: {self.api_url}")
        await self.register_with_api()

        # Start stats broadcaster
        asyncio.create_task(self.stats_broadcaster())

        # Start heartbeat if API connected
        if self.api_connected:
            asyncio.create_task(self.send_heartbeat())

        # Start WebSocket server
        async with websockets.serve(self.register_client, self.host, self.port):
            logger.info(
                f"✅ Edge Server running on ws://{self.host}:{self.port}")
            logger.info(f"🔑 Device ID: {self.device_id}")
            logger.info(
                f"🌐 API Status: {'Connected' if self.api_connected else 'Disconnected'}")
            logger.info("Press Ctrl+C to stop the server")

            try:
                await asyncio.Future()  # Run forever
            except KeyboardInterrupt:
                logger.info("Shutting down server...")
                self.running = False
                self.terminal_manager.close_all_sessions()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='IoT Edge Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080,
                        help='Port to bind to')
    parser.add_argument('--device-id', required=True,
                        help='Unique device identifier (provided by management system)')
    parser.add_argument('--api-url', default='http://172.30.30.233:3001',
                        help='Management API URL (default: http://172.30.30.233:3001)')
    parser.add_argument('--stats-interval', type=int,
                        default=10, help='Stats broadcast interval in seconds')
    parser.add_argument('--log-level', default='INFO', help='Log level')

    args = parser.parse_args()

    # Configure logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))

    logger.info("🔧 IoT Edge Server Configuration:")
    logger.info(f"   Device ID: {args.device_id}")
    logger.info(f"   Server: {args.host}:{args.port}")
    logger.info(f"   API URL: {args.api_url}")

    # Create and start server
    server = EdgeServer(
        device_id=args.device_id,
        host=args.host,
        port=args.port,
        api_url=args.api_url
    )
    server.stats_interval = args.stats_interval

    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        logger.info("🛑 Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {str(e)}")


if __name__ == '__main__':
    main()
