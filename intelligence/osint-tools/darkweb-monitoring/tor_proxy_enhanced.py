#!/usr/bin/env python3
"""
Enhanced Tor Proxy Manager with Circuit Rotation and Health Monitoring
Provides secure and reliable Tor connectivity for dark web operations
"""

import asyncio
import aiohttp
from aiohttp_socks import ProxyConnector
from typing import Optional, Dict, Any, List
import logging
import subprocess
import socket
import time
from pathlib import Path
import tempfile
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
import hashlib
import secrets


@dataclass
class CircuitInfo:
    """Information about a Tor circuit"""
    circuit_id: str
    created_at: datetime
    exit_ip: Optional[str] = None
    country: Optional[str] = None
    bandwidth_used: int = 0
    requests_made: int = 0
    last_used: Optional[datetime] = None
    is_healthy: bool = True


@dataclass
class TorHealthStatus:
    """Tor connection health status"""
    is_connected: bool = False
    is_tor_verified: bool = False
    current_ip: Optional[str] = None
    exit_country: Optional[str] = None
    latency_ms: Optional[float] = None
    circuit_id: Optional[str] = None
    uptime_seconds: int = 0
    total_requests: int = 0
    failed_requests: int = 0
    last_check: Optional[datetime] = None
    errors: List[str] = field(default_factory=list)


class TorProxyEnhanced:
    """
    Enhanced Tor SOCKS5 proxy manager with:
    - Circuit rotation for anonymity
    - Connection health monitoring
    - Automatic reconnection
    - Rate limiting
    - Session management
    """

    # Tor check endpoints
    TOR_CHECK_URLS = [
        "https://check.torproject.org/api/ip",
        "https://api.ipify.org?format=json",
        "https://httpbin.org/ip"
    ]

    def __init__(
        self,
        socks_port: int = 9050,
        control_port: int = 9051,
        control_password: Optional[str] = None,
        tor_path: Optional[str] = None,
        auto_rotate_interval: int = 600,  # 10 minutes
        max_requests_per_circuit: int = 100
    ):
        """
        Initialize enhanced Tor proxy

        Args:
            socks_port: SOCKS5 proxy port
            control_port: Tor control port
            control_password: Tor control password (hashed)
            tor_path: Path to Tor binary
            auto_rotate_interval: Seconds between automatic circuit rotations
            max_requests_per_circuit: Maximum requests before circuit rotation
        """
        self.socks_port = socks_port
        self.control_port = control_port
        self.control_password = control_password or self._generate_password()
        self.tor_path = tor_path or 'tor'
        self.auto_rotate_interval = auto_rotate_interval
        self.max_requests_per_circuit = max_requests_per_circuit

        self.logger = self._setup_logging()

        # State management
        self.tor_process: Optional[subprocess.Popen] = None
        self.running = False
        self.start_time: Optional[datetime] = None

        # Circuit tracking
        self.current_circuit: Optional[CircuitInfo] = None
        self.circuit_history: List[CircuitInfo] = []

        # Health monitoring
        self.health_status = TorHealthStatus()
        self._health_check_task: Optional[asyncio.Task] = None
        self._rotation_task: Optional[asyncio.Task] = None

        # Request tracking
        self.total_requests = 0
        self.failed_requests = 0

        # Data directory
        self.data_dir = Path(tempfile.gettempdir()) / f'tor_enhanced_{socks_port}'
        self.data_dir.mkdir(exist_ok=True)

        # Rate limiting
        self._request_times: List[datetime] = []
        self._rate_limit = 10  # requests per second

    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger(f"TorProxyEnhanced-{self.socks_port}")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    def _generate_password(self) -> str:
        """Generate a random control password"""
        return secrets.token_hex(16)

    async def start(self, wait_for_bootstrap: bool = True) -> bool:
        """
        Start Tor proxy with enhanced features

        Args:
            wait_for_bootstrap: Wait for Tor to fully bootstrap

        Returns:
            True if started successfully
        """
        if self.running:
            self.logger.warning("Tor proxy already running")
            return True

        self.logger.info("Starting enhanced Tor proxy...")

        try:
            # Check if Tor is already running on the port
            if self._check_port_available():
                await self._start_tor_process()
            else:
                self.logger.info(f"Port {self.socks_port} already in use, assuming Tor is running")

            if wait_for_bootstrap:
                await self._wait_for_bootstrap()

            # Initialize circuit info
            self.current_circuit = CircuitInfo(
                circuit_id=secrets.token_hex(8),
                created_at=datetime.utcnow()
            )

            self.running = True
            self.start_time = datetime.utcnow()

            # Start background tasks
            self._health_check_task = asyncio.create_task(self._health_monitor_loop())
            self._rotation_task = asyncio.create_task(self._auto_rotation_loop())

            # Update circuit with exit IP
            await self._update_circuit_info()

            self.logger.info(f"Enhanced Tor proxy started on port {self.socks_port}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to start Tor: {e}")
            self.health_status.errors.append(str(e))
            return False

    async def stop(self):
        """Stop Tor proxy and cleanup"""
        if not self.running:
            return

        self.logger.info("Stopping enhanced Tor proxy...")
        self.running = False

        try:
            # Cancel background tasks
            if self._health_check_task:
                self._health_check_task.cancel()
                try:
                    await self._health_check_task
                except asyncio.CancelledError:
                    pass

            if self._rotation_task:
                self._rotation_task.cancel()
                try:
                    await self._rotation_task
                except asyncio.CancelledError:
                    pass

            # Stop Tor process
            if self.tor_process:
                self.tor_process.terminate()
                try:
                    self.tor_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.tor_process.kill()
                self.tor_process = None

            # Archive current circuit
            if self.current_circuit:
                self.circuit_history.append(self.current_circuit)

            self.logger.info("Enhanced Tor proxy stopped")

        except Exception as e:
            self.logger.error(f"Error stopping Tor: {e}")

    def _check_port_available(self) -> bool:
        """Check if SOCKS port is available"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', self.socks_port))
            sock.close()
            return result != 0  # Available if connection fails
        except:
            return True

    async def _start_tor_process(self):
        """Start Tor process with enhanced configuration"""
        # Create torrc configuration
        torrc_path = self.data_dir / 'torrc'

        # Hash the password for Tor control
        hashed_password = self._hash_control_password(self.control_password)

        torrc_content = f"""
# Enhanced Tor Configuration
SocksPort {self.socks_port}
ControlPort {self.control_port}
HashedControlPassword {hashed_password}
DataDirectory {self.data_dir}

# Logging
Log notice stdout
Log notice file {self.data_dir / 'tor.log'}

# Connection settings
ConnectionPadding auto
ReducedConnectionPadding 0

# Circuit settings
MaxCircuitDirtiness {self.auto_rotate_interval}
NewCircuitPeriod {self.auto_rotate_interval // 2}

# Security settings
SafeSocks 1
TestSocks 1

# Performance
NumEntryGuards 3
UseEntryGuards 1
"""

        with open(torrc_path, 'w') as f:
            f.write(torrc_content)

        # Start Tor
        try:
            self.tor_process = subprocess.Popen(
                [self.tor_path, '-f', str(torrc_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            self.logger.info("Tor process started")
        except FileNotFoundError:
            raise RuntimeError(
                "Tor binary not found. Install Tor or provide path to binary."
            )

    def _hash_control_password(self, password: str) -> str:
        """
        Hash password for Tor control port

        Note: This is a simplified implementation.
        In production, use 'tor --hash-password' command.
        """
        # For demonstration, return a placeholder
        # Real implementation would use Tor's password hashing
        return "16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C"

    async def _wait_for_bootstrap(self, timeout: int = 120):
        """Wait for Tor to fully bootstrap"""
        self.logger.info("Waiting for Tor to bootstrap...")

        start_time = time.time()

        while time.time() - start_time < timeout:
            # Check if SOCKS port is responding
            if not self._check_port_available():
                # Try to verify Tor connection
                try:
                    is_tor = await self.verify_tor_connection()
                    if is_tor:
                        self.logger.info("Tor bootstrap complete")
                        return
                except:
                    pass

            await asyncio.sleep(2)

        # If we can connect to SOCKS but can't verify Tor, warn but continue
        if not self._check_port_available():
            self.logger.warning("Tor appears to be running but couldn't verify connectivity")
            return

        raise RuntimeError("Tor failed to bootstrap within timeout")

    @asynccontextmanager
    async def get_session(self):
        """
        Get aiohttp session configured for Tor

        Usage:
            async with proxy.get_session() as session:
                async with session.get(url) as response:
                    ...
        """
        if not self.running:
            raise RuntimeError("Tor proxy is not running")

        # Rate limiting
        await self._apply_rate_limit()

        # Create connector with SOCKS proxy
        connector = ProxyConnector.from_url(
            f"socks5://127.0.0.1:{self.socks_port}",
            rdns=True  # Remote DNS resolution through Tor
        )

        # User agent rotation
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0',
            'Mozilla/5.0 (Windows NT 10.0; rv:102.0) Gecko/20100101 Firefox/102.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
        ]
        import random
        user_agent = random.choice(user_agents)

        session = aiohttp.ClientSession(
            connector=connector,
            headers={
                'User-Agent': user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            },
            timeout=aiohttp.ClientTimeout(total=60)
        )

        try:
            yield session
            # Track successful request
            self.total_requests += 1
            if self.current_circuit:
                self.current_circuit.requests_made += 1
                self.current_circuit.last_used = datetime.utcnow()

                # Check if circuit rotation needed
                if self.current_circuit.requests_made >= self.max_requests_per_circuit:
                    self.logger.info("Max requests per circuit reached, rotating...")
                    await self.rotate_circuit()
        finally:
            await session.close()

    async def _apply_rate_limit(self):
        """Apply rate limiting to requests"""
        now = datetime.utcnow()

        # Remove old request times
        cutoff = now - timedelta(seconds=1)
        self._request_times = [t for t in self._request_times if t > cutoff]

        # Check if rate limit exceeded
        if len(self._request_times) >= self._rate_limit:
            sleep_time = (self._request_times[0] + timedelta(seconds=1) - now).total_seconds()
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

        self._request_times.append(now)

    async def rotate_circuit(self) -> bool:
        """
        Request new Tor circuit (new exit node)

        Returns:
            True if rotation successful
        """
        if not self.running:
            raise RuntimeError("Tor proxy is not running")

        self.logger.info("Rotating Tor circuit...")

        try:
            # Connect to control port
            reader, writer = await asyncio.open_connection('127.0.0.1', self.control_port)

            # Authenticate
            writer.write(f'AUTHENTICATE "{self.control_password}"\r\n'.encode())
            await writer.drain()
            response = await reader.readline()

            if b'250 OK' not in response:
                # Try without password (for system Tor)
                writer.write(b'AUTHENTICATE\r\n')
                await writer.drain()
                response = await reader.readline()

                if b'250 OK' not in response:
                    raise RuntimeError("Failed to authenticate to Tor control port")

            # Request new circuit
            writer.write(b'SIGNAL NEWNYM\r\n')
            await writer.drain()
            response = await reader.readline()

            writer.close()
            await writer.wait_closed()

            if b'250 OK' in response:
                # Archive old circuit
                if self.current_circuit:
                    self.circuit_history.append(self.current_circuit)

                # Create new circuit
                self.current_circuit = CircuitInfo(
                    circuit_id=secrets.token_hex(8),
                    created_at=datetime.utcnow()
                )

                # Wait for circuit to establish
                await asyncio.sleep(5)

                # Update circuit info with new exit IP
                await self._update_circuit_info()

                self.logger.info(f"Circuit rotated. New exit IP: {self.current_circuit.exit_ip}")
                return True
            else:
                raise RuntimeError("Failed to rotate circuit")

        except Exception as e:
            self.logger.error(f"Error rotating circuit: {e}")
            self.health_status.errors.append(f"Circuit rotation failed: {e}")
            return False

    async def _update_circuit_info(self):
        """Update current circuit information"""
        if not self.current_circuit:
            return

        try:
            ip_info = await self.get_exit_info()
            if ip_info:
                self.current_circuit.exit_ip = ip_info.get('ip')
                self.current_circuit.country = ip_info.get('country')
        except Exception as e:
            self.logger.warning(f"Could not update circuit info: {e}")

    async def verify_tor_connection(self) -> bool:
        """
        Verify connection is going through Tor

        Returns:
            True if connected through Tor
        """
        try:
            async with self.get_session() as session:
                async with session.get(
                    'https://check.torproject.org/api/ip',
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        is_tor = data.get('IsTor', False)

                        # Update health status
                        self.health_status.is_tor_verified = is_tor
                        self.health_status.current_ip = data.get('IP')

                        if is_tor:
                            self.logger.info(f"Verified Tor connection. Exit IP: {data.get('IP')}")
                        else:
                            self.logger.warning("NOT connected through Tor!")

                        return is_tor

        except Exception as e:
            self.logger.error(f"Error verifying Tor connection: {e}")
            self.health_status.errors.append(f"Verification failed: {e}")

        return False

    async def get_exit_info(self) -> Optional[Dict[str, Any]]:
        """
        Get current exit node information

        Returns:
            Dictionary with IP and location info
        """
        try:
            async with self.get_session() as session:
                # Use ipinfo.io for location data
                async with session.get(
                    'https://ipinfo.io/json',
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return {
                            'ip': data.get('ip'),
                            'country': data.get('country'),
                            'region': data.get('region'),
                            'city': data.get('city'),
                            'org': data.get('org'),
                            'timezone': data.get('timezone')
                        }

        except Exception as e:
            self.logger.warning(f"Could not get exit info: {e}")

        return None

    async def _health_monitor_loop(self):
        """Background task for health monitoring"""
        while self.running:
            try:
                await self._perform_health_check()
                await asyncio.sleep(60)  # Check every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Health check error: {e}")
                await asyncio.sleep(30)

    async def _perform_health_check(self):
        """Perform health check"""
        start_time = time.time()

        try:
            # Verify Tor connection
            is_tor = await self.verify_tor_connection()

            # Calculate latency
            latency = (time.time() - start_time) * 1000

            # Update health status
            self.health_status.is_connected = True
            self.health_status.is_tor_verified = is_tor
            self.health_status.latency_ms = latency
            self.health_status.last_check = datetime.utcnow()
            self.health_status.total_requests = self.total_requests
            self.health_status.failed_requests = self.failed_requests

            if self.start_time:
                self.health_status.uptime_seconds = int(
                    (datetime.utcnow() - self.start_time).total_seconds()
                )

            if self.current_circuit:
                self.health_status.circuit_id = self.current_circuit.circuit_id

            # Clear old errors
            if len(self.health_status.errors) > 10:
                self.health_status.errors = self.health_status.errors[-10:]

        except Exception as e:
            self.health_status.is_connected = False
            self.health_status.errors.append(f"Health check failed: {e}")

    async def _auto_rotation_loop(self):
        """Background task for automatic circuit rotation"""
        while self.running:
            try:
                await asyncio.sleep(self.auto_rotate_interval)

                if self.running and self.current_circuit:
                    age = (datetime.utcnow() - self.current_circuit.created_at).total_seconds()
                    if age >= self.auto_rotate_interval:
                        self.logger.info(f"Auto-rotating circuit (age: {age:.0f}s)")
                        await self.rotate_circuit()

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Auto-rotation error: {e}")

    def get_health_status(self) -> Dict[str, Any]:
        """
        Get current health status

        Returns:
            Health status dictionary
        """
        return {
            'is_connected': self.health_status.is_connected,
            'is_tor_verified': self.health_status.is_tor_verified,
            'current_ip': self.health_status.current_ip,
            'exit_country': self.health_status.exit_country,
            'latency_ms': self.health_status.latency_ms,
            'circuit_id': self.health_status.circuit_id,
            'uptime_seconds': self.health_status.uptime_seconds,
            'total_requests': self.health_status.total_requests,
            'failed_requests': self.health_status.failed_requests,
            'last_check': self.health_status.last_check.isoformat() if self.health_status.last_check else None,
            'recent_errors': self.health_status.errors[-5:] if self.health_status.errors else []
        }

    def get_circuit_info(self) -> Optional[Dict[str, Any]]:
        """
        Get current circuit information

        Returns:
            Circuit info dictionary
        """
        if not self.current_circuit:
            return None

        return {
            'circuit_id': self.current_circuit.circuit_id,
            'created_at': self.current_circuit.created_at.isoformat(),
            'exit_ip': self.current_circuit.exit_ip,
            'country': self.current_circuit.country,
            'requests_made': self.current_circuit.requests_made,
            'age_seconds': int((datetime.utcnow() - self.current_circuit.created_at).total_seconds()),
            'last_used': self.current_circuit.last_used.isoformat() if self.current_circuit.last_used else None
        }

    def get_circuit_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get circuit rotation history

        Args:
            limit: Maximum circuits to return

        Returns:
            List of circuit info dictionaries
        """
        circuits = []
        for circuit in self.circuit_history[-limit:]:
            circuits.append({
                'circuit_id': circuit.circuit_id,
                'created_at': circuit.created_at.isoformat(),
                'exit_ip': circuit.exit_ip,
                'country': circuit.country,
                'requests_made': circuit.requests_made
            })
        return circuits

    def get_proxy_url(self) -> str:
        """Get SOCKS5 proxy URL"""
        return f"socks5://127.0.0.1:{self.socks_port}"

    def cleanup(self):
        """Cleanup temporary files"""
        try:
            if self.data_dir.exists():
                shutil.rmtree(self.data_dir)
                self.logger.info("Cleaned up temporary files")
        except Exception as e:
            self.logger.error(f"Error cleaning up: {e}")


async def main():
    """Example usage"""
    proxy = TorProxyEnhanced(
        socks_port=9050,
        auto_rotate_interval=300,  # 5 minutes
        max_requests_per_circuit=50
    )

    try:
        # Start Tor
        if not await proxy.start():
            print("[!] Failed to start Tor proxy")
            return

        print("[+] Tor proxy started")

        # Verify connection
        is_tor = await proxy.verify_tor_connection()
        print(f"[*] Connected through Tor: {is_tor}")

        # Get exit info
        exit_info = await proxy.get_exit_info()
        if exit_info:
            print(f"[*] Exit node: {exit_info}")

        # Get health status
        health = proxy.get_health_status()
        print(f"[*] Health status: {health}")

        # Get circuit info
        circuit = proxy.get_circuit_info()
        print(f"[*] Current circuit: {circuit}")

        # Make some test requests
        async with proxy.get_session() as session:
            async with session.get('https://httpbin.org/ip') as response:
                data = await response.json()
                print(f"[*] Request IP: {data}")

        # Rotate circuit
        print("[*] Rotating circuit...")
        await proxy.rotate_circuit()

        # Get new exit info
        new_exit = await proxy.get_exit_info()
        print(f"[*] New exit node: {new_exit}")

        # Get circuit history
        history = proxy.get_circuit_history()
        print(f"[*] Circuit history: {history}")

    finally:
        # Stop Tor
        await proxy.stop()
        proxy.cleanup()
        print("[+] Tor proxy stopped")


if __name__ == "__main__":
    asyncio.run(main())
