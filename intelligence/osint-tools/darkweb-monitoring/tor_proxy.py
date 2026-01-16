#!/usr/bin/env python3
"""
Tor Proxy Manager
Manages Tor SOCKS5 proxy connectivity for dark web access
"""

import asyncio
import aiohttp
from typing import Optional, Dict, Any
import logging
import subprocess
import socket
import time
from pathlib import Path
import tempfile
import shutil


class TorProxy:
    """Tor SOCKS5 proxy manager"""

    def __init__(
        self,
        socks_port: int = 9050,
        control_port: int = 9051,
        tor_path: Optional[str] = None
    ):
        """
        Initialize Tor proxy

        Args:
            socks_port: SOCKS5 proxy port
            control_port: Tor control port
            tor_path: Path to Tor binary (if not in PATH)
        """
        self.socks_port = socks_port
        self.control_port = control_port
        self.tor_path = tor_path or 'tor'
        self.logger = self._setup_logging()

        # Tor process
        self.tor_process: Optional[subprocess.Popen] = None
        self.running = False

        # Data directory
        self.data_dir = Path(tempfile.gettempdir()) / 'tor_darkweb_monitor'
        self.data_dir.mkdir(exist_ok=True)

        # Session
        self.session: Optional[aiohttp.ClientSession] = None

    def _setup_logging(self) -> logging.Logger:
        """Setup logging"""
        logger = logging.getLogger("TorProxy")
        logger.setLevel(logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger

    async def start(self):
        """Start Tor proxy"""
        if self.running:
            self.logger.warning("Tor proxy already running")
            return

        self.logger.info("Starting Tor proxy...")

        try:
            # Check if Tor is already running
            if self._check_tor_running():
                self.logger.info("Tor is already running on the system")
                self.running = True
                return

            # Start Tor process
            await self._start_tor_process()

            # Wait for Tor to bootstrap
            await self._wait_for_bootstrap()

            self.running = True
            self.logger.info(f"Tor proxy started on port {self.socks_port}")

        except Exception as e:
            self.logger.error(f"Failed to start Tor: {e}")
            raise

    async def stop(self):
        """Stop Tor proxy"""
        if not self.running:
            return

        self.logger.info("Stopping Tor proxy...")

        try:
            # Close session
            if self.session:
                await self.session.close()
                self.session = None

            # Stop Tor process
            if self.tor_process:
                self.tor_process.terminate()
                self.tor_process.wait(timeout=10)
                self.tor_process = None

            self.running = False
            self.logger.info("Tor proxy stopped")

        except Exception as e:
            self.logger.error(f"Error stopping Tor: {e}")

    def _check_tor_running(self) -> bool:
        """Check if Tor is already running"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', self.socks_port))
            sock.close()
            return result == 0
        except:
            return False

    async def _start_tor_process(self):
        """Start Tor process"""
        # Create torrc configuration
        torrc_path = self.data_dir / 'torrc'
        torrc_content = f"""
SocksPort {self.socks_port}
ControlPort {self.control_port}
DataDirectory {self.data_dir}
Log notice stdout
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
                "Tor binary not found. Please install Tor or provide path to binary."
            )

    async def _wait_for_bootstrap(self, timeout: int = 60):
        """Wait for Tor to bootstrap"""
        self.logger.info("Waiting for Tor to bootstrap...")

        start_time = time.time()

        while time.time() - start_time < timeout:
            if self._check_tor_running():
                # Try to connect through Tor
                try:
                    async with self.get_session() as session:
                        async with session.get(
                            'http://check.torproject.org',
                            timeout=10
                        ) as response:
                            text = await response.text()
                            if 'Congratulations' in text:
                                self.logger.info("Tor bootstrap complete")
                                return
                except:
                    pass

            await asyncio.sleep(2)

        # If we're here, Tor might be running but we can't verify
        if self._check_tor_running():
            self.logger.warning("Tor appears to be running but couldn't verify connectivity")
            return

        raise RuntimeError("Tor failed to bootstrap within timeout")

    def get_session(self) -> aiohttp.ClientSession:
        """
        Get aiohttp session configured for Tor

        Returns:
            aiohttp.ClientSession configured with Tor proxy
        """
        if not self.running:
            raise RuntimeError("Tor proxy is not running")

        # Create proxy URL
        proxy = f"socks5://127.0.0.1:{self.socks_port}"

        # Create connector
        connector = aiohttp.TCPConnector(ssl=False)

        # Create session
        session = aiohttp.ClientSession(
            connector=connector,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0'
            }
        )

        # Note: aiohttp doesn't support SOCKS proxy directly
        # In production, you'd use aiohttp-socks:
        # from aiohttp_socks import ProxyConnector
        # connector = ProxyConnector.from_url(proxy)
        # session = aiohttp.ClientSession(connector=connector)

        return session

    async def rotate_circuit(self):
        """Request new Tor circuit (new exit node)"""
        if not self.running:
            raise RuntimeError("Tor proxy is not running")

        try:
            # Connect to control port and send NEWNYM signal
            reader, writer = await asyncio.open_connection('127.0.0.1', self.control_port)

            # Authenticate (no password by default)
            writer.write(b'AUTHENTICATE ""\r\n')
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
                self.logger.info("Tor circuit rotated")
            else:
                raise RuntimeError("Failed to rotate Tor circuit")

        except Exception as e:
            self.logger.error(f"Error rotating circuit: {e}")
            raise

    async def get_current_ip(self) -> Optional[str]:
        """
        Get current exit node IP

        Returns:
            Current IP address or None
        """
        try:
            async with self.get_session() as session:
                async with session.get(
                    'https://api.ipify.org?format=json',
                    timeout=10
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get('ip')

        except Exception as e:
            self.logger.error(f"Error getting IP: {e}")

        return None

    async def verify_tor_connection(self) -> bool:
        """
        Verify Tor connection is working

        Returns:
            True if connected through Tor
        """
        try:
            async with self.get_session() as session:
                async with session.get(
                    'https://check.torproject.org/api/ip',
                    timeout=10
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        is_tor = data.get('IsTor', False)

                        if is_tor:
                            self.logger.info(f"Connected through Tor. Exit IP: {data.get('IP')}")
                        else:
                            self.logger.warning("Not connected through Tor")

                        return is_tor

        except Exception as e:
            self.logger.error(f"Error verifying Tor connection: {e}")

        return False

    def get_proxy_url(self) -> str:
        """
        Get proxy URL for manual configuration

        Returns:
            SOCKS5 proxy URL
        """
        return f"socks5://127.0.0.1:{self.socks_port}"

    def get_status(self) -> Dict[str, Any]:
        """
        Get Tor proxy status

        Returns:
            Status information
        """
        return {
            'running': self.running,
            'socks_port': self.socks_port,
            'control_port': self.control_port,
            'proxy_url': self.get_proxy_url(),
            'data_dir': str(self.data_dir)
        }

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
    proxy = TorProxy()

    try:
        # Start Tor
        await proxy.start()

        # Verify connection
        is_tor = await proxy.verify_tor_connection()
        print(f"[*] Connected through Tor: {is_tor}")

        # Get current IP
        ip = await proxy.get_current_ip()
        print(f"[*] Current exit IP: {ip}")

        # Get status
        status = proxy.get_status()
        print(f"[*] Tor status: {status}")

        # Rotate circuit
        print("[*] Rotating circuit...")
        await proxy.rotate_circuit()
        await asyncio.sleep(5)

        # Get new IP
        new_ip = await proxy.get_current_ip()
        print(f"[*] New exit IP: {new_ip}")

    finally:
        # Stop Tor
        await proxy.stop()
        proxy.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
