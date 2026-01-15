"""
Multi-Chain API Clients

Clients for various blockchain explorers:
- BSCScan (Binance Smart Chain)
- PolygonScan (Polygon/Matic)
- SnowTrace (Avalanche)
- Solscan (Solana)
- CardanoScan (Cardano)
"""

import aiohttp
from typing import Dict, List, Optional
from .bitcoin_clients import BaseBlockchainClient


class BSCScanClient(BaseBlockchainClient):
    """BscScan API client for Binance Smart Chain"""

    def __init__(self, session: aiohttp.ClientSession, config):
        super().__init__(session, config)
        self.base_url = "https://api.bscscan.com/api"
        self.api_key = config.BSCSCAN_API_KEY

    async def get_address_transactions(self, address: str, limit: int = 100) -> List[Dict]:
        """Get BNB transactions"""
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "sort": "desc",
            "apikey": self.api_key
        }

        data = await self._get("", params)
        return data.get("result", [])[:limit] if data else []

    async def get_transaction(self, txid: str) -> Optional[Dict]:
        """Get transaction details"""
        # Implementation similar to Etherscan
        return None

    async def get_address_balance(self, address: str) -> float:
        """Get BNB balance"""
        params = {
            "module": "account",
            "action": "balance",
            "address": address,
            "apikey": self.api_key
        }

        data = await self._get("", params)
        if data and data.get("status") == "1":
            balance_wei = int(data.get("result", 0))
            return balance_wei / 1e18

        return 0.0

    async def get_current_price(self) -> float:
        """Get BNB price"""
        return 0.0  # Implement via external price API


class PolygonScanClient(BaseBlockchainClient):
    """PolygonScan API client"""

    def __init__(self, session: aiohttp.ClientSession, config):
        super().__init__(session, config)
        self.base_url = "https://api.polygonscan.com/api"
        self.api_key = config.POLYGONSCAN_API_KEY

    async def get_address_transactions(self, address: str, limit: int = 100) -> List[Dict]:
        """Get MATIC transactions"""
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "sort": "desc",
            "apikey": self.api_key
        }

        data = await self._get("", params)
        return data.get("result", [])[:limit] if data else []

    async def get_transaction(self, txid: str) -> Optional[Dict]:
        """Get transaction details"""
        return None

    async def get_address_balance(self, address: str) -> float:
        """Get MATIC balance"""
        params = {
            "module": "account",
            "action": "balance",
            "address": address,
            "apikey": self.api_key
        }

        data = await self._get("", params)
        if data and data.get("status") == "1":
            balance_wei = int(data.get("result", 0))
            return balance_wei / 1e18

        return 0.0

    async def get_current_price(self) -> float:
        """Get MATIC price"""
        return 0.0


class SnowTraceClient(BaseBlockchainClient):
    """SnowTrace API client for Avalanche"""

    def __init__(self, session: aiohttp.ClientSession, config):
        super().__init__(session, config)
        self.base_url = "https://api.snowtrace.io/api"
        self.api_key = config.SNOWTRACE_API_KEY

    async def get_address_transactions(self, address: str, limit: int = 100) -> List[Dict]:
        """Get AVAX transactions"""
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "sort": "desc",
            "apikey": self.api_key
        }

        data = await self._get("", params)
        return data.get("result", [])[:limit] if data else []

    async def get_transaction(self, txid: str) -> Optional[Dict]:
        """Get transaction details"""
        return None

    async def get_address_balance(self, address: str) -> float:
        """Get AVAX balance"""
        params = {
            "module": "account",
            "action": "balance",
            "address": address,
            "apikey": self.api_key
        }

        data = await self._get("", params)
        if data and data.get("status") == "1":
            balance_wei = int(data.get("result", 0))
            return balance_wei / 1e18

        return 0.0

    async def get_current_price(self) -> float:
        """Get AVAX price"""
        return 0.0


class SolscanClient(BaseBlockchainClient):
    """Solscan API client for Solana"""

    def __init__(self, session: aiohttp.ClientSession, config):
        super().__init__(session, config)
        self.base_url = "https://api.solscan.io"

    async def get_address_transactions(self, address: str, limit: int = 100) -> List[Dict]:
        """Get SOL transactions"""
        endpoint = f"/account/transactions"
        params = {"account": address, "limit": limit}

        data = await self._get(endpoint, params)
        return data if isinstance(data, list) else []

    async def get_transaction(self, txid: str) -> Optional[Dict]:
        """Get transaction details"""
        endpoint = f"/transaction/{txid}"
        return await self._get(endpoint)

    async def get_address_balance(self, address: str) -> float:
        """Get SOL balance"""
        endpoint = f"/account/{address}"
        data = await self._get(endpoint)

        if data:
            lamports = data.get("lamports", 0)
            return lamports / 1e9  # Lamports to SOL

        return 0.0

    async def get_current_price(self) -> float:
        """Get SOL price"""
        return 0.0


class CardanoScanClient(BaseBlockchainClient):
    """CardanoScan API client"""

    def __init__(self, session: aiohttp.ClientSession, config):
        super().__init__(session, config)
        self.base_url = "https://api.cardanoscan.io"

    async def get_address_transactions(self, address: str, limit: int = 100) -> List[Dict]:
        """Get ADA transactions"""
        # Cardano uses different address format and API structure
        # Placeholder implementation
        return []

    async def get_transaction(self, txid: str) -> Optional[Dict]:
        """Get transaction details"""
        return None

    async def get_address_balance(self, address: str) -> float:
        """Get ADA balance"""
        return 0.0

    async def get_current_price(self) -> float:
        """Get ADA price"""
        return 0.0
