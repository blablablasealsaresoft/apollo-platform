"""
Ethereum API Clients

Clients for Ethereum blockchain explorers:
- etherscan.io
- ethplorer.io
- alchemy.com
"""

import aiohttp
from typing import Dict, List, Optional
from .bitcoin_clients import BaseBlockchainClient


class EtherscanClient(BaseBlockchainClient):
    """Etherscan API client"""

    def __init__(self, session: aiohttp.ClientSession, config):
        super().__init__(session, config)
        self.base_url = "https://api.etherscan.io/api"
        self.api_key = config.ETHERSCAN_API_KEY

    async def get_address_transactions(self, address: str, limit: int = 100) -> List[Dict]:
        """Get transactions for an Ethereum address"""
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "sort": "desc",
            "apikey": self.api_key
        }

        data = await self._get("", params)

        if not data or data.get("status") != "1":
            return []

        return data.get("result", [])[:limit]

    async def get_transaction(self, txid: str) -> Optional[Dict]:
        """Get transaction details"""
        params = {
            "module": "proxy",
            "action": "eth_getTransactionByHash",
            "txhash": txid,
            "apikey": self.api_key
        }

        data = await self._get("", params)
        return data.get("result")

    async def get_address_balance(self, address: str) -> float:
        """Get ETH balance"""
        params = {
            "module": "account",
            "action": "balance",
            "address": address,
            "tag": "latest",
            "apikey": self.api_key
        }

        data = await self._get("", params)

        if not data or data.get("status") != "1":
            return 0.0

        # Wei to ETH
        balance_wei = int(data.get("result", 0))
        return balance_wei / 1e18

    async def get_current_price(self) -> float:
        """Get current ETH price"""
        params = {
            "module": "stats",
            "action": "ethprice",
            "apikey": self.api_key
        }

        data = await self._get("", params)

        if not data or data.get("status") != "1":
            return 0.0

        return float(data.get("result", {}).get("ethusd", 0))


class EthplorerClient(BaseBlockchainClient):
    """Ethplorer API client"""

    def __init__(self, session: aiohttp.ClientSession, config):
        super().__init__(session, config)
        self.base_url = "https://api.ethplorer.io"

    async def get_address_transactions(self, address: str, limit: int = 100) -> List[Dict]:
        """Get transactions for an Ethereum address"""
        endpoint = f"/getAddressHistory/{address}"
        params = {"limit": limit, "apiKey": "freekey"}

        data = await self._get(endpoint, params)
        return data.get("operations", [])

    async def get_transaction(self, txid: str) -> Optional[Dict]:
        """Get transaction details"""
        endpoint = f"/getTxInfo/{txid}"
        params = {"apiKey": "freekey"}

        return await self._get(endpoint, params)

    async def get_address_balance(self, address: str) -> float:
        """Get ETH balance"""
        endpoint = f"/getAddressInfo/{address}"
        params = {"apiKey": "freekey"}

        data = await self._get(endpoint, params)
        return float(data.get("ETH", {}).get("balance", 0))

    async def get_current_price(self) -> float:
        """Ethplorer doesn't provide price data"""
        return 0.0


class AlchemyClient(BaseBlockchainClient):
    """Alchemy API client (premium Ethereum API)"""

    def __init__(self, session: aiohttp.ClientSession, config):
        super().__init__(session, config)
        self.api_key = config.ALCHEMY_API_KEY
        self.base_url = f"https://eth-mainnet.g.alchemy.com/v2/{self.api_key}"

    async def get_address_transactions(self, address: str, limit: int = 100) -> List[Dict]:
        """Get transactions using Alchemy's enhanced API"""
        # Alchemy uses JSON-RPC
        payload = {
            "id": 1,
            "jsonrpc": "2.0",
            "method": "alchemy_getAssetTransfers",
            "params": [{
                "fromAddress": address,
                "category": ["external", "internal", "erc20", "erc721", "erc1155"],
                "maxCount": hex(limit)
            }]
        }

        async with self.session.post(self.base_url, json=payload) as response:
            if response.status == 200:
                data = await response.json()
                return data.get("result", {}).get("transfers", [])

        return []

    async def get_transaction(self, txid: str) -> Optional[Dict]:
        """Get transaction details"""
        payload = {
            "id": 1,
            "jsonrpc": "2.0",
            "method": "eth_getTransactionByHash",
            "params": [txid]
        }

        async with self.session.post(self.base_url, json=payload) as response:
            if response.status == 200:
                data = await response.json()
                return data.get("result")

        return None

    async def get_address_balance(self, address: str) -> float:
        """Get ETH balance"""
        payload = {
            "id": 1,
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [address, "latest"]
        }

        async with self.session.post(self.base_url, json=payload) as response:
            if response.status == 200:
                data = await response.json()
                balance_hex = data.get("result", "0x0")
                balance_wei = int(balance_hex, 16)
                return balance_wei / 1e18

        return 0.0

    async def get_current_price(self) -> float:
        """Alchemy doesn't provide price data"""
        return 0.0
