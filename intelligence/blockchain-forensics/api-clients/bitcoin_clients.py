"""
Bitcoin API Clients

Clients for Bitcoin blockchain explorers:
- blockchain.info
- blockchair.com
- blockcypher.com
- btc.com
"""

import aiohttp
from typing import Dict, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class BaseBlockchainClient:
    """Base class for blockchain API clients"""

    def __init__(self, session: aiohttp.ClientSession, config):
        self.session = session
        self.config = config
        self.base_url = ""

    async def _get(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        """Make GET request"""
        url = f"{self.base_url}{endpoint}"

        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    logger.error(f"API error: {response.status} from {url}")
                    return {}
        except Exception as e:
            logger.error(f"Request error: {e}")
            return {}


class BlockchainInfoClient(BaseBlockchainClient):
    """
    Blockchain.info API client
    https://www.blockchain.com/api/blockchain_api
    """

    def __init__(self, session: aiohttp.ClientSession, config):
        super().__init__(session, config)
        self.base_url = "https://blockchain.info"

    async def get_address_transactions(
        self,
        address: str,
        limit: int = 100
    ) -> List[Dict]:
        """Get transactions for an address"""
        endpoint = f"/rawaddr/{address}"
        params = {"limit": limit}

        data = await self._get(endpoint, params)

        if not data or "txs" not in data:
            return []

        transactions = []
        for tx in data.get("txs", []):
            # Parse transaction
            parsed_tx = {
                "txid": tx.get("hash"),
                "timestamp": tx.get("time"),
                "inputs": [
                    {
                        "address": inp.get("prev_out", {}).get("addr"),
                        "amount": inp.get("prev_out", {}).get("value", 0) / 1e8,  # satoshis to BTC
                    }
                    for inp in tx.get("inputs", [])
                ],
                "outputs": [
                    {
                        "address": out.get("addr"),
                        "amount": out.get("value", 0) / 1e8,
                    }
                    for out in tx.get("out", [])
                ],
                "fee": tx.get("fee", 0) / 1e8,
            }

            transactions.append(parsed_tx)

        return transactions

    async def get_transaction(self, txid: str) -> Optional[Dict]:
        """Get transaction details"""
        endpoint = f"/rawtx/{txid}"

        data = await self._get(endpoint)

        if not data:
            return None

        return {
            "txid": data.get("hash"),
            "timestamp": data.get("time"),
            "inputs": [
                {
                    "address": inp.get("prev_out", {}).get("addr"),
                    "amount": inp.get("prev_out", {}).get("value", 0) / 1e8,
                }
                for inp in data.get("inputs", [])
            ],
            "outputs": [
                {
                    "address": out.get("addr"),
                    "amount": out.get("value", 0) / 1e8,
                }
                for out in data.get("out", [])
            ],
            "fee": data.get("fee", 0) / 1e8,
        }

    async def get_address_balance(self, address: str) -> float:
        """Get address balance"""
        endpoint = f"/balance?active={address}"

        data = await self._get(endpoint)

        if not data or address not in data:
            return 0.0

        # Balance in satoshis, convert to BTC
        balance_satoshis = data[address].get("final_balance", 0)
        return balance_satoshis / 1e8

    async def get_current_price(self) -> float:
        """Get current BTC price in USD"""
        endpoint = "/ticker"

        data = await self._get(endpoint)

        if not data or "USD" not in data:
            return 0.0

        return float(data["USD"].get("last", 0))


class BlockchairClient(BaseBlockchainClient):
    """
    Blockchair API client
    https://blockchair.com/api
    """

    def __init__(self, session: aiohttp.ClientSession, config):
        super().__init__(session, config)
        self.base_url = "https://api.blockchair.com/bitcoin"

    async def get_address_transactions(
        self,
        address: str,
        limit: int = 100
    ) -> List[Dict]:
        """Get transactions for an address"""
        endpoint = f"/dashboards/address/{address}"
        params = {"limit": limit}

        data = await self._get(endpoint, params)

        if not data or "data" not in data:
            return []

        addr_data = data["data"].get(address, {})
        transactions = []

        for tx in addr_data.get("transactions", []):
            transactions.append({
                "txid": tx.get("hash"),
                "timestamp": datetime.fromisoformat(tx.get("time").replace("Z", "+00:00")).timestamp() if tx.get("time") else None,
                "amount": tx.get("balance_change", 0) / 1e8,
                "fee": 0,  # Blockchair doesn't provide fee in transaction list
            })

        return transactions

    async def get_transaction(self, txid: str) -> Optional[Dict]:
        """Get transaction details"""
        endpoint = f"/dashboards/transaction/{txid}"

        data = await self._get(endpoint)

        if not data or "data" not in data:
            return None

        tx_data = data["data"].get(txid, {}).get("transaction", {})

        return {
            "txid": tx_data.get("hash"),
            "timestamp": datetime.fromisoformat(tx_data.get("time").replace("Z", "+00:00")).timestamp() if tx_data.get("time") else None,
            "inputs": [
                {
                    "address": inp.get("recipient"),
                    "amount": inp.get("value", 0) / 1e8,
                }
                for inp in data["data"].get(txid, {}).get("inputs", [])
            ],
            "outputs": [
                {
                    "address": out.get("recipient"),
                    "amount": out.get("value", 0) / 1e8,
                }
                for out in data["data"].get(txid, {}).get("outputs", [])
            ],
            "fee": tx_data.get("fee", 0) / 1e8,
        }

    async def get_address_balance(self, address: str) -> float:
        """Get address balance"""
        endpoint = f"/dashboards/address/{address}"

        data = await self._get(endpoint)

        if not data or "data" not in data:
            return 0.0

        addr_data = data["data"].get(address, {}).get("address", {})
        balance_satoshis = addr_data.get("balance", 0)

        return balance_satoshis / 1e8

    async def get_current_price(self) -> float:
        """Get current BTC price"""
        # Blockchair provides price in their stats endpoint
        endpoint = "/stats"

        data = await self._get(endpoint)

        if not data or "data" not in data:
            return 0.0

        return float(data["data"].get("market_price_usd", 0))


class BlockCypherClient(BaseBlockchainClient):
    """
    BlockCypher API client
    https://www.blockcypher.com/dev/bitcoin/
    """

    def __init__(self, session: aiohttp.ClientSession, config):
        super().__init__(session, config)
        self.base_url = "https://api.blockcypher.com/v1/btc/main"
        self.api_key = config.BLOCKCYPHER_API_KEY

    async def get_address_transactions(
        self,
        address: str,
        limit: int = 100
    ) -> List[Dict]:
        """Get transactions for an address"""
        endpoint = f"/addrs/{address}/full"
        params = {"limit": limit}

        if self.api_key:
            params["token"] = self.api_key

        data = await self._get(endpoint, params)

        if not data or "txs" not in data:
            return []

        transactions = []
        for tx in data.get("txs", []):
            transactions.append({
                "txid": tx.get("hash"),
                "timestamp": datetime.fromisoformat(tx.get("confirmed").replace("Z", "+00:00")).timestamp() if tx.get("confirmed") else None,
                "inputs": [
                    {
                        "address": inp.get("addresses", [""])[0] if inp.get("addresses") else "",
                        "amount": inp.get("output_value", 0) / 1e8,
                    }
                    for inp in tx.get("inputs", [])
                ],
                "outputs": [
                    {
                        "address": out.get("addresses", [""])[0] if out.get("addresses") else "",
                        "amount": out.get("value", 0) / 1e8,
                    }
                    for out in tx.get("outputs", [])
                ],
                "fee": tx.get("fees", 0) / 1e8,
                "confirmations": tx.get("confirmations", 0),
            })

        return transactions

    async def get_transaction(self, txid: str) -> Optional[Dict]:
        """Get transaction details"""
        endpoint = f"/txs/{txid}"
        params = {}

        if self.api_key:
            params["token"] = self.api_key

        data = await self._get(endpoint, params)

        if not data:
            return None

        return {
            "txid": data.get("hash"),
            "timestamp": datetime.fromisoformat(data.get("confirmed").replace("Z", "+00:00")).timestamp() if data.get("confirmed") else None,
            "inputs": [
                {
                    "address": inp.get("addresses", [""])[0] if inp.get("addresses") else "",
                    "amount": inp.get("output_value", 0) / 1e8,
                }
                for inp in data.get("inputs", [])
            ],
            "outputs": [
                {
                    "address": out.get("addresses", [""])[0] if out.get("addresses") else "",
                    "amount": out.get("value", 0) / 1e8,
                }
                for out in data.get("outputs", [])
            ],
            "fee": data.get("fees", 0) / 1e8,
            "confirmations": data.get("confirmations", 0),
        }

    async def get_address_balance(self, address: str) -> float:
        """Get address balance"""
        endpoint = f"/addrs/{address}/balance"
        params = {}

        if self.api_key:
            params["token"] = self.api_key

        data = await self._get(endpoint, params)

        if not data:
            return 0.0

        balance_satoshis = data.get("final_balance", 0)
        return balance_satoshis / 1e8

    async def get_current_price(self) -> float:
        """BlockCypher doesn't provide price data"""
        return 0.0


class BTCComClient(BaseBlockchainClient):
    """
    BTC.com API client
    https://btc.com/api-doc
    """

    def __init__(self, session: aiohttp.ClientSession, config):
        super().__init__(session, config)
        self.base_url = "https://chain.api.btc.com/v3"

    async def get_address_transactions(
        self,
        address: str,
        limit: int = 100
    ) -> List[Dict]:
        """Get transactions for an address"""
        endpoint = f"/address/{address}/tx"
        params = {"pagesize": min(limit, 50)}  # BTC.com max 50 per page

        data = await self._get(endpoint, params)

        if not data or "data" not in data:
            return []

        transactions = []
        for tx in data["data"].get("list", []):
            transactions.append({
                "txid": tx.get("hash"),
                "timestamp": tx.get("block_time"),
                "amount": tx.get("balance_diff", 0) / 1e8,
                "fee": tx.get("fee", 0) / 1e8,
                "confirmations": tx.get("confirmations", 0),
            })

        return transactions

    async def get_transaction(self, txid: str) -> Optional[Dict]:
        """Get transaction details"""
        endpoint = f"/tx/{txid}"

        data = await self._get(endpoint)

        if not data or "data" not in data:
            return None

        tx_data = data["data"]

        return {
            "txid": tx_data.get("hash"),
            "timestamp": tx_data.get("block_time"),
            "inputs": [
                {
                    "address": inp.get("prev_addresses", [""])[0] if inp.get("prev_addresses") else "",
                    "amount": inp.get("prev_value", 0) / 1e8,
                }
                for inp in tx_data.get("inputs", [])
            ],
            "outputs": [
                {
                    "address": out.get("addresses", [""])[0] if out.get("addresses") else "",
                    "amount": out.get("value", 0) / 1e8,
                }
                for out in tx_data.get("outputs", [])
            ],
            "fee": tx_data.get("fee", 0) / 1e8,
            "confirmations": tx_data.get("confirmations", 0),
        }

    async def get_address_balance(self, address: str) -> float:
        """Get address balance"""
        endpoint = f"/address/{address}"

        data = await self._get(endpoint)

        if not data or "data" not in data:
            return 0.0

        balance_satoshis = data["data"].get("balance", 0)
        return balance_satoshis / 1e8

    async def get_current_price(self) -> float:
        """BTC.com doesn't provide price data in API"""
        return 0.0
