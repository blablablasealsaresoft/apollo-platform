"""
Ethereum API Clients

Clients for Ethereum blockchain explorers:
- etherscan.io (free tier with API key)
- ethplorer.io (free with 'freekey')
- alchemy.com (free tier with API key)
- infura.io (free tier with API key)

Each client supports:
- Transaction history
- ERC-20 token transfers
- Smart contract interactions
- Gas estimation
"""

import aiohttp
from typing import Dict, List, Optional, Any
from datetime import datetime
from decimal import Decimal
import logging

from .bitcoin_clients import BaseBlockchainClient

logger = logging.getLogger(__name__)


class EtherscanClient(BaseBlockchainClient):
    """
    Etherscan API client

    Free tier: 5 calls/second, 100,000 calls/day
    Requires API key for best results (get free at etherscan.io)
    """

    def __init__(self, session: aiohttp.ClientSession, config):
        super().__init__(session, config)
        self.base_url = "https://api.etherscan.io/api"
        self.api_key = getattr(config, 'ETHERSCAN_API_KEY', '')

    async def get_address_transactions(self, address: str, limit: int = 100) -> List[Dict]:
        """Get transactions for an Ethereum address"""
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "sort": "desc",
            "offset": min(limit, 10000),
            "apikey": self.api_key
        }

        data = await self._get("", params)

        if not data or data.get("status") != "1":
            # Check if it's just "no transactions"
            if data and "No transactions found" in str(data.get("result", "")):
                return []
            return []

        transactions = []
        for tx in data.get("result", [])[:limit]:
            # Parse to normalized format
            value_wei = int(tx.get("value", 0))
            gas_price = int(tx.get("gasPrice", 0))
            gas_used = int(tx.get("gasUsed", 0))

            transactions.append({
                "txid": tx.get("hash"),
                "timestamp": int(tx.get("timeStamp", 0)),
                "block_height": int(tx.get("blockNumber", 0)),
                "from_address": tx.get("from", ""),
                "to_address": tx.get("to", ""),
                "value": value_wei / 1e18,  # ETH
                "value_wei": value_wei,
                "gas_price": gas_price,
                "gas_used": gas_used,
                "fee": (gas_price * gas_used) / 1e18,
                "confirmations": int(tx.get("confirmations", 0)),
                "is_error": tx.get("isError") == "1",
                "input": tx.get("input", "0x"),
                "contract_address": tx.get("contractAddress", ""),
            })

        return transactions

    async def get_transaction(self, txid: str) -> Optional[Dict]:
        """Get transaction details"""
        params = {
            "module": "proxy",
            "action": "eth_getTransactionByHash",
            "txhash": txid,
            "apikey": self.api_key
        }

        data = await self._get("", params)
        result = data.get("result") if data else None

        if not result:
            return None

        # Parse hex values
        value_wei = int(result.get("value", "0x0"), 16)
        gas = int(result.get("gas", "0x0"), 16)
        gas_price = int(result.get("gasPrice", "0x0"), 16)

        return {
            "txid": result.get("hash"),
            "block_number": int(result.get("blockNumber", "0x0"), 16) if result.get("blockNumber") else None,
            "from_address": result.get("from", ""),
            "to_address": result.get("to", ""),
            "value": value_wei / 1e18,
            "value_wei": value_wei,
            "gas": gas,
            "gas_price": gas_price,
            "input": result.get("input", "0x"),
            "nonce": int(result.get("nonce", "0x0"), 16),
        }

    async def get_address_balance(self, address: str) -> float:
        """Get ETH balance in ETH"""
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

        balance_wei = int(data.get("result", 0))
        return balance_wei / 1e18

    async def get_erc20_transfers(
        self,
        address: str,
        contract_address: str = None,
        limit: int = 100
    ) -> List[Dict]:
        """Get ERC-20 token transfers for an address"""
        params = {
            "module": "account",
            "action": "tokentx",
            "address": address,
            "sort": "desc",
            "offset": min(limit, 10000),
            "apikey": self.api_key
        }

        if contract_address:
            params["contractaddress"] = contract_address

        data = await self._get("", params)

        if not data or data.get("status") != "1":
            return []

        transfers = []
        for tx in data.get("result", [])[:limit]:
            decimals = int(tx.get("tokenDecimal", 18))
            value = int(tx.get("value", 0))

            transfers.append({
                "tx_hash": tx.get("hash"),
                "timestamp": int(tx.get("timeStamp", 0)),
                "from_address": tx.get("from", ""),
                "to_address": tx.get("to", ""),
                "value": value / (10 ** decimals),
                "value_raw": value,
                "token_name": tx.get("tokenName", ""),
                "token_symbol": tx.get("tokenSymbol", ""),
                "token_decimals": decimals,
                "contract_address": tx.get("contractAddress", ""),
            })

        return transfers

    async def get_internal_transactions(self, address: str, limit: int = 100) -> List[Dict]:
        """Get internal transactions (traces) for an address"""
        params = {
            "module": "account",
            "action": "txlistinternal",
            "address": address,
            "sort": "desc",
            "offset": min(limit, 10000),
            "apikey": self.api_key
        }

        data = await self._get("", params)

        if not data or data.get("status") != "1":
            return []

        return [
            {
                "tx_hash": tx.get("hash"),
                "timestamp": int(tx.get("timeStamp", 0)),
                "from_address": tx.get("from", ""),
                "to_address": tx.get("to", ""),
                "value": int(tx.get("value", 0)) / 1e18,
                "type": tx.get("type", "call"),
                "is_error": tx.get("isError") == "1",
            }
            for tx in data.get("result", [])[:limit]
        ]

    async def get_gas_oracle(self) -> Dict[str, int]:
        """Get current gas prices"""
        params = {
            "module": "gastracker",
            "action": "gasoracle",
            "apikey": self.api_key
        }

        data = await self._get("", params)

        if not data or data.get("status") != "1":
            return {"safe": 20, "propose": 25, "fast": 35}

        result = data.get("result", {})
        return {
            "safe": int(result.get("SafeGasPrice", 20)),
            "propose": int(result.get("ProposeGasPrice", 25)),
            "fast": int(result.get("FastGasPrice", 35)),
            "base_fee": float(result.get("suggestBaseFee", 0)),
        }

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

    async def get_contract_abi(self, address: str) -> Optional[str]:
        """Get ABI for a verified contract"""
        params = {
            "module": "contract",
            "action": "getabi",
            "address": address,
            "apikey": self.api_key
        }

        data = await self._get("", params)

        if data and data.get("status") == "1":
            return data.get("result")
        return None

    async def is_contract(self, address: str) -> bool:
        """Check if an address is a contract"""
        params = {
            "module": "proxy",
            "action": "eth_getCode",
            "address": address,
            "tag": "latest",
            "apikey": self.api_key
        }

        data = await self._get("", params)

        if data:
            code = data.get("result", "0x")
            return code != "0x" and len(code) > 2

        return False


class EthplorerClient(BaseBlockchainClient):
    """
    Ethplorer API client

    Free with 'freekey' - 2 requests/second
    Excellent for token analysis
    """

    def __init__(self, session: aiohttp.ClientSession, config):
        super().__init__(session, config)
        self.base_url = "https://api.ethplorer.io"
        self.api_key = getattr(config, 'ETHPLORER_API_KEY', 'freekey')

    async def get_address_transactions(self, address: str, limit: int = 100) -> List[Dict]:
        """Get transactions for an Ethereum address"""
        endpoint = f"/getAddressHistory/{address}"
        params = {"limit": min(limit, 1000), "apiKey": self.api_key}

        data = await self._get(endpoint, params)

        if not data:
            return []

        operations = data.get("operations", [])
        transactions = []

        for op in operations:
            tx = {
                "txid": op.get("transactionHash"),
                "timestamp": op.get("timestamp"),
                "from_address": op.get("from", ""),
                "to_address": op.get("to", ""),
                "value": float(op.get("value", 0)),
                "token_info": op.get("tokenInfo", {}),
                "type": op.get("type", "transfer"),
            }
            transactions.append(tx)

        return transactions

    async def get_transaction(self, txid: str) -> Optional[Dict]:
        """Get transaction details"""
        endpoint = f"/getTxInfo/{txid}"
        params = {"apiKey": self.api_key}

        data = await self._get(endpoint, params)

        if not data:
            return None

        return {
            "txid": data.get("hash"),
            "timestamp": data.get("timestamp"),
            "block_number": data.get("blockNumber"),
            "from_address": data.get("from", ""),
            "to_address": data.get("to", ""),
            "value": float(data.get("value", 0)),
            "success": data.get("success", True),
            "operations": data.get("operations", []),
        }

    async def get_address_balance(self, address: str) -> float:
        """Get ETH balance"""
        endpoint = f"/getAddressInfo/{address}"
        params = {"apiKey": self.api_key}

        data = await self._get(endpoint, params)

        if not data:
            return 0.0

        return float(data.get("ETH", {}).get("balance", 0))

    async def get_address_info(self, address: str) -> Optional[Dict]:
        """Get comprehensive address information including tokens"""
        endpoint = f"/getAddressInfo/{address}"
        params = {"apiKey": self.api_key}

        data = await self._get(endpoint, params)

        if not data:
            return None

        # Parse token balances
        tokens = []
        for token in data.get("tokens", []):
            token_info = token.get("tokenInfo", {})
            decimals = int(token_info.get("decimals", 18) or 18)
            balance = float(token.get("balance", 0))

            tokens.append({
                "contract_address": token_info.get("address"),
                "name": token_info.get("name", "Unknown"),
                "symbol": token_info.get("symbol", ""),
                "decimals": decimals,
                "balance": balance / (10 ** decimals) if decimals else balance,
                "balance_raw": balance,
            })

        return {
            "address": address,
            "eth_balance": float(data.get("ETH", {}).get("balance", 0)),
            "token_count": len(tokens),
            "tokens": tokens,
            "count_txs": data.get("countTxs", 0),
        }

    async def get_token_info(self, contract_address: str) -> Optional[Dict]:
        """Get information about an ERC-20 token"""
        endpoint = f"/getTokenInfo/{contract_address}"
        params = {"apiKey": self.api_key}

        data = await self._get(endpoint, params)

        if not data:
            return None

        return {
            "address": data.get("address"),
            "name": data.get("name", ""),
            "symbol": data.get("symbol", ""),
            "decimals": int(data.get("decimals", 18) or 18),
            "total_supply": data.get("totalSupply"),
            "holders_count": data.get("holdersCount", 0),
            "transfers_count": data.get("transfersCount", 0),
            "price": data.get("price", {}),
        }

    async def get_top_token_holders(self, contract_address: str, limit: int = 100) -> List[Dict]:
        """Get top holders of a token"""
        endpoint = f"/getTopTokenHolders/{contract_address}"
        params = {"limit": min(limit, 1000), "apiKey": self.api_key}

        data = await self._get(endpoint, params)

        if not data or "holders" not in data:
            return []

        return [
            {
                "address": holder.get("address"),
                "balance": float(holder.get("balance", 0)),
                "share": float(holder.get("share", 0)),
            }
            for holder in data.get("holders", [])
        ]

    async def get_current_price(self) -> float:
        """Get ETH price via top token info"""
        # Ethplorer doesn't have a direct price endpoint
        # but we can get it from token price data
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
