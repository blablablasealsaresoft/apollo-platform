"""
Enhanced API Endpoints for Blockchain Forensics

Production-ready FastAPI endpoints for:
- Bitcoin tracking
- Ethereum tracking
- Wallet clustering
- AML scoring
- Transaction tracing
"""

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from enum import Enum
import logging
import asyncio

# Import our real implementations
from .api_clients.real_bitcoin_tracker import RealBitcoinTracker, UTXO, AddressStats
from .api_clients.real_ethereum_tracker import RealEthereumTracker
from .clustering.real_clustering_engine import RealWalletClusteringEngine, AddressCluster
from .aml.real_aml_scoring import RealAMLScoringEngine, RiskLevel

logger = logging.getLogger(__name__)

# =====================================================
# Pydantic Models
# =====================================================

class BlockchainType(str, Enum):
    BITCOIN = "bitcoin"
    ETHEREUM = "ethereum"
    BSC = "bsc"
    POLYGON = "polygon"


class AddressInfoRequest(BaseModel):
    address: str = Field(..., description="Blockchain address")
    blockchain: BlockchainType = Field(default=BlockchainType.BITCOIN)

    @validator('address')
    def validate_address(cls, v):
        if not v or len(v) < 20:
            raise ValueError('Invalid address format')
        return v


class TransactionRequest(BaseModel):
    txid: str = Field(..., description="Transaction hash")
    blockchain: BlockchainType = Field(default=BlockchainType.BITCOIN)


class AddressTransactionsRequest(BaseModel):
    address: str
    blockchain: BlockchainType = Field(default=BlockchainType.BITCOIN)
    limit: int = Field(default=50, ge=1, le=1000)


class ClusteringRequest(BaseModel):
    seed_address: str = Field(..., description="Seed address to cluster from")
    blockchain: BlockchainType = Field(default=BlockchainType.BITCOIN)
    max_depth: int = Field(default=2, ge=1, le=5)


class AMLScreeningRequest(BaseModel):
    address: str
    blockchain: BlockchainType = Field(default=BlockchainType.BITCOIN)
    include_transactions: bool = Field(default=True)


class TraceRequest(BaseModel):
    txid: str
    blockchain: BlockchainType = Field(default=BlockchainType.BITCOIN)
    direction: str = Field(default="both", description="inputs, outputs, or both")
    max_depth: int = Field(default=3, ge=1, le=10)


class UTXOResponse(BaseModel):
    txid: str
    vout: int
    value_satoshis: int
    value_btc: float
    address: str
    confirmations: int
    block_height: Optional[int]


class AddressInfoResponse(BaseModel):
    address: str
    blockchain: str
    balance: float
    balance_usd: Optional[float]
    total_received: float
    total_sent: float
    tx_count: int
    utxo_count: Optional[int]
    first_seen: Optional[str]
    last_seen: Optional[str]


class TransactionResponse(BaseModel):
    txid: str
    blockchain: str
    confirmed: bool
    block_height: Optional[int]
    timestamp: Optional[int]
    fee: float
    input_value: float
    output_value: float
    input_count: int
    output_count: int
    inputs: List[Dict[str, Any]]
    outputs: List[Dict[str, Any]]


class ClusterResponse(BaseModel):
    cluster_id: str
    address_count: int
    addresses: List[str]
    confidence: float
    evidence_count: int
    evidence_types: List[str]


class AMLScoreResponse(BaseModel):
    address: str
    blockchain: str
    total_score: int
    risk_level: str
    red_flags: List[str]
    recommendations: List[str]
    risk_factors: List[Dict[str, Any]]
    analysis_timestamp: str


class FeeEstimateResponse(BaseModel):
    blockchain: str
    fastest: int
    half_hour: int
    hour: int
    economy: int
    minimum: int
    unit: str


# =====================================================
# FastAPI Application
# =====================================================

app = FastAPI(
    title="Apollo Blockchain Forensics API",
    description="Production blockchain intelligence and AML scoring API",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global clients (initialized on startup)
bitcoin_tracker: Optional[RealBitcoinTracker] = None
ethereum_tracker: Optional[RealEthereumTracker] = None
clustering_engine: Optional[RealWalletClusteringEngine] = None
aml_engine: Optional[RealAMLScoringEngine] = None


@app.on_event("startup")
async def startup():
    """Initialize services on startup"""
    global bitcoin_tracker, ethereum_tracker, clustering_engine, aml_engine

    logger.info("Starting Blockchain Forensics API...")

    bitcoin_tracker = RealBitcoinTracker()
    ethereum_tracker = RealEthereumTracker()
    clustering_engine = RealWalletClusteringEngine()
    aml_engine = RealAMLScoringEngine()

    logger.info("Blockchain Forensics API ready")


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown"""
    global bitcoin_tracker, ethereum_tracker

    if bitcoin_tracker:
        await bitcoin_tracker.close()
    if ethereum_tracker:
        await ethereum_tracker.close()

    logger.info("Blockchain Forensics API shutdown complete")


# =====================================================
# Health Check Endpoints
# =====================================================

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0",
        "services": {
            "bitcoin_tracker": bitcoin_tracker is not None,
            "ethereum_tracker": ethereum_tracker is not None,
            "clustering_engine": clustering_engine is not None,
            "aml_engine": aml_engine is not None
        }
    }


@app.get("/api/v2/status")
async def api_status():
    """Get API status and capabilities"""
    return {
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
        "supported_blockchains": ["bitcoin", "ethereum", "bsc", "polygon"],
        "features": {
            "address_lookup": True,
            "transaction_lookup": True,
            "utxo_tracking": True,
            "wallet_clustering": True,
            "aml_scoring": True,
            "transaction_tracing": True,
            "fee_estimation": True
        },
        "rate_limits": {
            "bitcoin": "10 req/sec (Blockstream/Mempool.space)",
            "ethereum": "5 req/sec (Etherscan free tier)"
        }
    }


# =====================================================
# Bitcoin Endpoints
# =====================================================

@app.get("/api/v2/bitcoin/address/{address}", response_model=AddressInfoResponse)
async def get_bitcoin_address(address: str):
    """
    Get Bitcoin address information

    Returns balance, transaction count, and statistics.
    """
    info = await bitcoin_tracker.get_address_info(address)

    if not info:
        raise HTTPException(status_code=404, detail="Address not found")

    return AddressInfoResponse(
        address=info.address,
        blockchain="bitcoin",
        balance=info.balance_btc,
        balance_usd=None,  # Would need price API
        total_received=info.total_received_satoshis / 1e8,
        total_sent=info.total_sent_satoshis / 1e8,
        tx_count=info.tx_count,
        utxo_count=info.utxo_count,
        first_seen=None,
        last_seen=None
    )


@app.get("/api/v2/bitcoin/address/{address}/transactions")
async def get_bitcoin_address_transactions(
    address: str,
    limit: int = Query(default=25, ge=1, le=100)
):
    """Get transactions for a Bitcoin address"""
    transactions = await bitcoin_tracker.get_address_transactions(address, limit=limit)

    return {
        "address": address,
        "transaction_count": len(transactions),
        "transactions": [
            {
                "txid": tx.txid,
                "confirmed": tx.confirmed,
                "block_height": tx.block_height,
                "timestamp": tx.block_time,
                "fee": tx.fee,
                "input_value": tx.input_value,
                "output_value": tx.output_value,
                "input_count": len(tx.inputs),
                "output_count": len(tx.outputs)
            }
            for tx in transactions
        ]
    }


@app.get("/api/v2/bitcoin/address/{address}/utxos")
async def get_bitcoin_utxos(address: str):
    """Get unspent transaction outputs for a Bitcoin address"""
    utxos = await bitcoin_tracker.get_address_utxos(address)

    return {
        "address": address,
        "utxo_count": len(utxos),
        "total_value_btc": sum(u.value_btc for u in utxos),
        "utxos": [
            {
                "txid": u.txid,
                "vout": u.vout,
                "value_satoshis": u.value_satoshis,
                "value_btc": u.value_btc,
                "block_height": u.block_height
            }
            for u in utxos
        ]
    }


@app.get("/api/v2/bitcoin/tx/{txid}", response_model=TransactionResponse)
async def get_bitcoin_transaction(txid: str):
    """Get Bitcoin transaction details"""
    tx = await bitcoin_tracker.get_transaction(txid)

    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    return TransactionResponse(
        txid=tx.txid,
        blockchain="bitcoin",
        confirmed=tx.confirmed,
        block_height=tx.block_height,
        timestamp=tx.block_time,
        fee=tx.fee / 1e8,
        input_value=tx.input_value / 1e8,
        output_value=tx.output_value / 1e8,
        input_count=len(tx.inputs),
        output_count=len(tx.outputs),
        inputs=tx.inputs,
        outputs=tx.outputs
    )


@app.get("/api/v2/bitcoin/fees", response_model=FeeEstimateResponse)
async def get_bitcoin_fee_estimates():
    """Get current Bitcoin fee estimates"""
    fees = await bitcoin_tracker.get_fee_estimates()

    return FeeEstimateResponse(
        blockchain="bitcoin",
        fastest=fees['fastest'],
        half_hour=fees['half_hour'],
        hour=fees['hour'],
        economy=fees['economy'],
        minimum=fees['minimum'],
        unit="sat/vB"
    )


@app.get("/api/v2/bitcoin/block-height")
async def get_bitcoin_block_height():
    """Get current Bitcoin block height"""
    height = await bitcoin_tracker.get_block_height()

    return {
        "blockchain": "bitcoin",
        "block_height": height,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/api/v2/bitcoin/trace")
async def trace_bitcoin_transaction(request: TraceRequest):
    """Trace Bitcoin transaction inputs/outputs"""
    if request.direction == "inputs":
        result = await bitcoin_tracker.trace_transaction_inputs(
            request.txid,
            max_depth=request.max_depth
        )
    elif request.direction == "outputs":
        result = await bitcoin_tracker.trace_transaction_outputs(
            request.txid,
            max_depth=request.max_depth
        )
    else:
        # Trace both
        inputs = await bitcoin_tracker.trace_transaction_inputs(
            request.txid,
            max_depth=request.max_depth
        )
        outputs = await bitcoin_tracker.trace_transaction_outputs(
            request.txid,
            max_depth=request.max_depth
        )
        result = {
            "txid": request.txid,
            "inputs_trace": inputs,
            "outputs_trace": outputs
        }

    return result


@app.get("/api/v2/bitcoin/address/{address}/analysis")
async def analyze_bitcoin_address(address: str):
    """Comprehensive Bitcoin address analysis"""
    analysis = await bitcoin_tracker.analyze_address_patterns(address)
    return analysis


# =====================================================
# Ethereum Endpoints
# =====================================================

@app.get("/api/v2/ethereum/address/{address}")
async def get_ethereum_address(address: str):
    """Get Ethereum address information"""
    info = await ethereum_tracker.get_address_info(address)

    if not info:
        raise HTTPException(status_code=404, detail="Address not found")

    return {
        "address": info.address,
        "blockchain": "ethereum",
        "balance_eth": info.balance_eth,
        "balance_wei": info.balance_wei,
        "tx_count": info.tx_count,
        "is_contract": info.is_contract,
        "token_count": len(info.token_balances),
        "top_tokens": [
            {
                "symbol": tb.symbol,
                "name": tb.name,
                "balance": float(tb.balance),
                "contract": tb.contract_address
            }
            for tb in sorted(info.token_balances, key=lambda x: x.balance, reverse=True)[:10]
        ]
    }


@app.get("/api/v2/ethereum/address/{address}/transactions")
async def get_ethereum_address_transactions(
    address: str,
    page: int = Query(default=1, ge=1),
    offset: int = Query(default=50, ge=1, le=100)
):
    """Get transactions for an Ethereum address"""
    transactions = await ethereum_tracker.get_address_transactions(
        address, page=page, offset=offset
    )

    return {
        "address": address,
        "page": page,
        "transaction_count": len(transactions),
        "transactions": [
            {
                "tx_hash": tx.tx_hash,
                "block_number": tx.block_number,
                "timestamp": tx.timestamp,
                "from": tx.from_address,
                "to": tx.to_address,
                "value_eth": tx.value_eth,
                "fee_eth": tx.fee_eth,
                "is_error": tx.is_error
            }
            for tx in transactions
        ]
    }


@app.get("/api/v2/ethereum/address/{address}/tokens")
async def get_ethereum_token_transfers(
    address: str,
    contract: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    offset: int = Query(default=50, ge=1, le=100)
):
    """Get ERC-20 token transfers for an Ethereum address"""
    transfers = await ethereum_tracker.get_erc20_transfers(
        address,
        contract_address=contract,
        page=page,
        offset=offset
    )

    return {
        "address": address,
        "transfer_count": len(transfers),
        "transfers": [
            {
                "tx_hash": t.tx_hash,
                "block_number": t.block_number,
                "timestamp": t.timestamp,
                "from": t.from_address,
                "to": t.to_address,
                "value": float(t.value),
                "token_name": t.token_name,
                "token_symbol": t.token_symbol,
                "contract": t.contract_address
            }
            for t in transfers
        ]
    }


@app.get("/api/v2/ethereum/tx/{txid}")
async def get_ethereum_transaction(txid: str):
    """Get Ethereum transaction details"""
    tx = await ethereum_tracker.get_transaction(txid)

    if not tx:
        raise HTTPException(status_code=404, detail="Transaction not found")

    return {
        "tx_hash": tx.tx_hash,
        "blockchain": "ethereum",
        "block_number": tx.block_number,
        "timestamp": tx.timestamp,
        "from": tx.from_address,
        "to": tx.to_address,
        "value_eth": tx.value_eth,
        "gas_used": tx.gas_used,
        "gas_price": tx.gas_price,
        "fee_eth": tx.fee_eth,
        "is_error": tx.is_error,
        "confirmations": tx.confirmations,
        "input_data": tx.input_data[:100] + "..." if len(tx.input_data) > 100 else tx.input_data
    }


@app.get("/api/v2/ethereum/gas")
async def get_ethereum_gas_prices():
    """Get current Ethereum gas prices"""
    gas = await ethereum_tracker.get_gas_oracle()
    eth_price = await ethereum_tracker.get_eth_price()

    return {
        "blockchain": "ethereum",
        "gas_prices_gwei": gas,
        "eth_price_usd": eth_price.get('usd', 0),
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/v2/ethereum/token/{contract}")
async def get_token_info(contract: str):
    """Get ERC-20 token information"""
    token = await ethereum_tracker.get_token_info(contract)

    if not token:
        raise HTTPException(status_code=404, detail="Token not found")

    return {
        "contract_address": token.contract_address,
        "name": token.name,
        "symbol": token.symbol,
        "decimals": token.decimals,
        "total_supply": token.total_supply,
        "holders_count": token.holders_count
    }


@app.get("/api/v2/ethereum/address/{address}/analysis")
async def analyze_ethereum_address(address: str):
    """Comprehensive Ethereum address analysis"""
    analysis = await ethereum_tracker.analyze_address(address)
    return analysis


# =====================================================
# Clustering Endpoints
# =====================================================

@app.post("/api/v2/clustering/analyze", response_model=List[ClusterResponse])
async def cluster_addresses(request: ClusteringRequest):
    """
    Cluster addresses starting from a seed address

    Uses Common Input Ownership Heuristic and other techniques
    to identify addresses likely controlled by same entity.
    """
    # Get transactions for seed address
    if request.blockchain == BlockchainType.BITCOIN:
        transactions = await bitcoin_tracker.get_address_transactions(
            request.seed_address, limit=100
        )
        # Convert to dict format for clustering engine
        tx_dicts = [
            {
                'txid': tx.txid,
                'inputs': tx.inputs,
                'outputs': tx.outputs,
                'timestamp': tx.block_time
            }
            for tx in transactions
        ]
    else:
        # Ethereum clustering (simpler - no UTXO model)
        raise HTTPException(
            status_code=400,
            detail="Clustering currently only supported for Bitcoin"
        )

    # Perform clustering
    result = await clustering_engine.cluster_from_seed(
        request.seed_address,
        tx_dicts,
        max_depth=request.max_depth
    )

    return [
        ClusterResponse(
            cluster_id=cluster.cluster_id,
            address_count=len(cluster.addresses),
            addresses=list(cluster.addresses)[:100],  # Limit to 100
            confidence=cluster.confidence,
            evidence_count=len(cluster.evidence),
            evidence_types=list(set(e.heuristic for e in cluster.evidence))
        )
        for cluster in result.clusters
    ]


@app.get("/api/v2/clustering/related/{address}")
async def find_related_addresses(
    address: str,
    blockchain: BlockchainType = BlockchainType.BITCOIN
):
    """Find addresses related to a given address via common inputs"""
    from .clustering.real_clustering_engine import QuickClusterer

    if blockchain != BlockchainType.BITCOIN:
        raise HTTPException(status_code=400, detail="Only Bitcoin supported")

    transactions = await bitcoin_tracker.get_address_transactions(address, limit=100)

    tx_dicts = [
        {
            'txid': tx.txid,
            'inputs': tx.inputs,
            'outputs': tx.outputs
        }
        for tx in transactions
    ]

    related = QuickClusterer.find_related_addresses(address, tx_dicts)

    return {
        "seed_address": address,
        "related_count": len(related),
        "related_addresses": list(related)
    }


# =====================================================
# AML Scoring Endpoints
# =====================================================

@app.post("/api/v2/aml/screen", response_model=AMLScoreResponse)
async def aml_screen_address(request: AMLScreeningRequest):
    """
    AML risk screening for an address

    Checks against:
    - OFAC sanctioned addresses
    - Known mixer/tumbler services
    - Darknet markets
    - Ransomware payment addresses
    - Suspicious patterns
    """
    transactions = []

    if request.include_transactions:
        if request.blockchain == BlockchainType.BITCOIN:
            txs = await bitcoin_tracker.get_address_transactions(
                request.address, limit=100
            )
            transactions = [
                {
                    'txid': tx.txid,
                    'from_address': tx.input_addresses[0] if tx.input_addresses else '',
                    'to_address': tx.output_addresses[0] if tx.output_addresses else '',
                    'amount': tx.output_value / 1e8,
                    'amount_usd': 0,  # Would need price data
                    'timestamp': tx.block_time,
                    'inputs': tx.inputs,
                    'outputs': tx.outputs
                }
                for tx in txs
            ]
        elif request.blockchain == BlockchainType.ETHEREUM:
            txs = await ethereum_tracker.get_address_transactions(
                request.address, offset=100
            )
            transactions = [
                {
                    'txid': tx.tx_hash,
                    'from_address': tx.from_address,
                    'to_address': tx.to_address,
                    'amount': tx.value_eth,
                    'amount_usd': 0,
                    'timestamp': tx.timestamp,
                    'inputs': [],
                    'outputs': []
                }
                for tx in txs
            ]

    # Calculate AML score
    score = await aml_engine.calculate_risk_score(
        request.address,
        transactions,
        request.blockchain.value
    )

    return AMLScoreResponse(
        address=score.address,
        blockchain=score.blockchain,
        total_score=score.total_score,
        risk_level=score.risk_level.value,
        red_flags=score.red_flags,
        recommendations=score.recommendations,
        risk_factors=[
            {
                "category": f.category.value,
                "score": f.score,
                "weight": f.weight,
                "description": f.description,
                "evidence": f.evidence
            }
            for f in score.risk_factors
        ],
        analysis_timestamp=score.analysis_timestamp.isoformat()
    )


@app.get("/api/v2/aml/quick-check/{address}")
async def quick_aml_check(address: str):
    """
    Quick AML check against known lists

    Fast check without transaction analysis.
    """
    from .aml.real_aml_scoring import quick_aml_screen

    result = await quick_aml_screen(address)
    return result


@app.get("/api/v2/aml/sanctioned-list")
async def get_sanctioned_list_info():
    """Get information about sanctioned address lists"""
    return {
        "sources": [
            "OFAC SDN List (US Treasury)",
            "Tornado Cash sanctioned addresses",
            "Known ransomware addresses",
            "Known darknet market addresses"
        ],
        "total_addresses": len(aml_engine.sanctioned_addresses) +
                          len(aml_engine.mixer_addresses) +
                          len(aml_engine.darknet_addresses) +
                          len(aml_engine.ransomware_addresses),
        "last_updated": "2024-01-01",  # Would be dynamic in production
        "categories": {
            "ofac_sanctioned": len(aml_engine.sanctioned_addresses),
            "mixers": len(aml_engine.mixer_addresses),
            "darknet": len(aml_engine.darknet_addresses),
            "ransomware": len(aml_engine.ransomware_addresses)
        }
    }


# =====================================================
# Utility Endpoints
# =====================================================

@app.get("/api/v2/lookup/{identifier}")
async def universal_lookup(identifier: str):
    """
    Universal lookup for address or transaction

    Automatically detects Bitcoin/Ethereum based on format.
    """
    # Detect type
    if len(identifier) == 64 and all(c in '0123456789abcdefABCDEF' for c in identifier):
        # Likely Bitcoin txid
        tx = await bitcoin_tracker.get_transaction(identifier)
        if tx:
            return {
                "type": "bitcoin_transaction",
                "data": {
                    "txid": tx.txid,
                    "confirmed": tx.confirmed,
                    "block_height": tx.block_height,
                    "fee": tx.fee
                }
            }

    elif identifier.startswith('0x') and len(identifier) == 66:
        # Ethereum transaction
        tx = await ethereum_tracker.get_transaction(identifier)
        if tx:
            return {
                "type": "ethereum_transaction",
                "data": {
                    "tx_hash": tx.tx_hash,
                    "from": tx.from_address,
                    "to": tx.to_address,
                    "value_eth": tx.value_eth
                }
            }

    elif identifier.startswith('0x') and len(identifier) == 42:
        # Ethereum address
        info = await ethereum_tracker.get_address_info(identifier)
        if info:
            return {
                "type": "ethereum_address",
                "data": {
                    "address": info.address,
                    "balance_eth": info.balance_eth,
                    "is_contract": info.is_contract
                }
            }

    elif identifier.startswith(('1', '3', 'bc1')):
        # Bitcoin address
        info = await bitcoin_tracker.get_address_info(identifier)
        if info:
            return {
                "type": "bitcoin_address",
                "data": {
                    "address": info.address,
                    "balance_btc": info.balance_btc,
                    "tx_count": info.tx_count
                }
            }

    raise HTTPException(status_code=404, detail="Could not identify or find the provided identifier")


# Main entry point for running standalone
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
