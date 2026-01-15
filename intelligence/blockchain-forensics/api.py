"""
FastAPI Application for Blockchain Forensics

REST API endpoints for:
- OneCoin tracking
- Wallet clustering
- Transaction tracing
- Exchange surveillance
- Address intelligence
- Real-time monitoring
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging

# Import forensics modules
from .onecoin.tracker import OneCoinTracker
from .onecoin.wallet_identifier import RujaWalletIdentifier
from .onecoin.fund_flow import FundFlowAnalyzer
from .clustering.clustering_engine import WalletClusteringEngine
from .api_clients.api_manager import BlockchainAPIManager
from .config import config

logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Apollo Blockchain Forensics API",
    description="Advanced blockchain analysis and cryptocurrency tracking",
    version="1.0.0",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Pydantic models for request/response
class AddressRequest(BaseModel):
    address: str = Field(..., description="Blockchain address")
    blockchain: str = Field(default="btc", description="Blockchain type")
    depth: int = Field(default=3, ge=1, le=10, description="Trace depth")


class TrackingResult(BaseModel):
    address: str
    blockchain: str
    onecoin_confidence: float
    total_value: float
    suspicious_patterns: List[str]
    connected_addresses: List[str]


class ClusterRequest(BaseModel):
    addresses: List[str] = Field(..., description="Addresses to cluster")
    blockchain: str = Field(default="btc")
    min_confidence: float = Field(default=0.7, ge=0.0, le=1.0)


class WalletAnalysisRequest(BaseModel):
    address: str
    blockchain: str = Field(default="btc")


# Global instances (will be initialized on startup)
api_manager: Optional[BlockchainAPIManager] = None
onecoin_tracker: Optional[OneCoinTracker] = None
wallet_identifier: Optional[RujaWalletIdentifier] = None
fund_flow_analyzer: Optional[FundFlowAnalyzer] = None
clustering_engine: Optional[WalletClusteringEngine] = None


@app.on_event("startup")
async def startup():
    """Initialize services on startup"""
    global api_manager, onecoin_tracker, wallet_identifier, fund_flow_analyzer, clustering_engine

    logger.info("Starting Blockchain Forensics API...")

    # Initialize API manager
    api_manager = BlockchainAPIManager(config)
    await api_manager.initialize()

    # Initialize database and graph clients (placeholder - implement based on your DB setup)
    db_manager = None  # Initialize your database manager
    graph_client = None  # Initialize your Neo4j client

    # Initialize forensics modules
    onecoin_tracker = OneCoinTracker(db_manager, api_manager, graph_client)
    wallet_identifier = RujaWalletIdentifier(db_manager, api_manager, graph_client)
    fund_flow_analyzer = FundFlowAnalyzer(db_manager, api_manager, graph_client)
    clustering_engine = WalletClusteringEngine(db_manager, api_manager, graph_client)

    logger.info("Blockchain Forensics API started successfully")


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown"""
    global api_manager

    if api_manager:
        await api_manager.close()

    logger.info("Blockchain Forensics API shut down")


# ===== OneCoin Tracking Endpoints =====

@app.post("/api/v1/onecoin/track", response_model=TrackingResult)
async def track_onecoin_address(request: AddressRequest):
    """
    Track a cryptocurrency address for OneCoin connections

    Analyzes:
    - Connection to known OneCoin addresses
    - Suspicious transaction patterns
    - Fund flow to exchanges
    - Money laundering indicators
    """
    try:
        result = await onecoin_tracker.track_address(
            request.address,
            request.blockchain,
            request.depth
        )

        return TrackingResult(
            address=result["address"],
            blockchain=result["blockchain"],
            onecoin_confidence=result["onecoin_confidence"],
            total_value=sum(tx.get("amount_usd", 0) for tx in result["transactions"]),
            suspicious_patterns=result["suspicious_patterns"],
            connected_addresses=list(result["connected_addresses"])[:100],  # Limit to 100
        )

    except Exception as e:
        logger.error(f"Error tracking address: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/onecoin/ruja-wallets")
async def identify_ruja_wallets(
    min_confidence: float = Query(0.7, ge=0.0, le=1.0),
    limit: int = Query(50, ge=1, le=100)
):
    """
    Identify wallets likely controlled by Ruja Ignatova

    Uses multiple heuristics:
    - Transaction timing (2014-2017)
    - Value patterns
    - Network connections
    - Behavioral fingerprinting
    """
    try:
        wallets = await wallet_identifier.identify_ruja_wallets(
            min_confidence=min_confidence
        )

        return {
            "count": len(wallets),
            "wallets": wallets[:limit]
        }

    except Exception as e:
        logger.error(f"Error identifying Ruja wallets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/onecoin/fund-flow")
async def trace_fund_flow(request: AddressRequest):
    """
    Trace fund flow from a source address

    Tracks:
    - Multi-hop transaction paths
    - Exchange deposits
    - Mixer usage
    - Final destinations
    """
    try:
        flows = await fund_flow_analyzer.trace_fund_flow(
            request.address,
            request.blockchain,
            max_hops=request.depth
        )

        analysis = await fund_flow_analyzer.analyze_flow_patterns(flows)

        return {
            "source_address": request.address,
            "total_flows": len(flows),
            "analysis": analysis,
            "flows": [
                {
                    "destination": flow.destination_address,
                    "amount_usd": flow.amount_usd,
                    "hops": flow.hops,
                    "tags": flow.tags,
                }
                for flow in flows
            ]
        }

    except Exception as e:
        logger.error(f"Error tracing fund flow: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ===== Wallet Clustering Endpoints =====

@app.post("/api/v1/clustering/cluster")
async def cluster_wallets(request: ClusterRequest):
    """
    Cluster cryptocurrency addresses

    Uses multiple heuristics:
    - Common input ownership
    - Change address detection
    - Co-spending analysis
    - Peel chain detection
    """
    try:
        clusters = await clustering_engine.cluster_addresses(
            request.addresses,
            request.blockchain,
            request.min_confidence
        )

        return {
            "total_clusters": len(clusters),
            "clusters": [
                {
                    "cluster_id": cluster.cluster_id,
                    "address_count": len(cluster.addresses),
                    "addresses": list(cluster.addresses),
                    "confidence": cluster.confidence,
                    "evidence": cluster.evidence,
                    "label": cluster.label,
                }
                for cluster in clusters
            ]
        }

    except Exception as e:
        logger.error(f"Error clustering wallets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/clustering/cluster/{cluster_id}")
async def get_cluster(cluster_id: str):
    """Get details for a specific cluster"""
    try:
        if cluster_id not in clustering_engine.clusters:
            raise HTTPException(status_code=404, detail="Cluster not found")

        stats = await clustering_engine.get_cluster_statistics(cluster_id)

        return stats

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting cluster: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ===== Wallet Analysis Endpoints =====

@app.post("/api/v1/analysis/wallet")
async def analyze_wallet(request: WalletAnalysisRequest):
    """
    Comprehensive wallet analysis

    Provides:
    - Transaction history
    - Balance and value
    - Risk assessment
    - OneCoin connection score
    - Behavioral fingerprint
    """
    try:
        analysis = await wallet_identifier.analyze_wallet(
            request.address,
            request.blockchain
        )

        return analysis

    except Exception as e:
        logger.error(f"Error analyzing wallet: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/analysis/compare")
async def compare_wallets(
    address1: str = Query(..., description="First address"),
    address2: str = Query(..., description="Second address"),
    blockchain: str = Query("btc", description="Blockchain type")
):
    """
    Compare two wallets for common ownership

    Analyzes:
    - Behavioral similarity
    - Shared counterparties
    - Timing patterns
    - Amount patterns
    """
    try:
        comparison = await wallet_identifier.compare_wallets(address1, address2)

        return comparison

    except Exception as e:
        logger.error(f"Error comparing wallets: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ===== Transaction Endpoints =====

@app.get("/api/v1/transactions/address/{address}")
async def get_address_transactions(
    address: str,
    blockchain: str = Query("btc"),
    limit: int = Query(100, ge=1, le=1000)
):
    """Get transactions for an address"""
    try:
        transactions = await api_manager.get_address_transactions(
            address,
            blockchain,
            limit
        )

        return {
            "address": address,
            "blockchain": blockchain,
            "transaction_count": len(transactions),
            "transactions": transactions
        }

    except Exception as e:
        logger.error(f"Error getting transactions: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/transactions/{txid}")
async def get_transaction(
    txid: str,
    blockchain: str = Query("btc")
):
    """Get details for a specific transaction"""
    try:
        transaction = await api_manager.get_transaction(txid, blockchain)

        if not transaction:
            raise HTTPException(status_code=404, detail="Transaction not found")

        return transaction

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting transaction: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ===== Status and Health Endpoints =====

@app.get("/api/v1/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }


@app.get("/api/v1/stats")
async def get_statistics():
    """Get API statistics"""
    try:
        api_stats = api_manager.get_api_stats()

        return {
            "api_stats": api_stats,
            "timestamp": datetime.utcnow().isoformat(),
        }

    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
