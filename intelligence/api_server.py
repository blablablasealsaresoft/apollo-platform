"""
Apollo Intelligence API Server
FastAPI endpoints for all intelligence services
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
import logging

# Import intelligence modules
from osint-tools.sherlock import SherlockEngine, BatchUsernameProcessor
from osint-tools.bbot import BBOTEngine
from blockchain-intelligence import BlockchainIntelligenceEngine
from fusion-engine import IntelligenceFusionEngine
from api-orchestrator import APIOrchestrator

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="Apollo Intelligence API",
    description="Comprehensive intelligence and OSINT integration platform",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request/Response Models
class UsernameSearchRequest(BaseModel):
    username: str = Field(..., description="Username to search")
    platforms: Optional[List[str]] = Field(None, description="Platforms to search")


class BatchUsernameSearchRequest(BaseModel):
    usernames: List[str] = Field(..., description="List of usernames to search")
    platforms: Optional[List[str]] = Field(None, description="Platforms to search")


class DomainScanRequest(BaseModel):
    domain: str = Field(..., description="Domain to scan")
    scan_types: Optional[List[str]] = Field(
        None,
        description="Scan types: subdomain, port, tech, vuln"
    )


class WalletSearchRequest(BaseModel):
    address: str = Field(..., description="Wallet address")
    blockchain: str = Field(default='bitcoin', description="Blockchain name")


class TransactionTraceRequest(BaseModel):
    address: str = Field(..., description="Starting wallet address")
    blockchain: str = Field(default='bitcoin', description="Blockchain name")
    max_hops: int = Field(default=5, description="Maximum transaction hops")
    min_amount: Optional[float] = Field(None, description="Minimum transaction amount")


class IntelligenceFusionRequest(BaseModel):
    target: str = Field(..., description="Target identifier")
    target_type: str = Field(default='person', description="Target type")
    sources: Optional[List[str]] = Field(None, description="Intelligence sources")


class APICallRequest(BaseModel):
    api_name: str = Field(..., description="API name")
    endpoint: str = Field(..., description="API endpoint")
    method: str = Field(default='GET', description="HTTP method")
    params: Optional[Dict[str, Any]] = Field(None, description="Query parameters")
    data: Optional[Dict[str, Any]] = Field(None, description="Request body")
    api_key: Optional[str] = Field(None, description="API key")


# Initialize engines
sherlock_engine = SherlockEngine()
batch_processor = BatchUsernameProcessor(sherlock_engine)
bbot_engine = BBOTEngine()
blockchain_engine = BlockchainIntelligenceEngine()
fusion_engine = IntelligenceFusionEngine()
api_orchestrator = APIOrchestrator()


# Health check
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "services": {
            "sherlock": "operational",
            "bbot": "operational",
            "blockchain": "operational",
            "fusion": "operational",
            "api_orchestrator": "operational"
        }
    }


# Sherlock OSINT Endpoints
@app.post("/api/v1/osint/username/search")
async def search_username(request: UsernameSearchRequest):
    """Search for username across social media platforms"""
    try:
        results = await sherlock_engine.search_username(
            request.username,
            request.platforms
        )

        found = [r for r in results if r.status == 'found']

        return {
            "success": True,
            "username": request.username,
            "total_platforms_checked": len(results),
            "platforms_found": len(found),
            "results": [
                {
                    "platform": r.platform,
                    "url": r.url,
                    "status": r.status,
                    "confidence_score": r.confidence_score,
                    "response_time_ms": r.response_time_ms
                }
                for r in results
            ]
        }
    except Exception as e:
        logger.error(f"Username search error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/osint/username/batch-search")
async def batch_search_usernames(request: BatchUsernameSearchRequest):
    """Batch search for multiple usernames"""
    try:
        batch_result = await batch_processor.search_batch(
            request.usernames,
            request.platforms
        )

        return {
            "success": True,
            "total_usernames": batch_result.total_usernames,
            "total_platforms": batch_result.total_platforms,
            "found_results": batch_result.found_results,
            "duration_seconds": batch_result.duration_seconds,
            "results_by_username": {
                username: [
                    {
                        "platform": r.platform,
                        "url": r.url,
                        "status": r.status,
                        "confidence_score": r.confidence_score
                    }
                    for r in results if r.status == 'found'
                ]
                for username, results in batch_result.results_by_username.items()
            }
        }
    except Exception as e:
        logger.error(f"Batch search error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# BBOT OSINT Endpoints
@app.post("/api/v1/osint/domain/scan")
async def scan_domain(request: DomainScanRequest):
    """Perform comprehensive domain reconnaissance"""
    try:
        result = await bbot_engine.full_scan(
            request.domain,
            request.scan_types
        )

        return {
            "success": True,
            "target": result.target,
            "scan_type": result.scan_type,
            "duration_seconds": result.duration_seconds,
            "summary": {
                "subdomains_found": result.subdomains_found,
                "ips_found": result.ips_found,
                "ports_found": result.ports_found,
                "technologies_found": result.technologies_found,
                "vulnerabilities_found": result.vulnerabilities_found
            },
            "results": {
                "subdomains": list(result.results.subdomains)[:100],  # Limit response size
                "ips": result.results.ips,
                "technologies": result.results.technologies,
                "vulnerabilities": result.results.vulnerabilities
            }
        }
    except Exception as e:
        logger.error(f"Domain scan error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Blockchain Intelligence Endpoints
@app.post("/api/v1/blockchain/wallet/info")
async def get_wallet_info(request: WalletSearchRequest):
    """Get comprehensive wallet information"""
    try:
        wallet_info = await blockchain_engine.get_wallet_info(
            request.address,
            request.blockchain
        )

        return {
            "success": True,
            "address": wallet_info.address,
            "blockchain": wallet_info.blockchain,
            "balance": str(wallet_info.balance),
            "total_received": str(wallet_info.total_received),
            "total_sent": str(wallet_info.total_sent),
            "transaction_count": wallet_info.transaction_count,
            "risk_score": wallet_info.risk_score,
            "labels": wallet_info.labels
        }
    except Exception as e:
        logger.error(f"Wallet info error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/blockchain/trace/funds")
async def trace_funds(request: TransactionTraceRequest):
    """Trace cryptocurrency funds through transaction graph"""
    try:
        from decimal import Decimal

        min_amount = Decimal(str(request.min_amount)) if request.min_amount else None

        trace_result = await blockchain_engine.trace_funds(
            request.address,
            request.blockchain,
            request.max_hops,
            min_amount
        )

        return {
            "success": True,
            "start_address": trace_result['start'],
            "blockchain": trace_result['blockchain'],
            "total_nodes": len(trace_result['nodes']),
            "total_edges": len(trace_result['edges']),
            "graph": trace_result
        }
    except Exception as e:
        logger.error(f"Fund tracing error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Intelligence Fusion Endpoints
@app.post("/api/v1/fusion/intelligence")
async def fuse_intelligence(request: IntelligenceFusionRequest):
    """Fuse intelligence from all sources"""
    try:
        fused_report = await fusion_engine.fuse_intelligence(
            request.target,
            request.target_type,
            request.sources
        )

        return {
            "success": True,
            "report_id": fused_report.report_id,
            "target": fused_report.target,
            "entity_count": len(fused_report.entities),
            "link_count": len(fused_report.links),
            "confidence_score": fused_report.confidence_score,
            "risk_assessment": fused_report.risk_assessment,
            "recommendations": fused_report.recommendations,
            "sources_used": fused_report.sources_used,
            "generated_at": fused_report.generated_at.isoformat()
        }
    except Exception as e:
        logger.error(f"Intelligence fusion error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/fusion/report/{report_id}")
async def get_fusion_report(report_id: str):
    """Retrieve a fused intelligence report"""
    try:
        report = await fusion_engine.get_fused_report(report_id)

        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        return {
            "success": True,
            "report": report
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Report retrieval error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# API Orchestrator Endpoints
@app.post("/api/v1/orchestrator/call")
async def orchestrated_api_call(request: APICallRequest):
    """Make an orchestrated API call with rate limiting and caching"""
    try:
        response = await api_orchestrator.call_api(
            request.api_name,
            request.endpoint,
            request.method,
            request.params,
            request.data,
            api_key=request.api_key
        )

        return {
            "success": response.success,
            "status_code": response.status_code,
            "data": response.data,
            "error": response.error,
            "cached": response.cached,
            "response_time_ms": response.response_time_ms,
            "api_name": response.api_name
        }
    except Exception as e:
        logger.error(f"Orchestrated API call error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/orchestrator/apis")
async def list_apis():
    """List all registered APIs"""
    return {
        "success": True,
        "total_apis": api_orchestrator.get_api_count(),
        "apis": api_orchestrator.list_apis()
    }


@app.get("/api/v1/orchestrator/stats/{api_name}")
async def get_api_stats(api_name: str):
    """Get statistics for an API"""
    stats = api_orchestrator.get_api_stats(api_name)
    return {
        "success": True,
        "stats": stats
    }


# System Information
@app.get("/api/v1/system/info")
async def system_info():
    """Get system information"""
    return {
        "platform": "Apollo Intelligence",
        "version": "1.0.0",
        "modules": {
            "sherlock": {
                "platforms": sherlock_engine.get_platform_count(),
                "description": "Username search across 400+ platforms"
            },
            "bbot": {
                "description": "Domain reconnaissance and vulnerability scanning"
            },
            "blockchain": {
                "blockchains": len(blockchain_engine.get_supported_blockchains()),
                "supported": blockchain_engine.get_supported_blockchains()
            },
            "fusion": {
                "description": "Intelligence aggregation and correlation"
            },
            "orchestrator": {
                "apis": api_orchestrator.get_api_count(),
                "description": "1000+ API orchestration with rate limiting"
            }
        }
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
