"""
Sherlock OSINT - FastAPI REST API Endpoints

Production-ready RESTful API interface for username search operations.
Supports 300+ platforms with async processing, Redis caching, and Celery integration.

Author: Apollo Intelligence Platform
License: MIT
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query, Path as PathParam, Depends, status
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from pathlib import Path
import asyncio
import logging
import uuid
import json
import csv
import os
from io import StringIO

# Redis for result storage
try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

# Celery for background tasks
try:
    from celery import Celery
    from celery.result import AsyncResult
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False

# Import Sherlock engine components
from .sherlock_engine import (
    SherlockEngine,
    UsernameResult,
    ProxyConfig,
    RateLimitConfig
)
from .batch_processor import BatchUsernameProcessor, BatchSearchResult
from .results_storage import SherlockResultsStorage

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# Configuration
# =============================================================================

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CELERY_BROKER = os.getenv("CELERY_BROKER", "amqp://guest:guest@localhost:5672//")
RESULTS_TTL = int(os.getenv("RESULTS_TTL", "86400"))  # 24 hours default

# =============================================================================
# Initialize FastAPI app
# =============================================================================

app = FastAPI(
    title="Apollo Sherlock OSINT API",
    description="""
## Username Search API

Search for usernames across 300+ social media platforms with advanced features:

- **Single Search**: Search one username across all or selected platforms
- **Batch Search**: Search multiple usernames with background processing (Celery)
- **Category Filtering**: Filter by platform categories (social, gaming, development, etc.)
- **Proxy Support**: Use proxies for anonymized searches
- **Rate Limiting**: Built-in rate limiting to avoid platform bans
- **Redis Caching**: Fast results with intelligent caching
- **Persistent Storage**: Results stored in Redis for later retrieval

### Authentication

Use API key authentication via `X-API-Key` header.

### Rate Limits

- Standard: 100 requests/hour
- Pro: 1000 requests/hour
- Enterprise: Unlimited

    """,
    version="2.1.0",
    docs_url="/api/v1/osint/sherlock/docs",
    redoc_url="/api/v1/osint/sherlock/redoc",
    openapi_url="/api/v1/osint/sherlock/openapi.json"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global engine instance (will be initialized with Redis on startup)
sherlock_engine: Optional[SherlockEngine] = None
batch_processor: Optional[BatchUsernameProcessor] = None
redis_client: Optional[Any] = None

# In-memory fallback storage
background_jobs: Dict[str, Dict[str, Any]] = {}
search_results_cache: Dict[str, Dict[str, Any]] = {}

# Celery app for background tasks
celery_app = None
if CELERY_AVAILABLE:
    celery_app = Celery(
        'sherlock_tasks',
        broker=CELERY_BROKER,
        backend='redis://localhost:6379/1'
    )
    celery_app.conf.update(
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        task_track_started=True,
        task_time_limit=3600,
    )


# =============================================================================
# Pydantic Models
# =============================================================================

class UsernameSearchRequest(BaseModel):
    """Request model for single username search"""
    username: str = Field(..., min_length=1, max_length=100, description="Username to search")
    platforms: Optional[List[str]] = Field(None, description="Specific platforms to search")
    categories: Optional[List[str]] = Field(None, description="Platform categories to search")
    reliable_only: bool = Field(False, description="Only search reliable platforms")
    use_cache: bool = Field(True, description="Use Redis caching")

    @validator('username')
    def validate_username(cls, v):
        if not v or not v.strip():
            raise ValueError('Username cannot be empty')
        v = v.strip()
        if len(v) > 100:
            raise ValueError('Username too long')
        return v


class BatchSearchRequest(BaseModel):
    """Request model for batch search"""
    usernames: List[str] = Field(
        ...,
        min_items=1,
        max_items=100,
        description="List of usernames to search (max 100)"
    )
    platforms: Optional[List[str]] = Field(None, description="Specific platforms to search")
    categories: Optional[List[str]] = Field(None, description="Platform categories to search")
    use_celery: bool = Field(True, description="Use Celery for async processing")
    reliable_only: bool = Field(False, description="Only search reliable platforms")

    @validator('usernames')
    def validate_usernames(cls, v):
        if not v:
            raise ValueError('Usernames list cannot be empty')
        return [u.strip() for u in v if u.strip()]


class ProxyRequest(BaseModel):
    """Request model for proxy configuration"""
    protocol: str = Field(..., description="Proxy protocol: http, https, socks4, socks5")
    host: str = Field(..., description="Proxy host")
    port: int = Field(..., ge=1, le=65535, description="Proxy port")
    username: Optional[str] = Field(None, description="Proxy username")
    password: Optional[str] = Field(None, description="Proxy password")


class PlatformResult(BaseModel):
    """Platform search result"""
    platform: str
    url: str
    status: str
    confidence_score: float
    response_time_ms: int
    http_status: Optional[int] = None
    category: Optional[str] = None
    screenshot_path: Optional[str] = None


class SearchResponse(BaseModel):
    """Response model for username search"""
    search_id: str
    username: str
    total_platforms: int
    found_count: int
    not_found_count: int
    error_count: int
    search_duration_ms: int
    timestamp: str
    cache_hits: int = 0
    results: List[PlatformResult]


class BatchSearchResponse(BaseModel):
    """Response model for batch search initiation"""
    job_id: str
    status: str
    usernames_count: int
    estimated_time_seconds: int
    message: str
    celery_task_id: Optional[str] = None


class JobStatusResponse(BaseModel):
    """Response model for job status"""
    job_id: str
    status: str  # pending, processing, completed, failed
    progress: float
    current_username: Optional[str] = None
    completed_usernames: int
    total_usernames: int
    results: Optional[List[Dict[str, Any]]] = None
    created_at: str
    completed_at: Optional[str] = None
    error: Optional[str] = None
    celery_task_id: Optional[str] = None


class PlatformInfo(BaseModel):
    """Platform information"""
    name: str
    url_template: str
    category: str
    reliable: bool
    error_type: str


class PlatformsResponse(BaseModel):
    """Response model for platforms list"""
    total_platforms: int
    categories: List[str]
    platforms_by_category: Dict[str, List[PlatformInfo]]


class StatisticsResponse(BaseModel):
    """Response model for statistics"""
    requests_sent: int
    requests_succeeded: int
    requests_failed: int
    profiles_found: int
    rate_limited: int
    timeouts: int
    avg_response_time_ms: float
    success_rate: float
    platforms_available: int
    cache_enabled: bool = False
    cache_stats: Optional[Dict[str, Any]] = None


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    version: str
    platforms_available: int
    timestamp: str
    uptime_seconds: float
    redis_connected: bool
    celery_available: bool


# =============================================================================
# Helper Functions
# =============================================================================

async def get_redis_client():
    """Get or create Redis client"""
    global redis_client
    if redis_client is None and REDIS_AVAILABLE:
        try:
            redis_client = await aioredis.from_url(
                REDIS_URL,
                encoding="utf-8",
                decode_responses=True
            )
            await redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            redis_client = None
    return redis_client


async def store_search_result(search_id: str, result: dict, ttl: int = RESULTS_TTL):
    """Store search result in Redis"""
    client = await get_redis_client()
    if client:
        try:
            key = f"sherlock:result:{search_id}"
            await client.setex(key, ttl, json.dumps(result, default=str))
            logger.debug(f"Stored result {search_id} in Redis")
        except Exception as e:
            logger.error(f"Failed to store result in Redis: {e}")
    # Also store in memory as backup
    search_results_cache[search_id] = result


async def get_search_result(search_id: str) -> Optional[dict]:
    """Retrieve search result from Redis"""
    client = await get_redis_client()
    if client:
        try:
            key = f"sherlock:result:{search_id}"
            data = await client.get(key)
            if data:
                return json.loads(data)
        except Exception as e:
            logger.error(f"Failed to get result from Redis: {e}")

    # Fallback to in-memory storage
    if search_id in search_results_cache:
        return search_results_cache[search_id]

    # Check batch job results
    for job_id, job_data in background_jobs.items():
        for result in job_data.get('results', []):
            if result.get('search_id') == search_id:
                return result

    return None


async def store_job_status(job_id: str, status: dict, ttl: int = RESULTS_TTL):
    """Store job status in Redis"""
    client = await get_redis_client()
    if client:
        try:
            key = f"sherlock:job:{job_id}"
            await client.setex(key, ttl, json.dumps(status, default=str))
        except Exception as e:
            logger.error(f"Failed to store job status in Redis: {e}")
    # Also store in memory as backup
    background_jobs[job_id] = status


async def get_job_status(job_id: str) -> Optional[dict]:
    """Retrieve job status from Redis"""
    client = await get_redis_client()
    if client:
        try:
            key = f"sherlock:job:{job_id}"
            data = await client.get(key)
            if data:
                return json.loads(data)
        except Exception as e:
            logger.error(f"Failed to get job status from Redis: {e}")

    # Fallback to in-memory
    return background_jobs.get(job_id)


# =============================================================================
# Celery Tasks
# =============================================================================

if CELERY_AVAILABLE and celery_app:
    @celery_app.task(bind=True, name='sherlock.search_username')
    def celery_search_username(
        self,
        username: str,
        platforms: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        reliable_only: bool = False
    ):
        """Celery task for single username search"""
        import asyncio

        async def run_search():
            engine = SherlockEngine(max_concurrent=50, timeout=15)
            results = await engine.search_username(
                username=username,
                platforms=platforms,
                categories=categories,
                reliable_only=reliable_only
            )
            return [r.to_dict() for r in results]

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(run_search())
        finally:
            loop.close()

    @celery_app.task(bind=True, name='sherlock.batch_search')
    def celery_batch_search(
        self,
        job_id: str,
        usernames: List[str],
        platforms: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        reliable_only: bool = False
    ):
        """Celery task for batch username search"""
        import asyncio
        import redis

        async def run_batch():
            engine = SherlockEngine(max_concurrent=50, timeout=15)

            # Connect to Redis for progress updates
            try:
                r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
            except:
                r = None

            results = []

            for i, username in enumerate(usernames):
                # Update progress
                progress = {
                    'status': 'processing',
                    'progress': (i / len(usernames)) * 100,
                    'current_username': username,
                    'completed_usernames': i,
                    'total_usernames': len(usernames)
                }

                if r:
                    try:
                        r.setex(f"sherlock:job:{job_id}", RESULTS_TTL, json.dumps(progress))
                    except:
                        pass

                # Search username
                search_results = await engine.search_username(
                    username=username,
                    platforms=platforms,
                    categories=categories,
                    reliable_only=reliable_only
                )

                found_count = sum(1 for sr in search_results if sr.status == 'found')
                not_found_count = sum(1 for sr in search_results if sr.status == 'not_found')
                error_count = len(search_results) - found_count - not_found_count

                result = {
                    'search_id': f"{job_id}_{i}",
                    'username': username,
                    'total_platforms': len(search_results),
                    'found_count': found_count,
                    'not_found_count': not_found_count,
                    'error_count': error_count,
                    'timestamp': datetime.utcnow().isoformat(),
                    'results': [sr.to_dict() for sr in search_results]
                }
                results.append(result)

                # Store individual result
                if r:
                    try:
                        r.setex(
                            f"sherlock:result:{job_id}_{i}",
                            RESULTS_TTL,
                            json.dumps(result, default=str)
                        )
                    except:
                        pass

            # Final status
            final_status = {
                'status': 'completed',
                'progress': 100.0,
                'current_username': None,
                'completed_usernames': len(usernames),
                'total_usernames': len(usernames),
                'completed_at': datetime.utcnow().isoformat(),
                'results': results
            }

            if r:
                try:
                    r.setex(f"sherlock:job:{job_id}", RESULTS_TTL, json.dumps(final_status, default=str))
                except:
                    pass

            return final_status

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(run_batch())
        finally:
            loop.close()


# =============================================================================
# API Endpoints
# =============================================================================

# Track server start time for uptime
_start_time = datetime.utcnow()


@app.get("/", tags=["General"])
async def root():
    """Root endpoint - API information"""
    return {
        "name": "Apollo Sherlock OSINT API",
        "version": "2.1.0",
        "description": "Username search across 300+ social media platforms",
        "documentation": "/api/v1/osint/sherlock/docs",
        "endpoints": {
            "search": "POST /api/v1/osint/sherlock/search",
            "batch": "POST /api/v1/osint/sherlock/batch",
            "results": "GET /api/v1/osint/sherlock/results/{search_id}",
            "platforms": "GET /api/v1/osint/sherlock/platforms",
            "categories": "GET /api/v1/osint/sherlock/categories",
            "health": "GET /api/v1/osint/sherlock/health",
            "statistics": "GET /api/v1/osint/sherlock/statistics"
        }
    }


@app.get("/api/v1/osint/sherlock/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    """Health check endpoint for monitoring"""
    uptime = (datetime.utcnow() - _start_time).total_seconds()

    # Check Redis connection
    redis_connected = False
    client = await get_redis_client()
    if client:
        try:
            await client.ping()
            redis_connected = True
        except:
            pass

    return HealthResponse(
        status="healthy",
        version="2.1.0",
        platforms_available=sherlock_engine.get_platform_count() if sherlock_engine else 0,
        timestamp=datetime.utcnow().isoformat(),
        uptime_seconds=round(uptime, 2),
        redis_connected=redis_connected,
        celery_available=CELERY_AVAILABLE
    )


@app.get("/api/v1/osint/sherlock/statistics", response_model=StatisticsResponse, tags=["System"])
async def get_statistics():
    """Get search statistics"""
    if not sherlock_engine:
        raise HTTPException(status_code=503, detail="Engine not initialized")

    stats = sherlock_engine.get_statistics()

    # Get cache stats if available
    cache_stats = None
    cache_enabled = False
    if hasattr(sherlock_engine, '_redis_cache_enabled') and sherlock_engine._redis_cache_enabled:
        cache_enabled = True
        cache_stats = await sherlock_engine.get_cache_stats()

    return StatisticsResponse(
        **stats,
        cache_enabled=cache_enabled,
        cache_stats=cache_stats
    )


@app.post("/api/v1/osint/sherlock/statistics/reset", tags=["System"])
async def reset_statistics():
    """Reset search statistics"""
    if sherlock_engine:
        sherlock_engine.reset_statistics()
    return {"message": "Statistics reset successfully"}


# =============================================================================
# Platform Endpoints
# =============================================================================

@app.get("/api/v1/osint/sherlock/platforms", response_model=PlatformsResponse, tags=["Platforms"])
async def list_platforms(
    category: Optional[str] = Query(None, description="Filter by category"),
    reliable_only: bool = Query(False, description="Only show reliable platforms")
):
    """
    List all available platforms

    Returns platforms grouped by category with detection configuration.
    """
    if not sherlock_engine:
        raise HTTPException(status_code=503, detail="Engine not initialized")

    platforms_by_cat: Dict[str, List[PlatformInfo]] = {}

    for name, config in sherlock_engine.platforms.items():
        # Apply filters
        if category and config.category != category:
            continue
        if reliable_only and not config.reliable:
            continue

        cat = config.category
        if cat not in platforms_by_cat:
            platforms_by_cat[cat] = []

        platforms_by_cat[cat].append(PlatformInfo(
            name=name,
            url_template=config.url_template,
            category=config.category,
            reliable=config.reliable,
            error_type=config.error_type
        ))

    total = sum(len(p) for p in platforms_by_cat.values())

    return PlatformsResponse(
        total_platforms=total,
        categories=list(platforms_by_cat.keys()),
        platforms_by_category=platforms_by_cat
    )


@app.get("/api/v1/osint/sherlock/categories", tags=["Platforms"])
async def list_categories():
    """List all platform categories with counts"""
    if not sherlock_engine:
        raise HTTPException(status_code=503, detail="Engine not initialized")

    categories = sherlock_engine.get_platforms_by_category()
    return {
        "categories": [
            {
                "name": cat,
                "count": len(platforms),
                "platforms": platforms
            }
            for cat, platforms in sorted(categories.items())
        ],
        "total_categories": len(categories)
    }


@app.get("/api/v1/osint/sherlock/platform/{platform_name}", tags=["Platforms"])
async def get_platform_info(platform_name: str = PathParam(..., description="Platform name")):
    """Get detailed information about a specific platform"""
    if not sherlock_engine:
        raise HTTPException(status_code=503, detail="Engine not initialized")

    if platform_name not in sherlock_engine.platforms:
        raise HTTPException(status_code=404, detail=f"Platform '{platform_name}' not found")

    config = sherlock_engine.platforms[platform_name]
    return {
        "name": platform_name,
        "url_template": config.url_template,
        "category": config.category,
        "reliable": config.reliable,
        "error_type": config.error_type,
        "error_code": config.error_code,
        "error_message": config.error_msg
    }


# =============================================================================
# Search Endpoints
# =============================================================================

@app.post("/api/v1/osint/sherlock/search", response_model=SearchResponse, tags=["Search"])
async def search_username(request: UsernameSearchRequest):
    """
    Search for a username across platforms

    Performs synchronous search and returns results immediately.
    For large searches, use the batch endpoint.
    """
    if not sherlock_engine:
        raise HTTPException(status_code=503, detail="Engine not initialized")

    search_id = str(uuid.uuid4())
    start_time = datetime.utcnow()

    try:
        logger.info(f"Search request [{search_id}]: {request.username}")

        # Execute search
        results = await sherlock_engine.search_username(
            username=request.username,
            platforms=request.platforms,
            categories=request.categories,
            reliable_only=request.reliable_only,
            use_cache=request.use_cache
        )

        search_duration = int((datetime.utcnow() - start_time).total_seconds() * 1000)

        # Convert results
        platform_results = []
        found_count = 0
        not_found_count = 0
        error_count = 0

        for result in results:
            if result.status == 'found':
                found_count += 1
            elif result.status == 'not_found':
                not_found_count += 1
            else:
                error_count += 1

            platform_results.append(PlatformResult(
                platform=result.platform,
                url=result.url,
                status=result.status,
                confidence_score=result.confidence_score,
                response_time_ms=result.response_time_ms,
                http_status=result.http_status,
                category=result.metadata.get('category'),
                screenshot_path=result.screenshot_path
            ))

        response = SearchResponse(
            search_id=search_id,
            username=request.username,
            total_platforms=len(results),
            found_count=found_count,
            not_found_count=not_found_count,
            error_count=error_count,
            search_duration_ms=search_duration,
            timestamp=datetime.utcnow().isoformat(),
            results=platform_results
        )

        # Store result in Redis
        await store_search_result(search_id, response.dict())

        logger.info(
            f"Search [{search_id}] completed: "
            f"{found_count} found, {not_found_count} not found, {error_count} errors "
            f"in {search_duration}ms"
        )

        return response

    except Exception as e:
        logger.error(f"Search [{search_id}] failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")


@app.get("/api/v1/osint/sherlock/search/{username}", response_model=SearchResponse, tags=["Search"])
async def search_username_get(
    username: str = PathParam(..., description="Username to search"),
    platforms: Optional[str] = Query(None, description="Comma-separated list of platforms"),
    category: Optional[str] = Query(None, description="Platform category filter"),
    reliable_only: bool = Query(False, description="Only search reliable platforms")
):
    """
    Search for a username (GET method)

    Alternative endpoint using GET method for simple searches.
    """
    platforms_list = platforms.split(',') if platforms else None
    categories_list = [category] if category else None

    request = UsernameSearchRequest(
        username=username,
        platforms=platforms_list,
        categories=categories_list,
        reliable_only=reliable_only
    )

    return await search_username(request)


# =============================================================================
# Batch Search Endpoints
# =============================================================================

@app.post("/api/v1/osint/sherlock/batch", response_model=BatchSearchResponse, tags=["Batch Search"])
async def batch_search(
    request: BatchSearchRequest,
    background_tasks: BackgroundTasks
):
    """
    Start batch search for multiple usernames

    Creates a background job to search multiple usernames.
    Use the job_id to check status and retrieve results.

    If Celery is available and use_celery=True, uses Celery for distributed processing.
    Otherwise, uses FastAPI background tasks.
    """
    job_id = str(uuid.uuid4())

    # Estimate search time
    platform_count = len(request.platforms) if request.platforms else (sherlock_engine.get_platform_count() if sherlock_engine else 300)
    estimated_time = int(len(request.usernames) * (platform_count / 10) * 0.5)

    # Initialize job status
    job_status = {
        'status': 'pending',
        'progress': 0.0,
        'current_username': None,
        'completed_usernames': 0,
        'total_usernames': len(request.usernames),
        'results': [],
        'created_at': datetime.utcnow().isoformat(),
        'completed_at': None,
        'error': None,
        'request': request.dict()
    }

    celery_task_id = None

    # Use Celery if available and requested
    if CELERY_AVAILABLE and celery_app and request.use_celery:
        try:
            task = celery_batch_search.delay(
                job_id,
                request.usernames,
                request.platforms,
                request.categories,
                request.reliable_only
            )
            celery_task_id = task.id
            job_status['celery_task_id'] = celery_task_id
            logger.info(f"Batch job [{job_id}] submitted to Celery (task_id: {celery_task_id})")
        except Exception as e:
            logger.warning(f"Celery task submission failed: {e}, falling back to background tasks")
            background_tasks.add_task(
                process_batch_search,
                job_id,
                request.usernames,
                request.platforms,
                request.categories,
                request.reliable_only
            )
    else:
        # Use FastAPI background tasks
        background_tasks.add_task(
            process_batch_search,
            job_id,
            request.usernames,
            request.platforms,
            request.categories,
            request.reliable_only
        )

    # Store initial job status
    await store_job_status(job_id, job_status)

    logger.info(f"Batch job [{job_id}] created: {len(request.usernames)} usernames")

    return BatchSearchResponse(
        job_id=job_id,
        status="pending",
        usernames_count=len(request.usernames),
        estimated_time_seconds=estimated_time,
        message="Batch search started. Use GET /api/v1/osint/sherlock/batch/{job_id} to check status.",
        celery_task_id=celery_task_id
    )


async def process_batch_search(
    job_id: str,
    usernames: List[str],
    platforms: Optional[List[str]],
    categories: Optional[List[str]],
    reliable_only: bool = False
):
    """Background task to process batch search"""
    try:
        logger.info(f"Processing batch job [{job_id}]")

        job_status = await get_job_status(job_id) or {}
        job_status['status'] = 'processing'
        await store_job_status(job_id, job_status)

        results = []

        for i, username in enumerate(usernames):
            job_status['current_username'] = username

            # Search username
            search_results = await sherlock_engine.search_username(
                username=username,
                platforms=platforms,
                categories=categories,
                reliable_only=reliable_only
            )

            # Convert to response format
            found_count = sum(1 for r in search_results if r.status == 'found')
            not_found_count = sum(1 for r in search_results if r.status == 'not_found')
            error_count = len(search_results) - found_count - not_found_count

            search_response = {
                'search_id': f"{job_id}_{i}",
                'username': username,
                'total_platforms': len(search_results),
                'found_count': found_count,
                'not_found_count': not_found_count,
                'error_count': error_count,
                'timestamp': datetime.utcnow().isoformat(),
                'results': [
                    {
                        'platform': r.platform,
                        'url': r.url,
                        'status': r.status,
                        'confidence_score': r.confidence_score,
                        'response_time_ms': r.response_time_ms,
                        'http_status': r.http_status,
                        'category': r.metadata.get('category')
                    }
                    for r in search_results
                ]
            }

            results.append(search_response)

            # Store individual result
            await store_search_result(f"{job_id}_{i}", search_response)

            # Update progress
            job_status['completed_usernames'] = i + 1
            job_status['progress'] = (i + 1) / len(usernames) * 100
            job_status['results'] = results
            await store_job_status(job_id, job_status)

            logger.info(f"Job [{job_id}]: {i+1}/{len(usernames)} - {username}: {found_count} found")

            # Brief delay between usernames
            await asyncio.sleep(0.5)

        # Mark completed
        job_status['status'] = 'completed'
        job_status['progress'] = 100.0
        job_status['completed_at'] = datetime.utcnow().isoformat()
        job_status['current_username'] = None
        await store_job_status(job_id, job_status)

        logger.info(f"Batch job [{job_id}] completed successfully")

    except Exception as e:
        logger.error(f"Batch job [{job_id}] failed: {e}", exc_info=True)
        job_status = await get_job_status(job_id) or {}
        job_status['status'] = 'failed'
        job_status['error'] = str(e)
        await store_job_status(job_id, job_status)


@app.get("/api/v1/osint/sherlock/batch/{job_id}", response_model=JobStatusResponse, tags=["Batch Search"])
async def get_batch_status(job_id: str = PathParam(..., description="Batch job ID")):
    """Get batch search job status and results"""
    job = await get_job_status(job_id)

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Check Celery task status if applicable
    celery_task_id = job.get('celery_task_id')
    if celery_task_id and CELERY_AVAILABLE and celery_app:
        try:
            task_result = AsyncResult(celery_task_id, app=celery_app)
            if task_result.ready():
                if task_result.successful():
                    job['status'] = 'completed'
                    job['progress'] = 100.0
                    result_data = task_result.result
                    if isinstance(result_data, dict):
                        job.update(result_data)
                elif task_result.failed():
                    job['status'] = 'failed'
                    job['error'] = str(task_result.result)
            elif task_result.state == 'PENDING':
                job['status'] = 'pending'
            elif task_result.state == 'STARTED':
                job['status'] = 'processing'
        except Exception as e:
            logger.warning(f"Failed to check Celery task status: {e}")

    return JobStatusResponse(
        job_id=job_id,
        status=job.get('status', 'unknown'),
        progress=job.get('progress', 0.0),
        current_username=job.get('current_username'),
        completed_usernames=job.get('completed_usernames', 0),
        total_usernames=job.get('total_usernames', 0),
        results=job.get('results') if job.get('status') == 'completed' else None,
        created_at=job.get('created_at', datetime.utcnow().isoformat()),
        completed_at=job.get('completed_at'),
        error=job.get('error'),
        celery_task_id=job.get('celery_task_id')
    )


@app.delete("/api/v1/osint/sherlock/batch/{job_id}", tags=["Batch Search"])
async def delete_batch_job(job_id: str = PathParam(..., description="Job ID to delete")):
    """Delete a batch search job and its results"""
    job = await get_job_status(job_id)

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    # Remove from Redis
    client = await get_redis_client()
    if client:
        try:
            await client.delete(f"sherlock:job:{job_id}")
            # Also delete individual results
            for i in range(job.get('total_usernames', 0)):
                await client.delete(f"sherlock:result:{job_id}_{i}")
        except Exception as e:
            logger.error(f"Failed to delete job from Redis: {e}")

    # Remove from memory
    if job_id in background_jobs:
        del background_jobs[job_id]

    return {"message": f"Job {job_id} deleted successfully"}


@app.get("/api/v1/osint/sherlock/batch", tags=["Batch Search"])
async def list_batch_jobs(
    status: Optional[str] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=100, description="Maximum jobs to return")
):
    """List all batch search jobs"""
    jobs = []

    # Get from Redis first
    client = await get_redis_client()
    if client:
        try:
            cursor = 0
            while True:
                cursor, keys = await client.scan(cursor, match="sherlock:job:*", count=100)
                for key in keys[:limit - len(jobs)]:
                    if len(jobs) >= limit:
                        break
                    data = await client.get(key)
                    if data:
                        job_data = json.loads(data)
                        job_id = key.replace("sherlock:job:", "")
                        if status and job_data.get('status') != status:
                            continue
                        jobs.append({
                            'job_id': job_id,
                            'status': job_data.get('status'),
                            'progress': job_data.get('progress'),
                            'total_usernames': job_data.get('total_usernames'),
                            'created_at': job_data.get('created_at'),
                            'completed_at': job_data.get('completed_at')
                        })
                if cursor == 0 or len(jobs) >= limit:
                    break
        except Exception as e:
            logger.error(f"Failed to list jobs from Redis: {e}")

    # Supplement with in-memory jobs
    for job_id, job_data in list(background_jobs.items())[:limit - len(jobs)]:
        if status and job_data['status'] != status:
            continue
        if not any(j['job_id'] == job_id for j in jobs):
            jobs.append({
                'job_id': job_id,
                'status': job_data['status'],
                'progress': job_data['progress'],
                'total_usernames': job_data['total_usernames'],
                'created_at': job_data['created_at'],
                'completed_at': job_data.get('completed_at')
            })

    return {
        'total_jobs': len(jobs),
        'jobs': jobs
    }


# =============================================================================
# Results Endpoints
# =============================================================================

@app.get("/api/v1/osint/sherlock/results/{search_id}", tags=["Results"])
async def get_search_results(search_id: str = PathParam(..., description="Search ID")):
    """
    Get results for a specific search

    Results are persisted in Redis for the configured TTL (default 24 hours).
    """
    result = await get_search_result(search_id)

    if result:
        return result

    raise HTTPException(status_code=404, detail="Search results not found")


# =============================================================================
# Export Endpoints
# =============================================================================

@app.get("/api/v1/osint/sherlock/export/{job_id}", tags=["Export"])
async def export_results(
    job_id: str = PathParam(..., description="Job ID to export"),
    format: str = Query("json", regex="^(json|csv|markdown)$", description="Export format")
):
    """
    Export batch search results

    Supported formats: json, csv, markdown
    """
    job = await get_job_status(job_id)

    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    if job.get('status') != 'completed':
        raise HTTPException(status_code=400, detail="Job not completed yet")

    results = job.get('results', [])
    if not results:
        raise HTTPException(status_code=404, detail="No results to export")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"sherlock_{job_id}_{timestamp}"

    if format == "json":
        content = json.dumps(results, indent=2, default=str)
        return StreamingResponse(
            iter([content]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}.json"}
        )

    elif format == "csv":
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['Username', 'Platform', 'URL', 'Status', 'Confidence', 'Category'])

        for search_result in results:
            for platform_result in search_result.get('results', []):
                writer.writerow([
                    search_result['username'],
                    platform_result['platform'],
                    platform_result['url'],
                    platform_result['status'],
                    platform_result['confidence_score'],
                    platform_result.get('category', '')
                ])

        content = output.getvalue()
        return StreamingResponse(
            iter([content]),
            media_type="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}.csv"}
        )

    elif format == "markdown":
        lines = [
            f"# Sherlock OSINT Batch Report",
            f"",
            f"**Job ID:** {job_id}",
            f"**Generated:** {datetime.utcnow().isoformat()}",
            f"**Total Usernames:** {len(results)}",
            f"",
            "---",
            ""
        ]

        for search_result in results:
            lines.append(f"## {search_result['username']}")
            lines.append(f"")
            lines.append(f"- Platforms Found: {search_result['found_count']}/{search_result['total_platforms']}")
            lines.append(f"")

            found = [r for r in search_result.get('results', []) if r['status'] == 'found']
            if found:
                lines.append("| Platform | URL | Confidence |")
                lines.append("|----------|-----|------------|")
                for r in found:
                    conf = r.get('confidence_score', 0)
                    lines.append(f"| {r['platform']} | {r['url']} | {conf:.0%} |")
                lines.append("")
            else:
                lines.append("*No accounts found.*")
                lines.append("")

        content = "\n".join(lines)
        return StreamingResponse(
            iter([content]),
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename={filename}.md"}
        )


# =============================================================================
# Cache Management Endpoints
# =============================================================================

@app.get("/api/v1/osint/sherlock/cache/stats", tags=["Cache"])
async def get_cache_stats():
    """Get cache statistics"""
    if not sherlock_engine:
        raise HTTPException(status_code=503, detail="Engine not initialized")

    if hasattr(sherlock_engine, 'get_cache_stats'):
        stats = await sherlock_engine.get_cache_stats()
        return stats

    return {"enabled": False, "message": "Caching not configured"}


@app.delete("/api/v1/osint/sherlock/cache", tags=["Cache"])
async def clear_cache(username: Optional[str] = Query(None, description="Clear cache for specific username")):
    """Clear search cache"""
    if not sherlock_engine:
        raise HTTPException(status_code=503, detail="Engine not initialized")

    if hasattr(sherlock_engine, 'clear_cache'):
        await sherlock_engine.clear_cache(username)
        return {"message": f"Cache cleared" + (f" for {username}" if username else "")}

    return {"message": "Caching not configured"}


# =============================================================================
# Error Handlers
# =============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.status_code,
                "message": exc.detail
            }
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": 500,
                "message": "Internal server error"
            }
        }
    )


# =============================================================================
# Startup/Shutdown Events
# =============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    global sherlock_engine, batch_processor, redis_client

    logger.info("=" * 60)
    logger.info("Apollo Sherlock OSINT API starting up...")

    # Initialize Redis client
    redis_client = await get_redis_client()

    # Initialize engine with Redis caching if available
    if redis_client:
        sherlock_engine = SherlockEngine(
            max_concurrent=50,
            timeout=15,
            redis_client=redis_client
        )
        logger.info("Redis caching enabled")
    else:
        sherlock_engine = SherlockEngine(max_concurrent=50, timeout=15)
        logger.info("Running without Redis caching")

    batch_processor = BatchUsernameProcessor(sherlock_engine)

    logger.info(f"Loaded {sherlock_engine.get_platform_count()} platforms")
    logger.info(f"Categories: {', '.join(sherlock_engine.get_categories())}")
    logger.info(f"Celery available: {CELERY_AVAILABLE}")
    logger.info("=" * 60)


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    global redis_client

    logger.info("Apollo Sherlock OSINT API shutting down...")

    if redis_client:
        try:
            await redis_client.close()
        except:
            pass


# =============================================================================
# Development Server
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "fastapi_endpoints:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
        log_level="info"
    )
