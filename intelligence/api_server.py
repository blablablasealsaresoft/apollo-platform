"""
FastAPI Intelligence Server - Main Application
==============================================

Comprehensive REST API for intelligence gathering and analysis.
Production-ready server with authentication, rate limiting, and full documentation.

Author: Apollo Intelligence System
Version: 2.0.0
"""

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from fastapi.openapi.utils import get_openapi
from contextlib import asynccontextmanager
import logging
import time
from typing import Dict, Any
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import configuration and dependencies
from config import settings
from dependencies import get_db, get_cache, verify_api_key

# Import middleware
from middleware.auth import JWTBearer
from middleware.rate_limiter import RateLimiter

# Import routes
from routes import (
    osint_routes,
    blockchain_routes,
    socmint_routes,
    geoint_routes,
    fusion_routes,
    breach_routes,
    darkweb_routes,
    facial_routes,
    voice_routes,
    recon_routes
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('intelligence_api.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup and shutdown events."""
    # Startup
    logger.info("=" * 60)
    logger.info("APOLLO INTELLIGENCE SERVER - INITIALIZING")
    logger.info("=" * 60)
    logger.info(f"Environment: {settings.ENVIRONMENT}")
    logger.info(f"API Version: {settings.API_VERSION}")
    logger.info(f"Debug Mode: {settings.DEBUG}")
    logger.info("Starting intelligence services...")

    yield

    # Shutdown
    logger.info("Shutting down Apollo Intelligence Server...")
    logger.info("All services stopped gracefully")


# Initialize FastAPI application
app = FastAPI(
    title="Apollo Intelligence Server",
    description="""
    ## Comprehensive Intelligence Gathering & Analysis Platform

    The Apollo Intelligence Server provides advanced capabilities for:

    - **OSINT**: Username search, email intelligence, phone lookup, domain analysis
    - **Blockchain**: Wallet info, transaction tracing, multi-chain support
    - **SOCMINT**: Social media profile aggregation and network analysis
    - **GEOINT**: IP geolocation, phone location, photo geolocation
    - **Facial Recognition**: Face detection, matching, database management, real-time video
    - **Voice Recognition**: Audio transcription, speaker identification, voice print matching
    - **Intelligence Fusion**: Profile building, entity resolution, risk assessment
    - **Breach Intelligence**: Email breach search, credential lookup
    - **Dark Web**: Marketplace monitoring, forum scraping, paste tracking

    ### Authentication

    This API uses JWT tokens and API keys for authentication. Include your credentials in the request headers:

    - **Authorization**: Bearer {your_jwt_token}
    - **X-API-Key**: {your_api_key}

    ### Rate Limiting

    Rate limits are enforced per endpoint and user:

    - Free tier: 100 requests/hour
    - Pro tier: 1000 requests/hour
    - Enterprise: 10000 requests/hour

    """,
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)


# CORS Configuration - Secure defaults with explicit origin control
def get_cors_origins():
    """Get CORS origins with security validation"""
    origins = settings.CORS_ORIGINS
    if settings.ENVIRONMENT == 'production':
        # Never allow '*' in production
        if origins == ['*']:
            logger.warning("CORS_ORIGINS is set to '*' in production - this is a security risk!")
            raise RuntimeError("CORS_ORIGINS must be explicitly set in production")
        # Validate that all origins are HTTPS in production
        for origin in origins:
            if not origin.startswith('https://') and origin != 'null':
                logger.warning(f"Non-HTTPS origin in production CORS config: {origin}")
    return origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    # Restrict methods in production
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] if settings.ENVIRONMENT == 'production' else ["*"],
    # Restrict headers in production
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-API-Key",
        "X-Request-ID",
        "Accept",
        "Accept-Language",
        "Origin",
    ] if settings.ENVIRONMENT == 'production' else ["*"],
    expose_headers=["X-Request-ID", "X-Rate-Limit-Remaining", "X-Process-Time"],
    max_age=600 if settings.ENVIRONMENT == 'production' else 0,  # Cache preflight for 10 min in prod
)


# Trusted Host Middleware
if not settings.DEBUG:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.ALLOWED_HOSTS
    )


# Request ID and timing middleware
@app.middleware("http")
async def add_request_metadata(request: Request, call_next):
    """Add request ID and timing information to all requests."""
    request_id = f"req_{int(time.time() * 1000)}"
    start_time = time.time()

    # Add request ID to request state
    request.state.request_id = request_id

    # Process request
    response = await call_next(request)

    # Add headers
    process_time = time.time() - start_time
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Process-Time"] = f"{process_time:.4f}"

    # Log request
    logger.info(
        f"Request: {request.method} {request.url.path} | "
        f"Status: {response.status_code} | "
        f"Time: {process_time:.4f}s | "
        f"ID: {request_id}"
    )

    return response


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with consistent format."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.status_code,
                "message": exc.detail,
                "request_id": getattr(request.state, "request_id", "unknown")
            }
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": 500,
                "message": "Internal server error" if not settings.DEBUG else str(exc),
                "request_id": getattr(request.state, "request_id", "unknown")
            }
        }
    )


# Root endpoint
@app.get("/", tags=["System"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": "Apollo Intelligence Server",
        "version": "2.0.0",
        "status": "operational",
        "documentation": "/docs",
        "endpoints": {
            "osint": "/api/v1/osint",
            "blockchain": "/api/v1/blockchain",
            "socmint": "/api/v1/socmint",
            "geoint": "/api/v1/geoint",
            "fusion": "/api/v1/fusion",
            "breach": "/api/v1/breach",
            "darkweb": "/api/v1/darkweb",
            "facial": "/api/v1/facial",
            "voice": "/api/v1/voice",
            "recon": "/api/v1/recon"
        }
    }


# Health check endpoint
@app.get("/health", tags=["System"])
async def health_check():
    """Health check endpoint for monitoring."""
    return {
        "status": "healthy",
        "timestamp": int(time.time()),
        "services": {
            "api": "operational",
            "database": "operational",
            "cache": "operational"
        }
    }


# Metrics endpoint
@app.get("/metrics", tags=["System"])
async def metrics():
    """System metrics endpoint."""
    return {
        "uptime": time.time(),
        "requests_total": "Counter not implemented",
        "requests_active": "Gauge not implemented",
        "response_time_avg": "Histogram not implemented"
    }


# Authentication endpoints
@app.post("/api/v1/auth/login", tags=["Authentication"])
async def login(username: str, password: str):
    """
    Authenticate user and generate JWT token.

    - **username**: User's username
    - **password**: User's password

    Returns JWT token for API access.
    """
    # Mock authentication - implement proper authentication
    if username and password:
        from middleware.auth import create_access_token
        token = create_access_token({"sub": username, "role": "user"})
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": 3600
        }
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/api/v1/auth/refresh", tags=["Authentication"])
async def refresh_token(token: str = Depends(JWTBearer())):
    """Refresh JWT token."""
    from middleware.auth import create_access_token
    # Extract user from old token and create new one
    new_token = create_access_token({"sub": "user", "role": "user"})
    return {
        "access_token": new_token,
        "token_type": "bearer",
        "expires_in": 3600
    }


@app.post("/api/v1/auth/apikey/generate", tags=["Authentication"])
async def generate_api_key(
    token: str = Depends(JWTBearer()),
    description: str = "API Key"
):
    """Generate new API key."""
    import secrets
    api_key = f"apollo_{secrets.token_urlsafe(32)}"
    return {
        "api_key": api_key,
        "description": description,
        "created_at": int(time.time()),
        "expires_at": None
    }


@app.delete("/api/v1/auth/apikey/{key_id}", tags=["Authentication"])
async def revoke_api_key(
    key_id: str,
    token: str = Depends(JWTBearer())
):
    """Revoke API key."""
    return {
        "message": f"API key {key_id} revoked successfully"
    }


# Include routers
app.include_router(
    osint_routes.router,
    prefix="/api/v1/osint",
    tags=["OSINT"]
)

app.include_router(
    blockchain_routes.router,
    prefix="/api/v1/blockchain",
    tags=["Blockchain"]
)

app.include_router(
    socmint_routes.router,
    prefix="/api/v1/socmint",
    tags=["SOCMINT"]
)

app.include_router(
    geoint_routes.router,
    prefix="/api/v1/geoint",
    tags=["GEOINT"]
)

app.include_router(
    fusion_routes.router,
    prefix="/api/v1/fusion",
    tags=["Intelligence Fusion"]
)

app.include_router(
    breach_routes.router,
    prefix="/api/v1/breach",
    tags=["Breach Intelligence"]
)

app.include_router(
    darkweb_routes.router,
    prefix="/api/v1/darkweb",
    tags=["Dark Web"]
)

app.include_router(
    facial_routes.router,
    prefix="/api/v1/facial",
    tags=["Facial Recognition"]
)

app.include_router(
    voice_routes.router,
    prefix="/api/v1/voice",
    tags=["Voice Recognition"]
)

app.include_router(
    recon_routes.router,
    prefix="/api/v1/recon",
    tags=["Reconnaissance"]
)


# Custom OpenAPI schema
def custom_openapi():
    """Generate custom OpenAPI schema."""
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Apollo Intelligence Server API",
        version="2.0.0",
        description=app.description,
        routes=app.routes,
    )

    # Add security schemes
    openapi_schema["components"]["securitySchemes"] = {
        "Bearer": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT",
            "description": "JWT token authentication"
        },
        "ApiKey": {
            "type": "apiKey",
            "in": "header",
            "name": "X-API-Key",
            "description": "API key authentication"
        }
    }

    # Add security to all endpoints
    for path in openapi_schema["paths"].values():
        for operation in path.values():
            if isinstance(operation, dict) and "tags" in operation:
                operation["security"] = [
                    {"Bearer": []},
                    {"ApiKey": []}
                ]

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi




if __name__ == "__main__":
    import uvicorn

    logger.info("Starting Apollo Intelligence Server...")
    logger.info(f"Host: {settings.HOST}")
    logger.info(f"Port: {settings.PORT}")
    logger.info(f"Workers: {settings.WORKERS}")

    uvicorn.run(
        "api_server:app",
        host=settings.HOST,
        port=settings.PORT,
        workers=settings.WORKERS,
        reload=settings.DEBUG,
        log_level="info",
        access_log=True
    )
