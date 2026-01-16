"""
Routes Package
Exports all route modules for FastAPI application.
"""

from . import (
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

__all__ = [
    'osint_routes',
    'blockchain_routes',
    'socmint_routes',
    'geoint_routes',
    'fusion_routes',
    'breach_routes',
    'darkweb_routes',
    'facial_routes',
    'voice_routes',
    'recon_routes'
]
