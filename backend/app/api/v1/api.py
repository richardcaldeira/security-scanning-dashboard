from fastapi import APIRouter

from app.api.v1.endpoints import scans, stats

api_router = APIRouter()

# scans.router already declares prefix="/scans"; do not add it again here
api_router.include_router(scans.router, tags=["scans"])
api_router.include_router(stats.router, tags=["stats"])
