"""
diagnostics.py — readiness and pipeline debug endpoints.
"""
import asyncio

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from app.api.deps import get_current_user_dep
from app.models.user import User
from app.services.diagnostics import collect_pipeline_state, collect_readiness_status

router = APIRouter(tags=["diagnostics"])


@router.get("/health/ready")
async def health_ready():
    readiness = await asyncio.to_thread(collect_readiness_status)
    status_code = 200 if readiness["ok"] else 503
    return JSONResponse(status_code=status_code, content=readiness)


@router.get("/api/debug/pipeline")
async def pipeline_debug_snapshot(_: User = Depends(get_current_user_dep)):
    """Pipeline state snapshot. Requires an authenticated session."""
    snapshot = await asyncio.to_thread(collect_pipeline_state)
    return snapshot
