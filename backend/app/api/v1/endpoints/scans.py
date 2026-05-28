import uuid
import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db, AsyncSessionLocal
from app.core.config import settings
from app.core.security import get_current_user
from app.services.scan_service import ScanService
from app.services.mcp_client import MCPClient
from app.models.scan import Scan
from app.api.v1.schemas.scan import ScanCreate, ScanResponse, ScanStatus

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"])

# Scan service wired to the real MCP security-tools backend
scan_service = ScanService(MCPClient(settings.MCP_SERVER_URL))


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _risk_level(output: str) -> str:
    if not output:
        return "Low"
    low = output.lower()
    if any(k in low for k in ["vulnerable", "exploit", "critical", "remote code execution", "sql injection"]):
        return "High"
    if any(k in low for k in ["warning", "medium", "cve", "outdated", "misconfiguration"]):
        return "Medium"
    return "Low"


async def execute_scan_background(scan_id: str):
    """Run the scan via the MCP backend and persist the result."""
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            logger.error("Scan %s not found for execution", scan_id)
            return
        scan.status = "running"
        scan.started_at = _now()
        await db.commit()

    result = await scan_service.execute_scan(scan.tool, scan.config or {})
    output = result.get("output", "") or ""
    error = result.get("error", "") or ""
    success = result.get("success", False) and not error

    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = "completed" if success else "failed"
        scan.completed_at = _now()
        scan.output = output
        scan.error = error
        scan.findings = len([ln for ln in output.splitlines() if ln.strip()]) if output else 0
        scan.risk_level = _risk_level(output)
        await db.commit()
    logger.info("Scan %s finished: %s", scan_id, scan.status)


@router.post("", response_model=ScanResponse)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a scan and execute it in the background."""
    scan = Scan(
        id=str(uuid.uuid4()),
        tool=scan_data.tool,
        target=scan_data.config.get("target") or scan_data.config.get("term") or "unknown",
        config=scan_data.config,
        status="pending",
        created_by=current_user["username"],
        created_at=_now(),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(execute_scan_background, scan.id)
    return ScanResponse.model_validate(scan)


@router.get("", response_model=List[ScanResponse])
async def get_scans(
    skip: int = 0,
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List scans for the current user, newest first."""
    result = await db.execute(
        select(Scan)
        .where(Scan.created_by == current_user["username"])
        .order_by(Scan.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    scans = result.scalars().all()
    return [ScanResponse.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.get(Scan, scan_id)
    if scan is None or scan.created_by != current_user["username"]:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResponse.model_validate(scan)


@router.get("/{scan_id}/status", response_model=ScanStatus)
async def get_scan_status(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.get(Scan, scan_id)
    if scan is None or scan.created_by != current_user["username"]:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanStatus(
        status=scan.status,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    )


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.get(Scan, scan_id)
    if scan is None or scan.created_by != current_user["username"]:
        raise HTTPException(status_code=404, detail="Scan not found")
    await db.execute(delete(Scan).where(Scan.id == scan_id))
    await db.commit()
    return {"message": "Scan deleted successfully"}


@router.post("/{scan_id}/export")
async def export_scan(
    scan_id: str,
    format: str = "json",
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    scan = await db.get(Scan, scan_id)
    if scan is None or scan.created_by != current_user["username"]:
        raise HTTPException(status_code=404, detail="Scan not found")
    if format == "json":
        return ScanResponse.model_validate(scan).model_dump()
    raise HTTPException(status_code=400, detail="Unsupported export format")
