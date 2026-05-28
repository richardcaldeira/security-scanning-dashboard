import os
import shutil
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.scan import Scan

router = APIRouter(prefix="/stats", tags=["stats"])


def _memory_percent() -> int:
    try:
        info = {}
        with open("/proc/meminfo") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                info[key] = int(rest.strip().split()[0])  # kB
        total = info.get("MemTotal", 0)
        available = info.get("MemAvailable", info.get("MemFree", 0))
        if total:
            return round((total - available) / total * 100)
    except Exception:
        pass
    return 0


def _cpu_percent() -> int:
    try:
        load1 = os.getloadavg()[0]
        cores = os.cpu_count() or 1
        return min(100, round(load1 / cores * 100))
    except Exception:
        return 0


def _disk_percent() -> int:
    try:
        usage = shutil.disk_usage("/")
        return round(usage.used / usage.total * 100)
    except Exception:
        return 0


@router.get("")
async def get_system_stats(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Real dashboard metrics derived from the scans table and host."""
    user = current_user["username"]
    base = select(func.count()).select_from(Scan).where(Scan.created_by == user)

    total = (await db.execute(base)).scalar() or 0
    active = (await db.execute(
        base.where(Scan.status.in_(["pending", "running"]))
    )).scalar() or 0

    start_of_day = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    completed_today = (await db.execute(
        base.where(Scan.status == "completed", Scan.completed_at >= start_of_day)
    )).scalar() or 0

    threats = (await db.execute(
        base.where(Scan.risk_level.in_(["High", "Medium"]))
    )).scalar() or 0

    return {
        "totalScans": total,
        "activeScans": active,
        "completedToday": completed_today,
        "threatsFound": threats,
        "scansTrend": 0,
        "completionTrend": 0,
        "threatsTrend": 0,
        "systemStatus": {
            "cpu": _cpu_percent(),
            "memory": _memory_percent(),
            "disk": _disk_percent(),
        },
    }
