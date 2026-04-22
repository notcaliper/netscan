"""Device-level endpoints."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db.models import Alert, Detection, Device, NetworkFeature

router = APIRouter()


class DeviceOut(BaseModel):
    id: int
    ip_address: str
    mac_address: str | None = None
    hostname: str | None = None
    owner: str | None = None
    last_seen: datetime

    model_config = {"from_attributes": True}


class DeviceSummary(BaseModel):
    ip: str
    total_detections: int
    total_alerts: int
    latest_risk: float | None
    latest_window: datetime | None


@router.get("", response_model=list[DeviceOut])
def list_devices(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    return db.query(Device).order_by(desc(Device.last_seen)).limit(limit).all()


@router.get("/{ip}")
def device_detail(ip: str, db: Session = Depends(get_db)):
    device = db.query(Device).filter(Device.ip_address == ip).first()
    recent_detections = (
        db.query(Detection)
        .filter(Detection.src_ip == ip)
        .order_by(desc(Detection.created_at))
        .limit(20)
        .all()
    )
    recent_alerts = (
        db.query(Alert)
        .filter(Alert.src_ip == ip)
        .order_by(desc(Alert.created_at))
        .limit(20)
        .all()
    )
    recent_features = (
        db.query(NetworkFeature)
        .filter(NetworkFeature.src_ip == ip)
        .order_by(desc(NetworkFeature.window_start))
        .limit(10)
        .all()
    )

    return {
        "device": {
            "ip_address": ip,
            "hostname": device.hostname if device else None,
            "owner": device.owner if device else None,
            "last_seen": device.last_seen.isoformat() if device else None,
        },
        "recent_detections": [
            {
                "id": d.id,
                "window_start": d.window_start.isoformat(),
                "combined_risk": d.combined_risk,
                "decision": d.decision,
                "rule_score": d.rule_score,
                "ml_score": d.ml_score,
            }
            for d in recent_detections
        ],
        "recent_alerts": [
            {
                "id": a.id,
                "title": a.title,
                "severity": a.severity,
                "status": a.status,
                "created_at": a.created_at.isoformat(),
            }
            for a in recent_alerts
        ],
        "recent_features": [
            {
                "window_start": f.window_start.isoformat(),
                "num_flows": f.num_flows,
                "total_bytes_sent": f.total_bytes_sent,
                "num_unique_dst_ips": f.num_unique_dst_ips,
                "distinct_dst_ports": f.distinct_dst_ports,
            }
            for f in recent_features
        ],
    }


@router.get("/summary/all")
def devices_summary(db: Session = Depends(get_db)):
    """Get a summary of all IPs that have had detections."""
    rows = (
        db.query(
            Detection.src_ip,
            func.count(Detection.id).label("det_count"),
            func.max(Detection.combined_risk).label("max_risk"),
            func.max(Detection.window_start).label("latest"),
        )
        .group_by(Detection.src_ip)
        .order_by(desc("max_risk"))
        .limit(100)
        .all()
    )
    alert_counts: dict[str, int] = dict(
        db.query(Alert.src_ip, func.count(Alert.id))
        .group_by(Alert.src_ip)
        .all()
    )
    return [
        DeviceSummary(
            ip=r.src_ip,
            total_detections=r.det_count,
            total_alerts=alert_counts.get(r.src_ip, 0),
            latest_risk=r.max_risk,
            latest_window=r.latest,
        ).model_dump()
        for r in rows
    ]
