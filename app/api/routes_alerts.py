"""Alert CRUD endpoints."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db.models import AIAssessment, Alert, Detection

router = APIRouter()


# --------------- schemas ---------------

class AlertOut(BaseModel):
    id: int
    src_ip: str
    window_start: datetime
    window_end: datetime
    title: str
    summary: str
    severity: str
    threat_type: str
    status: str
    created_at: datetime
    resolved_at: datetime | None = None
    detection_id: int | None = None
    ai_assessment_id: int | None = None

    model_config = {"from_attributes": True}


class AlertDetail(AlertOut):
    rule_hits: dict[str, Any] | None = None
    rule_score: float | None = None
    ml_score: float | None = None
    combined_risk: float | None = None
    decision: str | None = None
    ai_explanation: str | None = None
    ai_recommended_action: str | None = None
    ai_raw: dict[str, Any] | None = None


class AlertPatch(BaseModel):
    status: str  # open | acknowledged | resolved


# --------------- routes ---------------

@router.get("", response_model=list[AlertOut])
def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    src_ip: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    q = db.query(Alert).order_by(desc(Alert.created_at))
    if status:
        q = q.filter(Alert.status == status)
    if severity:
        q = q.filter(Alert.severity == severity)
    if src_ip:
        q = q.filter(Alert.src_ip == src_ip)
    return q.offset(offset).limit(limit).all()


@router.get("/stats")
def alert_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(Alert.id)).scalar() or 0
    open_count = db.query(func.count(Alert.id)).filter(Alert.status == "open").scalar() or 0
    by_severity = dict(
        db.query(Alert.severity, func.count(Alert.id))
        .group_by(Alert.severity)
        .all()
    )
    by_type = dict(
        db.query(Alert.threat_type, func.count(Alert.id))
        .group_by(Alert.threat_type)
        .all()
    )
    return {
        "total": total,
        "open": open_count,
        "by_severity": by_severity,
        "by_threat_type": by_type,
    }


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert: Alert | None = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(404, "Alert not found")

    data = AlertDetail.model_validate(alert).model_dump()

    if alert.detection_id:
        det: Detection | None = db.query(Detection).filter(Detection.id == alert.detection_id).first()
        if det:
            data["rule_hits"] = det.rule_hits
            data["rule_score"] = det.rule_score
            data["ml_score"] = det.ml_score
            data["combined_risk"] = det.combined_risk
            data["decision"] = det.decision

    if alert.ai_assessment_id:
        ai: AIAssessment | None = db.query(AIAssessment).filter(AIAssessment.id == alert.ai_assessment_id).first()
        if ai:
            data["ai_explanation"] = ai.explanation
            data["ai_recommended_action"] = ai.recommended_action
            data["ai_raw"] = ai.raw_response

    return data


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert_status(alert_id: int, body: AlertPatch, db: Session = Depends(get_db)):
    alert: Alert | None = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.status = body.status
    if body.status == "resolved":
        from app.utils.time_utils import utcnow
        alert.resolved_at = utcnow()
    db.commit()
    db.refresh(alert)
    return alert


class BulkResolveRequest(BaseModel):
    alert_ids: list[int]

@router.post("/bulk-resolve")
def bulk_resolve_alerts(body: BulkResolveRequest, db: Session = Depends(get_db)):
    from app.utils.time_utils import utcnow
    now = utcnow()
    count = (
        db.query(Alert)
        .filter(Alert.id.in_(body.alert_ids))
        .update({"status": "resolved", "resolved_at": now}, synchronize_session=False)
    )
    db.commit()
    return {"resolved_count": count}


from fastapi.responses import StreamingResponse
import csv
import io

@router.get("/export/csv")
def export_alerts_csv(db: Session = Depends(get_db)):
    alerts = db.query(Alert).order_by(desc(Alert.created_at)).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Time", "Source IP", "Severity", "Threat Type", "Status", "Summary"])
    
    for a in alerts:
        writer.writerow([
            a.id,
            a.created_at.isoformat(),
            a.src_ip,
            a.severity,
            a.threat_type,
            a.status,
            a.summary.replace("\n", " ")
        ])
        
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alerts_export.csv"}
    )

