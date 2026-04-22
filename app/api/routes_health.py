import os
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.api.deps import get_db
from app.config import load_config
from app.db.models import Alert, Detection

router = APIRouter()


@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    cfg = load_config()
    db_path = cfg.db_url.replace("sqlite:///", "")
    db_size_mb = 0.0
    if os.path.exists(db_path) and db_path != ":memory:":
        db_size_mb = round(os.path.getsize(db_path) / (1024 * 1024), 2)
        
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    total_detections = db.query(func.count(Detection.id)).scalar() or 0
    
    return {
        "status": "ok",
        "app": cfg.raw.get("app", {}).get("name", "netscan"),
        "db": {
            "type": cfg.db_url.split("://")[0],
            "size_mb": db_size_mb,
            "total_alerts": total_alerts,
            "total_detections": total_detections,
        },
        "gemini_enabled": cfg.raw.get("gemini", {}).get("enabled", False),
    }
