"""FastAPI application factory & lifespan."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.db.db_session import init_db

from .routes_alerts import router as alerts_router
from .routes_devices import router as devices_router
from .routes_health import router as health_router

TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent.parent.parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    from app.utils.logging_utils import setup_logging
    setup_logging()
    init_db()
    yield
    # Shutdown — stop live capture if running
    from app.capture.live_capture_service import LiveCaptureService
    svc = LiveCaptureService.get_instance()
    if svc.is_running:
        svc.stop()


def create_app() -> FastAPI:
    app = FastAPI(
        title="NetScan – Network Intrusion Detection System",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Mount static files if dir exists
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Include routers
    app.include_router(health_router, tags=["health"])
    app.include_router(alerts_router, prefix="/alerts", tags=["alerts"])
    app.include_router(devices_router, prefix="/devices", tags=["devices"])

    # Dashboard HTML route
    from .routes_dashboard import router as dash_router
    app.include_router(dash_router, tags=["dashboard"])

    # Live monitoring API
    from .routes_live import router as live_router
    app.include_router(live_router, prefix="/api/live", tags=["live"])

    # Blocked IPs admin review
    from .routes_blocked import router as blocked_router
    app.include_router(blocked_router, tags=["blocked"])

    return app
