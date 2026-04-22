"""Tests for the FastAPI application endpoints."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.main import create_app
from app.db.db_session import SessionLocal, init_db
from app.db.models import Alert, Base
from app.utils.time_utils import utcnow

# Use in-memory SQLite for tests
import os
os.environ.setdefault("NETSCAN_TEST", "1")


@pytest.fixture(scope="module")
def client():
    app = create_app()
    init_db()

    # Seed a test alert
    session = SessionLocal()
    alert = Alert(
        src_ip="10.0.0.1",
        window_start=utcnow(),
        window_end=utcnow(),
        title="Test alert",
        summary="Unit test alert",
        severity="medium",
        threat_type="vpn_usage",
        status="open",
        created_at=utcnow(),
    )
    session.add(alert)
    session.commit()
    session.close()

    with TestClient(app) as c:
        yield c


class TestHealthEndpoint:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"


class TestAlertsEndpoint:
    def test_list_alerts(self, client):
        resp = client.get("/alerts")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_alert_stats(self, client):
        resp = client.get("/alerts/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total" in data
        assert "open" in data

    def test_get_alert_detail(self, client):
        resp = client.get("/alerts/1")
        assert resp.status_code == 200
        data = resp.json()
        assert data["src_ip"] == "10.0.0.1"

    def test_get_alert_not_found(self, client):
        resp = client.get("/alerts/9999")
        assert resp.status_code == 404

    def test_patch_alert_status(self, client):
        resp = client.patch("/alerts/1", json={"status": "acknowledged"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "acknowledged"


class TestDashboard:
    def test_dashboard_renders(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "NetScan" in resp.text
