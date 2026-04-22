"""Shared FastAPI dependencies for route modules."""
from __future__ import annotations

from app.db.db_session import SessionLocal


def get_db():
    """Yield a SQLAlchemy session, closing it when the request finishes."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
