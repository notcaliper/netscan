from __future__ import annotations

from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker

from app.config import load_config
from app.db.models import Base


def _get_engine():
    cfg = load_config()
    # check_same_thread is required for SQLite with FastAPI dev usage
    connect_args = {"check_same_thread": False} if cfg.db_url.startswith("sqlite") else {}
    from sqlalchemy.pool import StaticPool
    poolclass = StaticPool if ":memory:" in cfg.db_url else None
    engine = create_engine(cfg.db_url, future=True, connect_args=connect_args, poolclass=poolclass)

    if cfg.db_url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragmas(dbapi_conn, _conn_record):
            # WAL mode: allows concurrent readers + one writer — eliminates most "db locked" errors
            dbapi_conn.execute("PRAGMA journal_mode=WAL")
            # If the DB is momentarily busy, wait up to 5 s instead of erroring immediately
            dbapi_conn.execute("PRAGMA busy_timeout=5000")

    return engine


engine = _get_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def init_db() -> None:
    Base.metadata.create_all(bind=engine)

