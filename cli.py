#!/usr/bin/env python
"""
NetScan Unified CLI Tool

Usage:
    python cli.py api          # Start dashboard & API server
    python cli.py capture      # Run packet capture & processing pipeline
    python cli.py live         # Run live capture & auto-open dashboard
    python cli.py detect       # Run detection on unprocessed features
    python cli.py train        # Train the ML anomaly detection model
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
import threading
import time
import webbrowser

from sqlalchemy import func

from app.config import load_config
from app.db.db_session import SessionLocal, init_db
from app.db.models import Detection, NetworkFeature
from app.detection.hybrid_detector import HybridDetector
from app.features.feature_types import FeatureVector
from app.ai_reasoner.ai_decision_logic import AIDecisionLogic
from app.alerts.alert_manager import AlertManager
from app.alerts.notifier import Notifier
from app.utils.logging_utils import setup_logging


def is_admin() -> bool:
    """Check if running with root privileges (Linux)."""
    try:
        return os.getuid() == 0
    except AttributeError:
        return False


def run_api(args: argparse.Namespace) -> None:
    """Run the FastAPI admin dashboard and API server."""
    import uvicorn
    # Delay import so it doesn't run during help output
    from app.api.main import create_app
    app = create_app()

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


def run_capture(args: argparse.Namespace) -> None:
    """Run the continuous capture and processing loop."""
    from app.capture.capture_runner import run_capture_loop
    from app.capture.packet_source import auto_detect_interface
    from app.features.feature_extractor import FeatureExtractor
    from app.detection.dns_intelligence import DNSIntelligenceModule
    from app.db.db_session import SessionLocal, init_db
    from app.db.models import Device
    from app.utils.time_utils import utcnow

    setup_logging()
    logger = logging.getLogger("netscan.capture_main")
    init_db()
    conf = load_config()

    from app.capture.pipeline import ProcessingPipeline
    pipeline = ProcessingPipeline(conf.window_seconds)

    iface = args.interface or auto_detect_interface()
    logger.info(
        "Starting capture runner in %s mode (interface: %s)",
        args.mode, iface or "auto"
    )

    try:
        for capture_out in run_capture_loop(
            mode=args.mode,
            interface=iface,
        ):
            session = SessionLocal()
            try:
                pipeline.process_window(session, capture_out)
                session.commit()
            except Exception:
                session.rollback()
                logger.exception("Error processing window")
            finally:
                session.close()

    except KeyboardInterrupt:
        logger.info("Stopped gracefully by user.")


def run_live(args: argparse.Namespace) -> None:
    """Start the API dashboard and automatically begin live network capture."""
    setup_logging()
    logger = logging.getLogger("netscan.launcher")

    if not is_admin():
        logger.warning(
            "⚠  Not running as root! Live capture and firewall blocking may fail. "
            "Re-run with: sudo %s",
            " ".join(sys.argv),
        )

    init_db()

    from app.capture.live_capture_service import LiveCaptureService
    svc = LiveCaptureService.get_instance()

    if not args.no_capture:
        logger.info("Starting live capture...")
        interface = args.interface or "eth0"
        result = svc.start(interface=interface)
        if result.get("status") == "started":
            logger.info("✓ Live capture started on %s", result.get("interface"))
        else:
            logger.warning("⚠  Capture start result: %s", result)

    if not args.no_browser:
        def _open_browser():
            time.sleep(2)
            url = f"http://localhost:{args.port}"
            logger.info("Opening browser at %s", url)
            webbrowser.open(url)
        threading.Thread(target=_open_browser, daemon=True).start()

    import uvicorn
    from app.api.main import create_app
    app = create_app()

    logger.info("Starting NetScan dashboard on port %d...", args.port)
    logger.info("Press Ctrl+C to stop.")

    try:
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=args.port,
            log_level="info",
        )
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        svc.stop()


def run_detect(args: argparse.Namespace) -> None:
    """Run detection on existing feature rows that haven't been processed yet."""
    setup_logging()
    logger = logging.getLogger("netscan.batch_detect")
    init_db()

    detector = HybridDetector()
    ai_logic = AIDecisionLogic()
    alert_mgr = AlertManager()
    notifier = Notifier()

    session = SessionLocal()
    try:
        already = session.query(Detection.feature_id).subquery()
        unprocessed = (
            session.query(NetworkFeature)
            .filter(~NetworkFeature.id.in_(session.query(already.c.feature_id)))
            .order_by(NetworkFeature.window_start)
            .all()
        )
        logger.info("Found %d unprocessed feature rows", len(unprocessed))

        for nf in unprocessed:
            fv = FeatureVector(
                window_start=nf.window_start,
                window_end=nf.window_end,
                src_ip=nf.src_ip,
                dst_category=nf.dst_category,
                num_flows=nf.num_flows,
                num_unique_dst_ips=nf.num_unique_dst_ips,
                num_unique_domains=nf.num_unique_domains,
                total_bytes_sent=nf.total_bytes_sent,
                total_bytes_received=nf.total_bytes_received,
                avg_packet_size=nf.avg_packet_size,
                std_packet_size=nf.std_packet_size,
                avg_inter_packet_time=nf.avg_inter_packet_time,
                std_inter_packet_time=nf.std_inter_packet_time,
                tcp_flow_count=nf.tcp_flow_count,
                udp_flow_count=nf.udp_flow_count,
                dns_query_count=nf.dns_query_count,
                distinct_dst_ports=nf.distinct_dst_ports,
                top_port=nf.top_port,
                ratio_known_vpn_ips=nf.ratio_known_vpn_ips,
                ratio_known_restricted_domains=nf.ratio_known_restricted_domains,
                extra=nf.extra or {},
            )

            dr = detector.detect(fv)
            det = alert_mgr.persist_detection(session, fv, dr, nf.id)

            ai_result = None
            ai_id = None
            if ai_logic.should_escalate(dr):
                ai_result = ai_logic.assess_sync(fv, dr)
                ai_obj = alert_mgr.persist_ai_assessment(session, det.id, ai_result)
                ai_id = ai_obj.id

            if dr.decision != "allow":
                alert = alert_mgr.create_alert(
                    session, fv, dr, det.id,
                    ai=ai_result, ai_assessment_id=ai_id,
                )
                notifier.notify(alert.title, alert.summary, alert.severity)

            logger.info(
                "  %s → risk=%.2f (%s)",
                fv.src_ip, dr.combined_risk, dr.decision,
            )

        session.commit()
        logger.info("Batch detection complete.")
    except Exception:
        session.rollback()
        logger.exception("Batch detection failed")
    finally:
        session.close()


def run_train(args: argparse.Namespace) -> None:
    """Train the anomaly detection model using baseline data in the database."""
    import yaml
    import joblib
    import pandas as pd
    import os
    from sqlalchemy import create_engine
    from sklearn.ensemble import IsolationForest

    setup_logging()
    logger = logging.getLogger("netscan.train")

    # Load config
    config_path = os.path.join("models", "ml_config.yaml")
    if not os.path.exists(config_path):
        logger.error("ML config not found at %s. Ensure you are in the project root.", config_path)
        return

    try:
        with open(config_path, "r") as f:
            ml_cfg = yaml.safe_load(f)
    except Exception as e:
        logger.error("Failed to load ML config: %s", e)
        return

    FEATURE_COLS = ml_cfg["features"]
    MODEL_PARAMS = ml_cfg["model"]["params"]
    OUTPUT_PATH = ml_cfg["training"]["output_path"]
    MIN_SAMPLES = ml_cfg["training"].get("min_samples", 500)

    # Load data
    logger.info("Loading baseline data from database...")
    DB_URL = "sqlite:///netscan.db"
    engine = create_engine(DB_URL)
    
    try:
        # Use a raw SQL query or read_sql_table
        df = pd.read_sql_table("network_features", engine)
    except Exception as e:
        logger.error("Failed to load data from 'network_features' table: %s. Have you captured any traffic yet?", e)
        return

    count = len(df)
    logger.info("Found %d samples in database.", count)

    if count < 2:
        logger.error("Not enough data to train. Capture some normal traffic first.")
        return

    if count < MIN_SAMPLES:
        logger.warning("Found only %d samples. Recommended minimum is %d. The model might be unreliable.", count, MIN_SAMPLES)

    # Preprocess
    logger.info("Preprocessing features...")
    # Ensure all columns exist
    missing = [c for c in FEATURE_COLS if c not in df.columns]
    if missing:
        logger.error("Missing expected feature columns in DB: %s", missing)
        return

    X = df[FEATURE_COLS].fillna(0).values.astype(float)

    # Train
    logger.info("Training IsolationForest model (n_estimators=%d)...", MODEL_PARAMS.get("n_estimators", 100))
    model = IsolationForest(**MODEL_PARAMS)
    try:
        model.fit(X)
    except Exception as e:
        logger.error("Training failed: %s", e)
        return

    # Save
    logger.info("Saving model to %s...", OUTPUT_PATH)
    try:
        os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
        joblib.dump(model, OUTPUT_PATH)
        logger.info("✓ Training complete. The detection pipeline will now use this model for scoring.")
    except Exception as e:
        logger.error("Failed to save model: %s", e)


def main() -> None:
    parser = argparse.ArgumentParser(description="NetScan Unified CLI Tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # API Server command
    api_parser = subparsers.add_parser("api", help="Start the API server and dashboard")
    api_parser.add_argument("--host", default="0.0.0.0", help="Host ID to bind the API Server")
    api_parser.add_argument("--port", type=int, default=8000, help="Port to bind the API Server")
    api_parser.add_argument("--reload", action="store_true", help="Enable hot-reload for the server")

    # Capture command
    capture_parser = subparsers.add_parser("capture", help="Run the continuous packet capture pipeline")
    capture_parser.add_argument("--mode", choices=["scapy"], default="scapy", help="Capture backend mode")
    capture_parser.add_argument("--interface", help="Interface name or index. Required for scapy mode.")

    # Live monitor command
    live_parser = subparsers.add_parser("live", help="Start dashboard and live auto-capture")
    live_parser.add_argument("--interface", default=None, help="Network interface name (default: auto-detect)")
    live_parser.add_argument("--port", type=int, default=8000, help="Dashboard port (default: 8000)")
    live_parser.add_argument("--no-capture", action="store_true", help="Start dashboard only")
    live_parser.add_argument("--no-browser", action="store_true", help="Don't auto-open browser")

    # Detection batch command
    detect_parser = subparsers.add_parser("detect", help="Run detection on unprocessed feature rows in DB")

    # Training command
    train_parser = subparsers.add_parser("train", help="Train the ML anomaly detection model using DB data")

    args = parser.parse_args()

    if args.command == "api":
        run_api(args)
    elif args.command == "capture":
        run_capture(args)
    elif args.command == "live":
        run_live(args)
    elif args.command == "detect":
        run_detect(args)
    elif args.command == "train":
        run_train(args)


if __name__ == "__main__":
    main()
