"""Alert persistence and lifecycle management."""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.ai_reasoner.ai_decision_logic import AIAssessmentResult
from app.db.models import AIAssessment, Alert, Detection, NetworkFeature
from app.detection.hybrid_detector import DetectionResult
from app.features.feature_types import FeatureVector
from app.utils.time_utils import utcnow

logger = logging.getLogger("netscan.alerts")


class AlertManager:
    """Creates and persists detection results, AI assessments, and alerts."""

    # ------------------------------------------------------------------
    # Core persistence
    # ------------------------------------------------------------------

    def persist_feature(self, session: Session, fv: FeatureVector) -> NetworkFeature:
        """Write a FeatureVector to the network_features table."""
        nf = NetworkFeature(
            window_start=fv.window_start,
            window_end=fv.window_end,
            src_ip=fv.src_ip,
            dst_category=fv.dst_category,
            num_packets=fv.num_packets,
            num_flows=fv.num_flows,
            num_unique_dst_ips=fv.num_unique_dst_ips,
            num_unique_domains=fv.num_unique_domains,
            total_bytes_sent=fv.total_bytes_sent,
            total_bytes_received=fv.total_bytes_received,
            avg_packet_size=fv.avg_packet_size,
            std_packet_size=fv.std_packet_size,
            avg_inter_packet_time=fv.avg_inter_packet_time,
            std_inter_packet_time=fv.std_inter_packet_time,
            tcp_flow_count=fv.tcp_flow_count,
            udp_flow_count=fv.udp_flow_count,
            dns_query_count=fv.dns_query_count,
            distinct_dst_ports=fv.distinct_dst_ports,
            top_port=fv.top_port,
            ratio_known_vpn_ips=fv.ratio_known_vpn_ips,
            ratio_known_restricted_domains=fv.ratio_known_restricted_domains,
            extra=fv.extra,
        )
        session.add(nf)
        session.flush()
        return nf

    def persist_detection(
        self,
        session: Session,
        fv: FeatureVector,
        dr: DetectionResult,
        feature_id: int,
    ) -> Detection:
        """Write a DetectionResult to the detections table."""
        det = Detection(
            feature_id=feature_id,
            src_ip=fv.src_ip,
            window_start=fv.window_start,
            window_end=fv.window_end,
            rule_hits=dr.rule_hits,
            rule_score=dr.rule_score,
            ml_score=dr.ml_score,
            ml_confidence=dr.ml_confidence,
            combined_risk=dr.combined_risk,
            correlation_hits=dr.correlation_hits,
            guessed_threat_type=dr.guessed_threat_type,
            ml_model_used=dr.ml_model_used,
            top_features=dr.top_features,
            boosted=dr.boosted,
            decision=dr.decision,
            needs_ai=dr.needs_ai,
            created_at=utcnow(),
        )
        session.add(det)
        session.flush()
        return det

    def persist_ai_assessment(
        self,
        session: Session,
        detection_id: int,
        ai: AIAssessmentResult,
    ) -> AIAssessment:
        """Write an AI assessment to the ai_assessments table."""
        aa = AIAssessment(
            detection_id=detection_id,
            threat_type=ai.threat_type,
            severity=ai.severity,
            explanation=ai.explanation,
            recommended_action=ai.recommended_action,
            raw_response=ai.raw_response,
            created_at=utcnow(),
        )
        session.add(aa)
        session.flush()
        return aa

    # ------------------------------------------------------------------
    # Alert deduplication cooldown (seconds)
    # ------------------------------------------------------------------
    DEDUP_COOLDOWN = 300  # 5 minutes — same (src_ip, threat_type) won't create new alert

    def create_alert(
        self,
        session: Session,
        fv: FeatureVector,
        dr: DetectionResult,
        detection_id: int,
        ai: AIAssessmentResult | None = None,
        ai_assessment_id: int | None = None,
    ) -> Alert:
        """Create an alert record in the DB, deduplicating recent identical alerts."""
        if ai and ai.success:
            title = f"{ai.severity.upper()}: {ai.threat_type} from {fv.src_ip}"
            summary = ai.explanation
            severity = ai.severity
            threat_type = ai.threat_type
        else:
            threat_type = dr.guessed_threat_type or "anomaly"
            severity = _severity_from_risk(dr.combined_risk)
            title = f"{severity.upper()}: {threat_type} from {fv.src_ip}"
            
            summary = (
                f"Rule score: {dr.rule_score:.2f}, ML score: {dr.ml_score:.2f}, "
                f"Combined: {dr.combined_risk:.2f}. Decision: {dr.decision}. "
                f"Rule hits: {list(dr.rule_hits.keys())}"
            )
            
            # --- Hardening: Add privilege warning ---
            from app.blocking.firewall import is_blocking_enabled
            if not is_blocking_enabled() and dr.decision == "block":
                summary = (
                    "⚠ BLOCKING FAILED (No Admin Privileges)\n"
                    f"{summary}\n\n"
                    "Please restart NetScan as Administrator to enable automatic IP blocking."
                )

        # ── Deduplication ──────────────────────────────────────────────────
        # If an open/acknowledged alert for the same (src_ip, threat_type)
        # exists within the cooldown window, bump it instead of creating a new row.
        from datetime import timedelta
        cutoff = utcnow() - timedelta(seconds=self.DEDUP_COOLDOWN)
        existing = (
            session.query(Alert)
            .filter(
                Alert.src_ip == fv.src_ip,
                Alert.threat_type == threat_type,
                Alert.status.in_(["open", "acknowledged"]),
                Alert.created_at >= cutoff,
            )
            .order_by(Alert.created_at.desc())
            .first()
        )
        if existing is not None:
            existing.hit_count = (existing.hit_count or 1) + 1
            existing.last_hit_at = utcnow()
            existing.detection_id = detection_id  # point to latest detection
            if ai_assessment_id:
                existing.ai_assessment_id = ai_assessment_id
            # Escalate severity if the new detection is worse
            sev_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            if sev_order.get(severity, 0) > sev_order.get(existing.severity, 0):
                existing.severity = severity
                existing.title = title
                existing.summary = summary
            session.flush()
            logger.debug(
                "ALERT dedup: bumped #%d for %s/%s (hit_count=%d)",
                existing.id, fv.src_ip, threat_type, existing.hit_count,
            )
            return existing

        # ── New alert ──────────────────────────────────────────────────────
        alert = Alert(
            detection_id=detection_id,
            ai_assessment_id=ai_assessment_id,
            src_ip=fv.src_ip,
            window_start=fv.window_start,
            window_end=fv.window_end,
            title=title,
            summary=summary,
            severity=severity,
            threat_type=threat_type,
            status="open",
            created_at=utcnow(),
            hit_count=1,
            last_hit_at=utcnow(),
        )
        session.add(alert)
        session.flush()
        logger.info("ALERT created: %s", title)
        return alert


def _severity_from_risk(risk: float) -> str:
    if risk >= 0.9:
        return "critical"
    if risk >= 0.75:
        return "high"
    if risk >= 0.55:
        return "medium"
    return "low"
