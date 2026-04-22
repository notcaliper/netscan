"""Centralized pipeline logic for processing captured packet windows."""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.capture.capture_runner import CaptureOutput
from app.db.models import Detection, Device, NetworkFeature
from app.features.feature_types import FeatureVector
from app.detection.hybrid_detector import HybridDetector
from app.features.feature_extractor import FeatureExtractor
from app.ai_reasoner.ai_decision_logic import AIDecisionLogic
from app.alerts.alert_manager import AlertManager
from app.alerts.notifier import Notifier
from app.detection.dns_intelligence import DNSIntelligenceModule
from app.blocking.firewall import block_ip, block_ips, block_doh
from app.blocking.domain_blocker import block_domain, block_domains
from app.utils.ip_utils import is_monitor_only_ip, is_safe_to_block_threat
from app.utils.time_utils import utcnow

logger = logging.getLogger("netscan.pipeline")

class ProcessingPipeline:
    def __init__(self, window_seconds: int):
        self.dns_intel = DNSIntelligenceModule()
        self.extractor = FeatureExtractor(window_seconds, dns_intel=self.dns_intel)
        self.detector = HybridDetector()
        self.ai_logic = AIDecisionLogic()
        self.alert_mgr = AlertManager()
        self.notifier = Notifier()

    def process_window(self, session: Session, capture_out: CaptureOutput) -> dict[str, Any]:
        """
        Process a single window of captured packets:
        1. Extract Features
        2. DNS Intelligence Analysis & Alerting
        3. ML/Rules Detection
        4. Alert Creation & Notification
        5. Device Persistence
        """
        window_packets = len(capture_out.packets)
        window_bytes = sum(p.length_bytes for p in capture_out.packets)

        # 1. Feature Extraction
        fvs = self.extractor.extract(
            capture_out.packets,
            capture_out.window_start_ts,
            capture_out.window_end_ts,
        )

        # 2. DNS Intelligence Analysis
        unique_queries = set()
        for p in capture_out.packets:
            if p.dns_query:
                unique_queries.add((p.src_ip, p.dns_query))
        
        dns_alerts = 0
        for src_ip, domain in unique_queries:
            # Skip DNS response packets where src_ip is a known resolver (1.1.1.1, 8.8.8.8, etc.)
            # These are upstream servers responding to queries, not devices on the network.
            if is_monitor_only_ip(src_ip):
                continue
            try:
                dns_result = self.dns_intel.analyze_query(src_ip, domain)
                if dns_result["category"] != "normal":
                    alert_title = f"Restricted DNS Activity: {dns_result['category'].upper()}"
                    alert_summary = (
                        f"Device {src_ip} queried restricted domain: {domain}. "
                        f"Resolved IP: {dns_result['resolved_ip']}. Reason: {dns_result['reason']}"
                    )
                    risk_sev = "high" if dns_result["risk_score"] > 0.7 else "medium"
                    self.notifier.notify(alert_title, alert_summary, risk_sev)
                    logger.warning("DNS INTEL ALERT: %s - %s", alert_title, alert_summary)
                    dns_alerts += 1
                    
                    if risk_sev == "high":
                        # Block source device (skipped by guard if it's a LAN IP)
                        block_ip(src_ip, f"DNS IPS: {alert_title}", session=session)
                        # Block the resolved IP using threat-aware check
                        # (allows Cloudflare/CDN IPs for gambling/piracy categories)
                        bad_ip = dns_result.get("resolved_ip")
                        category = dns_result.get("category", "")
                        threat_map = {
                            "gambling": "gambling_access",
                            "piracy": "pirated_content",
                            "vpn": "vpn_usage",
                            "tor": "tor_usage",
                        }
                        threat_type = threat_map.get(category.lower())
                        if bad_ip and bad_ip != "0.0.0.0":
                            if is_safe_to_block_threat(bad_ip, threat_type):
                                block_ip(bad_ip, f"DNS IPS (Destination): {alert_title}",
                                         threat_type=threat_type, session=session)
                            else:
                                logger.info(
                                    "DNS IPS: resolved IP %s protected (CDN infrastructure) — "
                                    "domain block applied instead.", bad_ip
                                )
                        # Always block the domain in /etc/hosts AND via nftables redirect
                        block_domain(domain, reason=f"DNS IPS [{dns_result['category']}]: {dns_result['reason']}")
            except Exception as e:
                logger.error("Error in DNS intelligence analysis for %s: %s", domain, e)

        # 3. Detection & Persistence
        alerts_created = 0
        active_ips = []

        # Filter out feature vectors where src_ip is a DNS resolver.
        # DNS response packets have the resolver (1.1.1.1, 8.8.8.8) as src_ip;
        # these are not network devices and produce constant false positives.
        fvs = [fv for fv in fvs if not is_monitor_only_ip(fv.src_ip)]

        for fv in fvs:
            active_ips.append(fv.src_ip)

            # Persist Feature
            nf = self.alert_mgr.persist_feature(session, fv)
            
            # Run Detection (pass session for risk boosting)
            dr = self.detector.detect(fv, session=session)
            
            # Persist Detection Result
            det = self.alert_mgr.persist_detection(session, fv, dr, nf.id)

            if dr.decision == "allow":
                logger.debug(
                    "  %s → risk=%.2f (allow) rule=%.2f ml=%.2f conf=%.2f",
                    fv.src_ip, dr.combined_risk, dr.rule_score, dr.ml_score, dr.ml_confidence,
                )
            else:
                boost_tag = " [BOOSTED]" if dr.boosted else ""
                top = ", ".join(f"{n}={v:.2f}" for n, v in dr.top_features[:2])
                corr = list(dr.correlation_hits.keys())
                logger.warning(
                    "  ⚠ %s → risk=%.2f (%s) rule=%.2f ml=%.2f conf=%.2f%s %s%s%s",
                    fv.src_ip, dr.combined_risk, dr.decision,
                    dr.rule_score, dr.ml_score, dr.ml_confidence, boost_tag,
                    f"[{dr.guessed_threat_type}] " if dr.guessed_threat_type else "",
                    f"corr={corr} " if corr else "",
                    f"top={top}" if top else "",
                )

            # AI Review Escalation
            ai_result = None
            ai_id = None
            if self.ai_logic.should_escalate(dr):
                ai_result = self.ai_logic.assess_sync(fv, dr)
                ai_obj = self.alert_mgr.persist_ai_assessment(session, det.id, ai_result)
                ai_id = ai_obj.id

            # Create Alert if suspicious
            if dr.decision != "allow":
                alert = self.alert_mgr.create_alert(
                    session, fv, dr, det.id,
                    ai=ai_result, ai_assessment_id=ai_id,
                )
                self.notifier.notify(alert.title, alert.summary, alert.severity)
                alerts_created += 1
                
                if alert.severity in ("high", "critical"):
                    from app.utils.ip_utils import is_safe_to_block, is_private_ip

                    # 1. Attempt to block the source device (skipped for private/LAN IPs)
                    if is_private_ip(fv.src_ip):
                        logger.info(
                            "IPS: %s is a LAN device — blocking destinations and domains instead.",
                            fv.src_ip,
                        )
                    else:
                        block_ip(fv.src_ip, f"ML IPS: {alert.title}",
                                 threat_type=dr.guessed_threat_type,
                                 risk_score=dr.combined_risk, session=session)

                    # 2. Block destination IPs using threat-aware CDN check
                    dst_ips = fv.extra.get("observed_dst_ips") or []
                    blockable = [ip for ip in dst_ips
                                 if is_safe_to_block_threat(ip, dr.guessed_threat_type)]
                    if blockable:
                        label = (
                            "VPN IPS (Gateways)" if dr.guessed_threat_type in ("vpn_usage", "tor_usage")
                            else "IPS (Destinations)"
                        )
                        logger.info(
                            "Blocking %d destination IPs for %s [%s]: %s",
                            len(blockable), fv.src_ip, dr.guessed_threat_type, blockable[:5],
                        )
                        block_ips(blockable, f"{label}: {alert.title}",
                                  threat_type=dr.guessed_threat_type,
                                  risk_score=dr.combined_risk, session=session)

                    # 3. Domain-level blocking via hosts file for gambling/piracy/vpn.
                    #    Combined with DoH interception so browsers can't bypass /etc/hosts.
                    if dr.guessed_threat_type in ("gambling_access", "pirated_content", "vpn_usage", "tor_usage"):
                        observed_domains = fv.extra.get("observed_domains") or []
                        if observed_domains:
                            n = block_domains(
                                observed_domains,
                                reason=f"ML IPS [{dr.guessed_threat_type}]: {alert.title}",
                            )
                            if n:
                                logger.warning(
                                    "🚫 DOMAIN BLOCK — %d domains blocked in hosts file for %s",
                                    n, fv.src_ip,
                                )
                        # Block DoH so browsers fall back to system DNS (where /etc/hosts applies)
                        block_doh()

            # Update Device table
            device = session.query(Device).filter(Device.ip_address == fv.src_ip).first()
            if device:
                device.last_seen = utcnow()
            else:
                session.add(Device(ip_address=fv.src_ip, last_seen=utcnow()))

        return {
            "packets": window_packets,
            "bytes": window_bytes,
            "fvs_count": len(fvs),
            "alerts_count": alerts_created + dns_alerts,
            "active_ips": active_ips,
        }

    def run_batch_detection(self, session: Session, limit: int = 100) -> int:
        """Process unprocessed NetworkFeature rows."""
        unprocessed = (
            session.query(NetworkFeature)
            .outerjoin(Detection, NetworkFeature.id == Detection.feature_id)
            .filter(Detection.id == None)
            .order_by(desc(NetworkFeature.window_start))
            .limit(limit)
            .all()
        )
        
        if not unprocessed:
            return 0
            
        logger.info("Found %d unprocessed features. Starting catch-up batch.", len(unprocessed))
        processed = 0
        for nf in unprocessed:
            fv = FeatureVector(
                src_ip=nf.src_ip,
                window_start=nf.window_start,
                duration=nf.duration,
                num_packets=nf.num_packets,
                num_flows=nf.num_flows,
                total_bytes_sent=nf.total_bytes_sent,
                total_bytes_received=nf.total_bytes_received,
                num_unique_dst_ips=nf.num_unique_dst_ips,
                tcp_flow_count=nf.tcp_flow_count,
                udp_flow_count=nf.udp_flow_count,
                dns_query_count=nf.dns_query_count,
                distinct_dst_ports=nf.distinct_dst_ports,
                top_port=nf.top_port,
                ratio_known_vpn_ips=nf.ratio_known_vpn_ips,
                ratio_known_restricted_domains=nf.ratio_known_restricted_domains,
                extra=nf.extra or {},
            )
            
            dr = self.detector.detect(fv)
            det = self.alert_mgr.persist_detection(session, fv, dr, nf.id)
            
            ai_result = None
            ai_id = None
            if self.ai_logic.should_escalate(dr):
                ai_result = self.ai_logic.assess_sync(fv, dr)
                ai_obj = self.alert_mgr.persist_ai_assessment(session, det.id, ai_result)
                ai_id = ai_obj.id

            if dr.decision != "allow":
                alert = self.alert_mgr.create_alert(session, fv, dr, det.id, ai=ai_result, ai_assessment_id=ai_id)
                self.notifier.notify(alert.title, alert.summary, alert.severity)
                
                if alert.severity in ("high", "critical"):
                    from app.utils.ip_utils import is_safe_to_block, is_private_ip

                    if not is_private_ip(fv.src_ip):
                        block_ip(fv.src_ip, f"Batch ML IPS: {alert.title}", threat_type=dr.guessed_threat_type, risk_score=dr.combined_risk, session=session)

                    dst_ips = fv.extra.get("observed_dst_ips") or []
                    blockable = [ip for ip in dst_ips if is_safe_to_block(ip)]
                    if blockable:
                        label = (
                            "Batch VPN IPS" if dr.guessed_threat_type in ("vpn_usage", "tor_usage")
                            else "Batch IPS (Destinations)"
                        )
                        block_ips(blockable, f"{label}: {alert.title}", threat_type=dr.guessed_threat_type, risk_score=dr.combined_risk, session=session)

                    # Domain-level hosts file blocking for gambling/piracy/vpn
                    if dr.guessed_threat_type in ("gambling_access", "pirated_content", "vpn_usage", "tor_usage"):
                        observed_domains = fv.extra.get("observed_domains") or []
                        if observed_domains:
                            n = block_domains(
                                observed_domains,
                                reason=f"Batch IPS [{dr.guessed_threat_type}]: {alert.title}",
                            )
                            if n:
                                logger.warning(
                                    "🚫 DOMAIN BLOCK — %d domains blocked in hosts file for %s",
                                    n, fv.src_ip,
                                )

            processed += 1
        
        return processed
