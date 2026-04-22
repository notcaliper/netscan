from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.features.feature_types import FeatureVector


@dataclass(frozen=True)
class RuleResult:
    score: float
    hits: dict[str, Any]
    guessed_threat_type: str | None
    correlation_hits: dict[str, Any] = field(default_factory=dict)


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string — high values indicate random / DGA-like labels."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((cnt / n) * math.log2(cnt / n) for cnt in freq.values())


class RulesEngine:
    def __init__(self, rules_path: str | Path = "config/rules.yaml"):
        self.rules_path = Path(rules_path)
        _raw = yaml.safe_load(self.rules_path.read_text(encoding="utf-8"))
        self._rules: dict[str, Any] = _raw.get("rules", {})
        self._correlation: dict[str, Any] = _raw.get("correlation_rules", {})

    def evaluate(self, fv: FeatureVector) -> RuleResult:

        hits: dict[str, Any] = {}
        total_score = 0.0
        guessed: str | None = None

        observed_ports = set((fv.extra.get("observed_dst_ports") or []))
        observed_domains = [d.lower() for d in (fv.extra.get("observed_domains") or [])]

        # ── VPN UDP ports ──────────────────────────────────────────────────
        vpn_udp = self._rules.get("vpn_ports_udp", {})
        if vpn_udp.get("enabled"):
            vpn_ports = set(vpn_udp.get("ports") or [])
            matched = observed_ports & vpn_ports
            if fv.udp_flow_count > 0 and matched:
                hits["vpn_ports_udp"] = {
                    "matched_ports": sorted(matched),
                    "description": vpn_udp.get("description", ""),
                    "score": float(vpn_udp.get("score", 0.0)),
                }
                total_score += float(vpn_udp.get("score", 0.0))
                guessed = guessed or "vpn_usage"

        # ── Tor Directory Ports ──────────────────────────────────────────
        tor_dir = self._rules.get("tor_directory_ports", {})
        if tor_dir.get("enabled"):
            tor_ports = set(tor_dir.get("ports") or [])
            matched = observed_ports & tor_ports
            if matched:
                hits["tor_directory_ports"] = {
                    "matched_ports": sorted(matched),
                    "description": tor_dir.get("description", ""),
                    "score": float(tor_dir.get("score", 0.0)),
                }
                total_score += float(tor_dir.get("score", 0.0))
                guessed = guessed or "vpn_usage"

        # ── VPN TCP ports ──────────────────────────────────────────────────
        vpn_tcp = self._rules.get("vpn_ports_tcp", {})
        if vpn_tcp.get("enabled"):
            vpn_tcp_ports = set(vpn_tcp.get("ports") or [])
            matched = observed_ports & vpn_tcp_ports
            if fv.tcp_flow_count > 0 and matched:
                # Port 443 alone is not enough — require a second signal
                if matched == {443} and fv.ratio_known_vpn_ips < 0.3:
                    pass  # skip: plain HTTPS, no VPN ASN signal
                else:
                    hits["vpn_ports_tcp"] = {
                        "matched_ports": sorted(matched),
                        "description": vpn_tcp.get("description", ""),
                        "score": float(vpn_tcp.get("score", 0.0)),
                    }
                    total_score += float(vpn_tcp.get("score", 0.0))
                    guessed = guessed or "vpn_usage"

        # ── Torrent TCP ports ──────────────────────────────────────────────
        torrent_tcp = self._rules.get("torrent_ports_tcp", {})
        if torrent_tcp.get("enabled"):
            torrent_ports = set(torrent_tcp.get("ports") or [])
            matched = observed_ports & torrent_ports
            if fv.tcp_flow_count > 0 and matched:
                hits["torrent_ports_tcp"] = {
                    "matched_ports": sorted(matched),
                    "description": torrent_tcp.get("description", ""),
                    "score": float(torrent_tcp.get("score", 0.0)),
                }
                total_score += float(torrent_tcp.get("score", 0.0))
                guessed = guessed or "pirated_content"

        # ── Torrent UDP ports (DHT / μTP) ──────────────────────────────────
        torrent_udp = self._rules.get("torrent_ports_udp", {})
        if torrent_udp.get("enabled"):
            t_udp_ports = set(torrent_udp.get("ports") or [])
            matched = observed_ports & t_udp_ports
            if fv.udp_flow_count > 0 and matched:
                hits["torrent_ports_udp"] = {
                    "matched_ports": sorted(matched),
                    "description": torrent_udp.get("description", ""),
                    "score": float(torrent_udp.get("score", 0.0)),
                }
                total_score += float(torrent_udp.get("score", 0.0))
                guessed = guessed or "pirated_content"

        # ── Domain keyword matching ────────────────────────────────────────
        keywords_rule = self._rules.get("restricted_domain_keywords", {})
        if keywords_rule.get("enabled") and observed_domains:
            keyword_groups: dict[str, list[str]] = keywords_rule.get("keywords") or {}
            scores: dict[str, float] = keywords_rule.get("score") or {}
            for category, keywords in keyword_groups.items():
                matched_kw = sorted({k for k in keywords if any(k in d for d in observed_domains)})
                if matched_kw:
                    score = float(scores.get(category, 0.0))
                    hits[f"restricted_domain_keywords.{category}"] = {
                        "matched_keywords": matched_kw,
                        "description": keywords_rule.get("description", ""),
                        "score": score,
                    }
                    total_score += score
                    if category == "gambling":
                        guessed = "gambling_access"
                    elif category == "piracy":
                        guessed = "pirated_content"
                    elif category == "vpn_proxy":
                        guessed = guessed or "vpn_usage"

        # ── Tor discovery / bridge keywords ──────────────────────────────────
        tor_kw_rule = self._rules.get("tor_keywords", {})
        if tor_kw_rule.get("enabled") and observed_domains:
            tor_kws = tor_kw_rule.get("keywords") or []
            matched_tor = sorted({k for k in tor_kws if any(k in d for d in observed_domains)})
            if matched_tor:
                score = float(tor_kw_rule.get("score", 0.0))
                hits["tor_keywords"] = {
                    "matched_keywords": matched_tor,
                    "description": tor_kw_rule.get("description", ""),
                    "score": score,
                }
                total_score += score
                guessed = guessed or "vpn_usage"

        # ── ASN Infrastructure Intelligence ──────────────────────────────────
        asn_rule = self._rules.get("vpn_hosting_asn", {})
        if asn_rule.get("enabled"):
            observed_asn = fv.extra.get("asn")
            known_asns = set(asn_rule.get("known_asns") or [])
            if observed_asn and str(observed_asn).upper() in known_asns:
                score = float(asn_rule.get("score", 0.0))
                hits["vpn_hosting_asn"] = {
                    "asn": observed_asn,
                    "description": asn_rule.get("description", ""),
                    "score": score,
                }
                total_score += score

        # ── High fanout (many unique destinations) ─────────────────────────
        fanout = self._rules.get("high_fanout_connections", {})
        if fanout.get("enabled"):
            thr = int(fanout.get("unique_dst_ip_threshold") or 0)
            if thr > 0 and fv.num_unique_dst_ips >= thr:
                score = float(fanout.get("score", 0.0))
                hits["high_fanout_connections"] = {
                    "unique_dst_ips": fv.num_unique_dst_ips,
                    "threshold": thr,
                    "description": fanout.get("description", ""),
                    "score": score,
                }
                total_score += score

        # ── High DNS query burst ───────────────────────────────────────────
        dns_burst = self._rules.get("high_dns_query_burst", {})
        if dns_burst.get("enabled"):
            thr = int(dns_burst.get("dns_query_threshold") or 0)
            if thr > 0 and fv.dns_query_count >= thr:
                score = float(dns_burst.get("score", 0.0))
                hits["high_dns_query_burst"] = {
                    "dns_query_count": fv.dns_query_count,
                    "threshold": thr,
                    "description": dns_burst.get("description", ""),
                    "score": score,
                }
                total_score += score

        # ── High UDP data volume (VPN tunnel heuristic) ────────────────────
        udp_vol = self._rules.get("high_udp_data_volume", {})
        if udp_vol.get("enabled"):
            thr = int(udp_vol.get("udp_bytes_threshold") or 0)
            udp_bytes = fv.extra.get("udp_bytes_sent", 0) or 0
            if thr > 0 and udp_bytes >= thr:
                score = float(udp_vol.get("score", 0.0))
                hits["high_udp_data_volume"] = {
                    "udp_bytes": udp_bytes,
                    "threshold": thr,
                    "description": udp_vol.get("description", ""),
                    "score": score,
                }
                total_score += score
                guessed = guessed or "vpn_usage"

        # ── Near-uniform packet sizes (encrypted tunnel fingerprint) ───────
        pkt_var = self._rules.get("low_packet_size_variance", {})
        if pkt_var.get("enabled"):
            max_std = float(pkt_var.get("max_std_packet_size") or 999)
            min_pkts = int(pkt_var.get("min_packets") or 0)
            if (
                fv.num_packets >= min_pkts
                and fv.std_packet_size <= max_std
                and fv.avg_packet_size > 900  # large, uniform packets = tunnel
            ):
                score = float(pkt_var.get("score", 0.0))
                hits["low_packet_size_variance"] = {
                    "std_packet_size": fv.std_packet_size,
                    "avg_packet_size": fv.avg_packet_size,
                    "num_packets": fv.num_packets,
                    "description": pkt_var.get("description", ""),
                    "score": score,
                }
                total_score += score
                guessed = guessed or "vpn_usage"

        # ── Tor Fixed-Size Cell Pattern ──────────────────────────────────────
        tor_cell = self._rules.get("tor_fixed_cell_pattern", {})
        if tor_cell.get("enabled"):
            min_pkts = int(tor_cell.get("min_packets") or 0)
            avg_min = float(tor_cell.get("avg_packet_size_min") or 0)
            avg_max = float(tor_cell.get("avg_packet_size_max") or 9999)
            max_std = float(tor_cell.get("std_packet_size_max") or 999)
            
            if (fv.num_packets >= min_pkts 
                and avg_min <= fv.avg_packet_size <= avg_max
                and fv.std_packet_size <= max_std):
                
                score = float(tor_cell.get("score", 0.0))
                hits["tor_fixed_cell_pattern"] = {
                    "avg_packet_size": round(fv.avg_packet_size, 2),
                    "std_packet_size": round(fv.std_packet_size, 2),
                    "description": tor_cell.get("description", ""),
                    "score": score,
                }
                total_score += score
                guessed = guessed or "vpn_usage"

        # ── Encrypted Tunnel Pattern (all conditions must fire together) ───────
        tunnel = self._rules.get("vpn_encrypted_tunnel_pattern", {})
        if tunnel.get("enabled"):
            dur = float(fv.extra.get("duration_sec", 0) or 0)
            udp_ratio = fv.udp_flow_count / max(fv.num_flows, 1)
            if (
                dur >= float(tunnel.get("min_duration_sec", 999))
                and fv.num_packets >= int(tunnel.get("min_packets", 999))
                and fv.avg_packet_size >= float(tunnel.get("avg_packet_size_min", 9999))
                and fv.std_packet_size <= float(tunnel.get("std_packet_size_max", 0))
                and udp_ratio >= float(tunnel.get("udp_ratio_min", 1.0))
            ):
                score = float(tunnel.get("score", 0.0))
                hits["vpn_encrypted_tunnel_pattern"] = {
                    "duration_sec": dur, "num_packets": fv.num_packets,
                    "avg_packet_size": fv.avg_packet_size,
                    "std_packet_size": fv.std_packet_size,
                    "udp_ratio": round(udp_ratio, 3),
                    "description": tunnel.get("description", ""), "score": score,
                }
                total_score += score
                guessed = guessed or "vpn_usage"

        # ── P2P Peer Swarm (bidirectional multi-peer) ─────────────────────────
        swarm = self._rules.get("p2p_peer_swarm", {})
        if swarm.get("enabled"):
            bidir_ips = fv.extra.get("bidirectional_ips") or []
            unique_peers = fv.num_unique_dst_ips
            bidir_ratio = len(bidir_ips) / max(unique_peers, 1)
            if (unique_peers >= int(swarm.get("min_unique_peers", 999))
                    and bidir_ratio >= float(swarm.get("min_bidirectional_ratio", 1.0))):
                score = float(swarm.get("score", 0.0))
                hits["p2p_peer_swarm"] = {
                    "unique_peers": unique_peers, "bidirectional_peers": len(bidir_ips),
                    "bidir_ratio": round(bidir_ratio, 3),
                    "description": swarm.get("description", ""), "score": score,
                }
                total_score += score
                guessed = "pirated_content"

        # ── Torrent Tracker Behavior ───────────────────────────────────────────
        tracker_rule = self._rules.get("torrent_tracker_behavior", {})
        if tracker_rule.get("enabled") and observed_domains:
            tracker_kws = tracker_rule.get("tracker_keywords") or []
            tracker_matches = [d for d in observed_domains if any(k in d for k in tracker_kws)]
            if len(tracker_matches) >= int(tracker_rule.get("min_tracker_hits", 1)):
                score = float(tracker_rule.get("score", 0.0))
                hits["torrent_tracker_behavior"] = {
                    "matched_domains": tracker_matches[:10],
                    "description": tracker_rule.get("description", ""), "score": score,
                }
                total_score += score
                guessed = guessed or "pirated_content"

        # ── High Entropy Domains (DGA / DNS tunneling) ─────────────────────────
        entropy_rule = self._rules.get("high_entropy_domains", {})
        if entropy_rule.get("enabled") and observed_domains:
            min_ent = float(entropy_rule.get("min_entropy", 3.5))
            min_len = int(entropy_rule.get("min_length", 12))
            high_ent = []
            for domain in observed_domains:
                for label in domain.split("."):
                    if len(label) >= min_len and _shannon_entropy(label) >= min_ent:
                        high_ent.append(domain)
                        break
            if len(high_ent) >= int(entropy_rule.get("min_matches", 2)):
                score = float(entropy_rule.get("score", 0.0))
                hits["high_entropy_domains"] = {
                    "matched_domains": high_ent[:5], "count": len(high_ent),
                    "description": entropy_rule.get("description", ""), "score": score,
                }
                total_score += score

        # ── Fast Flux Detection ────────────────────────────────────────────────
        flux_rule = self._rules.get("fast_flux_detection", {})
        if flux_rule.get("enabled"):
            dns_results: list[dict] = fv.extra.get("dns_intel_results") or []
            domain_to_ips: dict[str, set] = {}
            for r in dns_results:
                d = r.get("domain", "")
                ip_addr = r.get("resolved_ip")
                if d and ip_addr:
                    domain_to_ips.setdefault(d, set()).add(ip_addr)
            flux_thr = int(flux_rule.get("ip_changes_threshold", 4))
            flux_domains = {d: list(ips) for d, ips in domain_to_ips.items() if len(ips) >= flux_thr}
            if flux_domains:
                score = float(flux_rule.get("score", 0.0))
                hits["fast_flux_detection"] = {
                    "domains": {k: v[:5] for k, v in list(flux_domains.items())[:3]},
                    "description": flux_rule.get("description", ""), "score": score,
                }
                total_score += score

        # ── Port Randomization (UDP port hopping) ─────────────────────────────
        rand_port = self._rules.get("random_port_usage", {})
        if rand_port.get("enabled") and rand_port.get("protocol", "udp") == "udp":
            udp_dominant = fv.udp_flow_count > fv.tcp_flow_count
            if udp_dominant and fv.distinct_dst_ports >= int(rand_port.get("min_distinct_ports", 12)):
                score = float(rand_port.get("score", 0.0))
                hits["random_port_usage"] = {
                    "distinct_ports": fv.distinct_dst_ports,
                    "description": rand_port.get("description", ""), "score": score,
                }
                total_score += score
                guessed = guessed or "vpn_usage"

        # ── Constant Bandwidth Pattern (tunnel heartbeat) ──────────────────────
        cbw = self._rules.get("constant_bandwidth_pattern", {})
        if cbw.get("enabled"):
            iat_cv = (fv.std_inter_packet_time / fv.avg_inter_packet_time
                      if fv.avg_inter_packet_time > 0 else 999.0)
            if (fv.num_packets >= int(cbw.get("min_packets", 60))
                    and iat_cv <= float(cbw.get("max_iat_cv", 0.25))):
                score = float(cbw.get("score", 0.0))
                hits["constant_bandwidth_pattern"] = {
                    "iat_cv": round(iat_cv, 4), "avg_iat": fv.avg_inter_packet_time,
                    "num_packets": fv.num_packets,
                    "description": cbw.get("description", ""), "score": score,
                }
                total_score += score
                guessed = guessed or "vpn_usage"

        # ── CORRELATION ENGINE ─────────────────────────────────────────────────
        # Runs after all individual rules so hits{} is fully populated.
        correlation_hits: dict[str, Any] = {}
        for corr_name, corr_cfg in self._correlation.items():
            conditions = corr_cfg.get("conditions") or []
            matched_conditions = [c for c in conditions if c in hits]
            if len(matched_conditions) >= int(corr_cfg.get("min_matches", 2)):
                corr_score = float(corr_cfg.get("score", 0.0))
                correlation_hits[corr_name] = {
                    "matched_conditions": matched_conditions,
                    "score": corr_score,
                    "action": corr_cfg.get("action", "block"),
                    "description": corr_cfg.get("description", ""),
                }
                # Correlation always wins if higher — prevents evasion by
                # spreading signals across rules with individually low scores
                total_score = max(total_score, corr_score)
                if "torrent" in corr_name:
                    guessed = "pirated_content"
                elif "vpn" in corr_name or "stealth" in corr_name:
                    guessed = "vpn_usage"
                elif "dns" in corr_name:
                    guessed = guessed or "dns_tunnel"

        total_score = min(1.0, total_score)
        return RuleResult(
            score=total_score,
            hits=hits,
            guessed_threat_type=guessed,
            correlation_hits=correlation_hits,
        )
