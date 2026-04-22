"""Builds the structured prompt sent to Gemini for AI-assisted detection."""
from __future__ import annotations

from app.features.feature_types import FeatureVector

_SYSTEM_INSTRUCTIONS = """\
You are a cybersecurity assistant analyzing network metadata for a college network.
You must classify potential threats based ONLY on metadata (no payload).
Be conservative and avoid false positives, but do not ignore clear patterns."""

_TASK = """\
Given the network behavior summary below for a single device in a time window,
decide if this activity is:
- VPN usage
- Gambling site access
- Pirated content / torrenting
- Benign normal usage
- Other (specify)

Then respond in **valid JSON only** (no markdown, no extra text) with these keys:
- threat_type: one of ["vpn_usage","gambling_access","pirated_content","benign","other"]
- severity: one of ["low","medium","high","critical"]
- explanation: short explanation (2-4 sentences) in simple language
- recommended_action: short recommendation for a network admin"""

_RESPONSE_FORMAT = """\
{
  "threat_type": "...",
  "severity": "...",
  "explanation": "...",
  "recommended_action": "..."
}"""


def build_analysis_prompt(
    fv: FeatureVector,
    *,
    recent_history: str | None = None,
) -> str:
    """
    Assemble the full prompt for Gemini.

    Parameters
    ----------
    fv : FeatureVector
        Current window's feature snapshot.
    recent_history : str | None
        Optional text summarising recent behaviour of the same device.
    """
    device_block = _feature_block(fv)

    parts = [
        f"SYSTEM INSTRUCTIONS:\n{_SYSTEM_INSTRUCTIONS}",
        f"\nTASK:\n{_TASK}",
        f"\nDEVICE_METADATA:\n{device_block}",
    ]

    if recent_history:
        parts.append(f"\nRECENT_HISTORY:\n{recent_history}")

    parts.append(f"\nRESPONSE FORMAT:\n{_RESPONSE_FORMAT}")

    return "\n".join(parts)


def _feature_block(fv: FeatureVector) -> str:
    lines = [
        f"src_ip: {fv.src_ip}",
        f"time_window: {fv.window_start.isoformat()}Z to {fv.window_end.isoformat()}Z",
        f"num_flows: {fv.num_flows}",
        f"num_unique_dst_ips: {fv.num_unique_dst_ips}",
        f"num_unique_domains: {fv.num_unique_domains}",
        f"total_bytes_sent: {fv.total_bytes_sent}",
        f"total_bytes_received: {fv.total_bytes_received}",
        f"avg_packet_size: {fv.avg_packet_size:.1f}",
        f"std_packet_size: {fv.std_packet_size:.1f}",
        f"avg_inter_packet_time: {fv.avg_inter_packet_time:.4f}",
        f"std_inter_packet_time: {fv.std_inter_packet_time:.4f}",
        f"tcp_flow_count: {fv.tcp_flow_count}",
        f"udp_flow_count: {fv.udp_flow_count}",
        f"dns_query_count: {fv.dns_query_count}",
        f"distinct_dst_ports: {fv.distinct_dst_ports}",
        f"top_port: {fv.top_port}",
        f"ratio_known_vpn_ips: {fv.ratio_known_vpn_ips:.2f}",
        f"ratio_known_restricted_domains: {fv.ratio_known_restricted_domains:.2f}",
    ]

    domains = fv.extra.get("observed_domains", [])
    if domains:
        lines.append(f"observed_domains: {', '.join(domains[:10])}")

    return "\n".join(lines)
