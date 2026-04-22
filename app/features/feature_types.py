from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class FeatureVector(BaseModel):
    window_start: datetime
    window_end: datetime
    src_ip: str
    dst_category: str | None = None

    num_packets: int = 0        # total packets seen in this window
    num_flows: int = 0
    num_unique_dst_ips: int = 0
    num_unique_domains: int = 0

    total_bytes_sent: int = 0
    total_bytes_received: int = 0

    avg_packet_size: float = 0.0
    std_packet_size: float = 0.0
    avg_inter_packet_time: float = 0.0
    std_inter_packet_time: float = 0.0

    tcp_flow_count: int = 0
    udp_flow_count: int = 0
    dns_query_count: int = 0

    distinct_dst_ports: int = 0
    top_port: int | None = None

    ratio_known_vpn_ips: float = 0.0
    ratio_known_restricted_domains: float = 0.0

    extra: dict[str, Any] = Field(default_factory=dict)

    def to_numeric_vector(self) -> list[float]:
        """
        Numeric-only vector for ML. Keep ordering stable — adding fields at the
        END only (or retrain the model).
        """
        return [
            float(self.num_packets),
            float(self.num_flows),
            float(self.num_unique_dst_ips),
            float(self.num_unique_domains),
            float(self.total_bytes_sent),
            float(self.total_bytes_received),
            float(self.avg_packet_size),
            float(self.std_packet_size),
            float(self.avg_inter_packet_time),
            float(self.std_inter_packet_time),
            float(self.tcp_flow_count),
            float(self.udp_flow_count),
            float(self.dns_query_count),
            float(self.distinct_dst_ports),
            float(self.top_port or 0),
            float(self.ratio_known_vpn_ips),
            float(self.ratio_known_restricted_domains),
        ]

