from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np

from app.config import load_config
from app.features.feature_types import FeatureVector

logger = logging.getLogger("netscan.ml")

# Stable feature name list — must stay in sync with FeatureVector.to_numeric_vector()
FEATURE_NAMES = [
    "num_packets", "num_flows", "num_unique_dst_ips", "num_unique_domains",
    "total_bytes_sent", "total_bytes_received",
    "avg_packet_size", "std_packet_size",
    "avg_inter_packet_time", "std_inter_packet_time",
    "tcp_flow_count", "udp_flow_count", "dns_query_count",
    "distinct_dst_ports", "top_port",
    "ratio_known_vpn_ips", "ratio_known_restricted_domains",
]


@dataclass
class MLResult:
    score: float                          # 0..1, higher = more anomalous
    confidence: float                     # 0..1, how certain the model is
    model_used: str
    top_features: list[tuple[str, float]] = field(default_factory=list)
    drift_detected: bool = False


def _sigmoid(x: float) -> float:
    """Map a raw score to (0, 1) via sigmoid — avoids hard clipping artefacts."""
    try:
        return 1.0 / (1.0 + math.exp(-x))
    except OverflowError:
        return 0.0 if x < 0 else 1.0


class MLModel:
    """
    Ensemble anomaly detector: IsolationForest (primary) + LocalOutlierFactor (secondary).

    Scoring:
        ensemble_raw = 0.60 × iso_raw + 0.40 × lof_raw
        anomaly_score (0–1) = clamp(normalise(ensemble_raw))
        confidence           = sigmoid(|margin from decision boundary|)

    Falls back to a 3-factor heuristic when no trained models exist.
    """

    # Normalisation constants for IsolationForest score_samples output.
    # Typical range is [-0.8, +0.2]; adjust if your baseline shifts.
    _ISO_MIN = -0.8
    _ISO_MAX =  0.2

    def __init__(self):
        self.cfg = load_config().raw
        ml_cfg = self.cfg.get("ml", {})
        self.enabled = bool(ml_cfg.get("enabled", True))
        self.model_path = Path(ml_cfg.get("model_path", "./models/isolation_forest.pkl"))
        self._iso: Optional[object] = None
        self._lof: Optional[object] = None
        self._scaler: Optional[object] = None
        self._loaded = False
        # Rolling baseline for drift detection (updated on each score call)
        self._recent_raws: list[float] = []
        self._baseline_mean: Optional[float] = None

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def _try_load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if not self.enabled or not self.model_path.exists():
            return
        try:
            import joblib  # type: ignore
            bundle = joblib.load(self.model_path)
            # Support both old single-model pkl and new dict bundle
            if isinstance(bundle, dict):
                self._iso    = bundle.get("iso")
                self._lof    = bundle.get("lof")
                self._scaler = bundle.get("scaler")
            else:
                # Legacy: plain IsolationForest
                self._iso = bundle
            logger.info("ML model loaded from %s (lof=%s)", self.model_path, self._lof is not None)
        except Exception as exc:
            logger.warning("Failed to load ML model: %s", exc)
            self._iso = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def score(self, fv: FeatureVector) -> MLResult:
        self._try_load()
        if not self.enabled:
            return MLResult(score=0.0, confidence=0.0, model_used="disabled")

        vec = fv.to_numeric_vector()
        x_raw = np.array([vec], dtype=float)

        # Apply scaler if available (from training bundle)
        if self._scaler is not None:
            try:
                x = self._scaler.transform(x_raw)
            except Exception:
                x = x_raw
        else:
            x = x_raw

        if self._iso is not None:
            return self._ensemble_score(x, vec)

        return self._heuristic_score(fv)

    def check_drift(self, new_score: float) -> bool:
        """
        Returns True if recent anomaly scores have drifted significantly from
        the established baseline — indicates the network behaviour has changed
        and the model may need retraining.
        """
        self._recent_raws.append(new_score)
        if len(self._recent_raws) > 200:
            self._recent_raws.pop(0)

        if len(self._recent_raws) < 50:
            return False  # not enough data yet

        recent_mean = float(np.mean(self._recent_raws[-50:]))

        if self._baseline_mean is None:
            self._baseline_mean = float(np.mean(self._recent_raws))
            return False

        drift = abs(recent_mean - self._baseline_mean) > 0.15  # 15% shift
        if drift:
            logger.warning(
                "⚠ ML DRIFT DETECTED — baseline mean=%.3f, recent mean=%.3f. "
                "Consider retraining: python cli.py train",
                self._baseline_mean, recent_mean,
            )
            # Update baseline so we don't spam warnings
            self._baseline_mean = recent_mean
        return drift

    # ------------------------------------------------------------------
    # Internal scoring helpers
    # ------------------------------------------------------------------

    def _ensemble_score(self, x: np.ndarray, raw_vec: list[float]) -> MLResult:
        """Score using IsoForest + optional LOF ensemble."""
        try:
            iso_raw = float(self._iso.score_samples(x)[0])  # type: ignore
            # Normalise to 0..1 (higher = more anomalous)
            iso_norm = float(np.clip(
                (self._ISO_MAX - iso_raw) / (self._ISO_MAX - self._ISO_MIN),
                0.0, 1.0,
            ))

            if self._lof is not None:
                try:
                    lof_raw = float(self._lof.score_samples(x)[0])  # type: ignore
                    # LOF score_samples is also negative-of-LOF score;
                    # same normalisation direction as IsoForest.
                    lof_norm = float(np.clip((0.0 - lof_raw) / 1.5, 0.0, 1.0))
                    combined = 0.60 * iso_norm + 0.40 * lof_norm
                    model_tag = "iso+lof_ensemble"
                except Exception:
                    combined = iso_norm
                    model_tag = "isolation_forest"
            else:
                combined = iso_norm
                model_tag = "isolation_forest"

            # Confidence: distance from 0.5 decision boundary scaled to (0,1)
            confidence = float(np.clip(abs(combined - 0.5) * 2.0, 0.0, 1.0))

            # Top contributing features (deviation from zero in scaled space)
            top_feats = self._top_features(x[0], raw_vec)

            drift = self.check_drift(combined)

            return MLResult(
                score=combined,
                confidence=confidence,
                model_used=model_tag,
                top_features=top_feats,
                drift_detected=drift,
            )
        except Exception as exc:
            logger.debug("Ensemble scoring failed, falling back to heuristic: %s", exc)
            from app.features.feature_types import FeatureVector
            # Re-create a dummy fv-like namespace for the heuristic
            class _FV:
                pass
            fv_dummy = _FV()
            fv_dummy.total_bytes_sent = int(raw_vec[4]) if len(raw_vec) > 4 else 0
            fv_dummy.total_bytes_received = int(raw_vec[5]) if len(raw_vec) > 5 else 0
            fv_dummy.num_unique_dst_ips = int(raw_vec[2]) if len(raw_vec) > 2 else 0
            fv_dummy.distinct_dst_ports = int(raw_vec[13]) if len(raw_vec) > 13 else 0
            return self._heuristic_score(fv_dummy)  # type: ignore

    def _top_features(self, x_scaled: np.ndarray, _raw: list[float]) -> list[tuple[str, float]]:
        """Return the top-3 features by absolute deviation in scaled space."""
        names = FEATURE_NAMES[:len(x_scaled)]
        devs = [(names[i], abs(float(x_scaled[i]))) for i in range(len(names))]
        devs.sort(key=lambda t: t[1], reverse=True)
        return devs[:3]

    def _heuristic_score(self, fv) -> MLResult:
        """3-factor heuristic fallback — used when no trained model is available."""
        bytes_total = float(getattr(fv, "total_bytes_sent", 0) + getattr(fv, "total_bytes_received", 0))
        fanout = float(getattr(fv, "num_unique_dst_ips", 0))
        port_div = float(getattr(fv, "distinct_dst_ports", 0))

        throughput_score = float(np.clip(np.log10(bytes_total + 1) / 8.0, 0.0, 1.0))
        fanout_score = float(np.clip(fanout / 80.0, 0.0, 1.0))
        port_score = float(np.clip(port_div / 25.0, 0.0, 1.0))

        combined = float(np.clip(
            0.45 * throughput_score + 0.40 * fanout_score + 0.15 * port_score,
            0.0, 1.0,
        ))
        return MLResult(
            score=combined,
            confidence=0.3,   # heuristic = low confidence
            model_used="heuristic_v1",
            top_features=[
                ("total_bytes", throughput_score),
                ("num_unique_dst_ips", fanout_score),
                ("distinct_dst_ports", port_score),
            ],
        )