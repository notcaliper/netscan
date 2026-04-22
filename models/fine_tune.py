"""
NetScan — Adaptive Model Fine-Tuner
====================================
Trains / retrains the anomaly detection ensemble:
  - IsolationForest  (primary)
  - LocalOutlierFactor (secondary, novelty=True)

Upgrades vs baseline
---------------------
✔ Risk-aware fitness: FP penalty prevents blocking innocent users
✔ Sample augmentation: 20 noisy variants per archetype
✔ Temporal features: delta_flows, rolling_mean, spike_ratio
✔ Ensemble training: IsoForest + LOF saved in a single bundle
✔ Model versioning: timestamped backups so good models are never lost
✔ Online retraining trigger: auto-retrain when DB has grown significantly
"""

import sys
import os
import datetime
import yaml
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from sqlalchemy import create_engine
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from itertools import product
from joblib import Parallel, delayed

# ── Thread control: prevent contention across cores ───────────────────────
os.environ["OMP_NUM_THREADS"] = "1"
os.environ["MKL_NUM_THREADS"] = "1"
os.environ["OPENBLAS_NUM_THREADS"] = "1"
os.environ["VECLIB_MAXIMUM_THREADS"] = "1"
os.environ["NUMEXPR_NUM_THREADS"] = "1"

if sys.platform != "win32":
    try:
        os.nice(10)   # de-prioritise so capture stays real-time
    except AttributeError:
        pass

# ── Config ─────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
CONFIG_PATH  = BASE_DIR / "ml_config.yaml"

with CONFIG_PATH.open() as f:
    ml_cfg = yaml.safe_load(f)

_raw_out = ml_cfg.get("training", {}).get("output_path", "./models/isolation_forest.pkl")
OUTPUT_PATH  = (PROJECT_ROOT / _raw_out.lstrip("./")).resolve()
VERSIONS_DIR = OUTPUT_PATH.parent / "versions"
VERSIONS_DIR.mkdir(parents=True, exist_ok=True)

FEATURE_COLS = ml_cfg["features"]
MIN_SAMPLES  = ml_cfg.get("training", {}).get("min_samples", 500)
RETRAIN_THRESHOLD = 1000   # retrain if DB grew by this many rows since last train

# ── Validation archetypes ──────────────────────────────────────────────────
# Each row = [num_packets, num_flows, num_unique_dst_ips, num_unique_domains,
#             total_bytes_sent, total_bytes_received, avg_packet_size, std_packet_size,
#             avg_iat, std_iat, tcp_flows, udp_flows, dns_queries,
#             distinct_dst_ports, top_port, ratio_vpn_ips, ratio_restricted_domains]
SAMPLES = {
    "VPN (OpenVPN)":  [500,  45,  3,  1, 8e6,  25e6, 1300, 22, 0.01, 0.002,  0,  45,  1,  1, 1194, 0.9, 0.0],
    "VPN (WireGuard)":[650,  60,  2,  1, 10e6, 30e6, 1100, 18, 0.008,0.001,  0,  60,  0,  1,51820, 0.8, 0.0],
    "Gambling":       [ 80,  80, 15,  6, 1e6,   7e6,  700,300, 0.05, 0.03,  80,   0, 20,  2,  443, 0.0, 0.7],
    "Torrent":        [200, 200, 60,  2, 15e6, 40e6, 1000,300, 0.005,0.003,120,  80,  5, 20, 6881, 0.1, 0.3],
    "Torrent DHT":    [400, 300, 90,  2, 20e6, 50e6,  800,200, 0.003,0.002, 50, 250,  3, 25, 51413,0.05,0.2],
    "Malware C2":     [ 10,  10,  2,  1,  5e3,  1e4,   90, 50, 0.8,  0.5,  10,   0,  5,  1, 8080, 0.0,0.95],
    "Hacking/Scan":   [500, 500,300,250,  2e5,  5e4,   60, 40, 0.001,0.001,500,   0, 10,400,   22, 0.2, 0.8],
    "DNS Tunnel":     [ 30,  30,  5,  1,  1e4,  2e4,  200, 80, 0.3,  0.1,  30,   0, 30,  3,   53, 0.0, 0.3],
    "Normal":         [ 60,  12,  5,  4,  2e5, 1.5e6, 600,250, 0.2,  0.15, 12,   0,  4,  2,  443, 0.0, 0.0],
}

# 1 = normal/benign, -1 = anomaly
EXPECTED_PREDS = {
    "VPN (OpenVPN)":   -1,
    "VPN (WireGuard)": -1,
    "Gambling":        -1,
    "Torrent":         -1,
    "Torrent DHT":     -1,
    "Malware C2":      -1,
    "Hacking/Scan":    -1,
    "DNS Tunnel":      -1,
    "Normal":           1,
}

# ── Sample Augmentation ────────────────────────────────────────────────────

def augment_sample(vec: list[float], noise: float = 0.12, n: int = 20) -> list[list[float]]:
    """Generate *n* noisy variants of *vec* to harden the fitness evaluation."""
    rng = np.random.default_rng(42)
    out = []
    for _ in range(n):
        variant = [max(0.0, v * float(rng.uniform(1 - noise, 1 + noise))) for v in vec]
        out.append(variant)
    return out


# ── Temporal Features ──────────────────────────────────────────────────────

def add_temporal_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Enrich the DataFrame with cross-window temporal features per src_ip.
    Detects spikes and slow-burn attacks invisible to single-window models.
    """
    df = df.sort_values(["src_ip", "window_start"])

    df["delta_flows"]        = df.groupby("src_ip")["num_flows"].diff().fillna(0)
    df["rolling_mean_flows"] = (
        df.groupby("src_ip")["num_flows"]
        .transform(lambda x: x.rolling(3, min_periods=1).mean())
        .fillna(0)
    )
    df["spike_ratio"] = df["num_flows"] / (df["rolling_mean_flows"].clip(lower=1))

    df["delta_bytes"]        = df.groupby("src_ip")["total_bytes_sent"].diff().fillna(0)
    df["rolling_mean_bytes"] = (
        df.groupby("src_ip")["total_bytes_sent"]
        .transform(lambda x: x.rolling(3, min_periods=1).mean())
        .fillna(0)
    )

    return df


# ── Data Loading ───────────────────────────────────────────────────────────

def load_data() -> pd.DataFrame | None:
    db_path = PROJECT_ROOT / "netscan.db"
    try:
        engine = create_engine(f"sqlite:///{db_path}")
        df = pd.read_sql_table("network_features", engine)
        return df
    except Exception as exc:
        print(f"[WARN] Could not load network_features table: {exc}")
        return None


def retrain_needed(df: pd.DataFrame) -> bool:
    """Return True if the dataset has grown significantly since the last training run."""
    marker = OUTPUT_PATH.with_suffix(".rowcount")
    current = len(df)
    if not marker.exists():
        return True
    try:
        last = int(marker.read_text().strip())
        return (current - last) >= RETRAIN_THRESHOLD
    except Exception:
        return True


def save_row_count(n: int) -> None:
    OUTPUT_PATH.with_suffix(".rowcount").write_text(str(n))


# ── Fitness Function ───────────────────────────────────────────────────────

def evaluate_params(n_est, cont, m_samp, X_sc, scaler):
    """
    Risk-aware fitness function.

    Scoring:
        +1000 per correct prediction
        -500  per False Positive (normal → predicted anomaly)
              FPs are the worst outcome in a college NIDS: blocking innocent users
        + margin between normal score and average anomaly score
        + augmentation bonus: average across 20 noisy variants per sample
    """
    model = IsolationForest(
        n_estimators=n_est,
        contamination=cont,
        max_samples=m_samp,
        random_state=42,
        n_jobs=1,
    )
    model.fit(X_sc)

    correct_preds      = 0
    fp_penalty         = 0
    normal_score       = 0.0
    anomaly_scores: list[float] = []
    aug_correct        = 0
    aug_total          = 0

    for label, vec in SAMPLES.items():
        x = np.array([vec], dtype=float)
        x_sc = scaler.transform(x)
        pred  = model.predict(x_sc)[0]
        score = model.score_samples(x_sc)[0]
        exp   = EXPECTED_PREDS[label]

        if pred == exp:
            correct_preds += 1
        elif exp == 1 and pred == -1:
            # False positive: normal traffic blocked
            fp_penalty += 500

        if label == "Normal":
            normal_score = score
        else:
            anomaly_scores.append(score)

        # Augmentation: test 20 noisy variants
        for variant in augment_sample(vec, noise=0.12):
            xv = scaler.transform(np.array([variant], dtype=float))
            aug_pred = model.predict(xv)[0]
            aug_total += 1
            if aug_pred == exp:
                aug_correct += 1

    avg_anomaly = sum(anomaly_scores) / max(len(anomaly_scores), 1)
    margin      = normal_score - avg_anomaly
    aug_bonus   = (aug_correct / max(aug_total, 1)) * 200

    fitness = correct_preds * 1000 - fp_penalty + margin + aug_bonus
    return fitness, {"n_estimators": n_est, "contamination": cont, "max_samples": m_samp}, model


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  NetScan — Adaptive Ensemble Fine-Tuner")
    print("=" * 60)

    df = load_data()

    use_temporal = False
    if df is not None and len(df) > 0:
        if not retrain_needed(df):
            print(f"[INFO] DB has {len(df)} rows — not enough new data since last train.")
            print("[INFO] Force retrain with: python models/fine_tune.py --force")
            if "--force" not in sys.argv:
                return
        print(f"[INFO] Training on {len(df)} rows from DB.")
        try:
            df = add_temporal_features(df)
            use_temporal = True
            print("[INFO] Temporal features added (delta_flows, rolling_mean, spike_ratio).")
        except Exception as e:
            print(f"[WARN] Temporal feature enrichment failed: {e}")
        cols = [c for c in FEATURE_COLS if c in df.columns]
        X = df[cols].fillna(0).values.astype(float)
    else:
        print("[WARN] No DB data found. Using synthetic baseline for demo run.")
        np.random.seed(42)
        X = np.abs(np.random.normal(
            loc  =[60, 10, 5, 3, 1e5, 5e5, 400, 200, 0.3, 0.1, 10, 0, 3, 2, 443, 0, 0],
            scale=[20,  5, 2, 1, 5e4, 2e5, 100,  50, 0.1,0.05,  5, 0, 2, 1,   0, 0, 0],
            size=(1000, len(FEATURE_COLS)),
        ))

    if len(X) < MIN_SAMPLES:
        print(f"[WARN] Only {len(X)} samples (need ≥ {MIN_SAMPLES}). Results may not generalise well.")

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Grid search
    n_estimators_grid  = [50, 100, 150, 200, 300, 400, 500]
    contamination_grid = [0.01, 0.03, 0.05, 0.08, 0.1, 0.12, 0.15, 0.2]
    max_samples_grid   = ["auto", 0.5, 0.8, 1.0]
    total_combos = len(n_estimators_grid) * len(contamination_grid) * len(max_samples_grid)

    print(f"\n[GRID] Testing {total_combos} combinations in parallel (risk-aware fitness + augmentation)...")

    results = Parallel(n_jobs=-1)(
        delayed(evaluate_params)(n_est, cont, m_samp, X_scaled, scaler)
        for n_est, cont, m_samp in product(n_estimators_grid, contamination_grid, max_samples_grid)
    )

    best_fitness, best_params, best_iso = max(results, key=lambda r: r[0])

    print(f"\n[RESULTS] Optimization complete")
    print(f"  Fitness score  : {best_fitness:.4f}")
    print(f"  n_estimators   : {best_params['n_estimators']}")
    print(f"  contamination  : {best_params['contamination']}")
    print(f"  max_samples    : {best_params['max_samples']}")

    # Train LOF ensemble partner on same data
    print("\n[LOF] Training LocalOutlierFactor ensemble partner...")
    try:
        lof = LocalOutlierFactor(n_neighbors=20, novelty=True, n_jobs=-1)
        lof.fit(X_scaled)
        print("[LOF] LOF trained successfully.")
    except Exception as exc:
        print(f"[LOF] Training failed (LOF will be skipped at inference): {exc}")
        lof = None

    # Save versioned backup
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    versioned  = VERSIONS_DIR / f"isolation_forest_{timestamp}.pkl"

    bundle = {"iso": best_iso, "lof": lof, "scaler": scaler, "params": best_params}
    joblib.dump(bundle, OUTPUT_PATH)
    joblib.dump(bundle, versioned)
    if df is not None:
        save_row_count(len(df) if df is not None else 0)

    print(f"\n[SAVED] Model bundle >> {OUTPUT_PATH}")
    print(f"[SAVED] Versioned backup >> {versioned}")

    # Update ml_config.yaml with best params
    ml_cfg["model"]["params"]["n_estimators"] = best_params["n_estimators"]
    ml_cfg["model"]["params"]["contamination"] = float(best_params["contamination"])
    ml_cfg["model"]["params"]["max_samples"]   = (
        best_params["max_samples"] if isinstance(best_params["max_samples"], str)
        else float(best_params["max_samples"])
    )
    with CONFIG_PATH.open("w") as f:
        yaml.dump(ml_cfg, f, default_flow_style=False, sort_keys=False)
    print(f"[CONFIG] Updated {CONFIG_PATH}")

    print("\n[OK] Training complete. Restart `python cli.py capture` to use the new model.")



if __name__ == "__main__":
    main()


