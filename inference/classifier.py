# classifier.py — inference entry point.
#
# Active path: online_detector.process_flow() — MultiWindowIF anomaly detection
# for both TCP and UDP. Protocol-specific feature sets, triple-window scoring,
# path-depth attribution, baselining period before detection starts.
#
# Legacy path: supervised ExtraTrees TCP classifier (extra_trees_tcp.pkl).
# Kept for reference but not called — feature set no longer matches the struct
# after fwd_pkts_per_sec / syn_flag_ratio / psh_flag_ratio were added.
# Re-enable when a retrained model is available.

import logging
import os
import pickle
import time
import uuid
from pathlib import Path
from typing import Any

import numpy as np
import shap
from sklearn.ensemble import IsolationForest

from feature_extractor import (
    TCP_FEATURE_NAMES, UDP_FEATURE_NAMES,
    extract_tcp, extract_udp,
)
from online_detector import process_flow as _if_process_flow, tcp_detector, udp_detector

log = logging.getLogger(__name__)

MODELS_DIR = Path(__file__).parent / "models"

# ── Severity maps ─────────────────────────────────────────────────────────────

TCP_SEVERITY: dict[str, str] = {
    "Benign":                  "INFO",
    "Bot":                     "HIGH",
    "Brute Force -Web":        "HIGH",
    "Brute Force -XSS":        "HIGH",
    "DDOS attack-HOIC":        "CRITICAL",
    "DoS attacks-GoldenEye":   "CRITICAL",
    "DoS attacks-Hulk":        "CRITICAL",
    "DoS attacks-SlowHTTPTest":"CRITICAL",
    "DoS attacks-Slowloris":   "CRITICAL",
    "FTP-BruteForce":          "HIGH",
    "Infilteration":           "CRITICAL",
    "SQL Injection":           "CRITICAL",
    "SSH-Bruteforce":          "HIGH",
}

UDP_SEVERITY: dict[str, str] = {
    "Benign":          "INFO",
    "DDoS-LOIC-UDP":   "CRITICAL",
    "DDoS-HOIC":       "CRITICAL",
}


def _load_pkl(name: str) -> Any:
    path = MODELS_DIR / name
    if not path.exists():
        raise FileNotFoundError(
            f"Model not found: {path}\n"
            "Copy the trained pkl files into inference/models/ or run with --anomaly-only."
        )
    with open(path, "rb") as f:
        return pickle.load(f)


class Classifier:
    def __init__(self, anomaly_only: bool = False) -> None:
        self.anomaly_only = anomaly_only

        self._tcp_model     = None
        self._tcp_label_map: dict[int, str] = {}
        self._tcp_classes:   list[int] = []
        self._tcp_explainer  = None

        # IsolationForest — prefer a pre-fitted model from disk; fall back to
        # fitting on the first 1000 flows seen. The fallback has a cold-start
        # risk (early attacks look "normal") but is acceptable for demo use.
        self._iso: IsolationForest | None = None
        self._iso_buffer: list[list[float]] = []
        self._iso_fitted = False
        self._ISO_FIT_THRESHOLD = 1000

        self._load_iso()

        if not anomaly_only:
            self._load_models()

    def _load_iso(self) -> None:
        iso_path = MODELS_DIR / "isoforest.pkl"
        if iso_path.exists():
            with open(iso_path, "rb") as f:
                self._iso = pickle.load(f)
            self._iso_fitted = True
            log.info("IsolationForest loaded from %s", iso_path)
        else:
            log.info("No isoforest.pkl found — will fit on first %d flows",
                     self._ISO_FIT_THRESHOLD)

    def _load_models(self) -> None:
        log.info("Loading TCP model...")
        tcp_bundle = _load_pkl("extra_trees_tcp.pkl")
        self._tcp_model     = tcp_bundle["model"]
        self._tcp_label_map = tcp_bundle["label_map"]   # {original_int: label_str}
        # bundle["classes"] holds the original class IDs in the same order as
        # predict_proba columns — the model re-encodes them to 0-based internally.
        self._tcp_classes   = tcp_bundle["classes"]     # [0,1,2,3,4,6,7,8,9,10,11,12,13]
        log.info("TCP classes: %s", [self._tcp_label_map[c] for c in self._tcp_classes])

        # SHAP on the classifier step inside the Pipeline, not the Pipeline itself
        clf_step = self._tcp_model.named_steps["clf"]
        self._tcp_explainer = shap.TreeExplainer(clf_step)
        log.info("TCP model loaded ✓  (UDP unsupervised component: pending)")

    # ── IsolationForest ───────────────────────────────────────────────────────

    def _iso_features(self, flow: dict) -> list[float]:
        """Compact 4-feature vector used for anomaly scoring across protocols."""
        return [
            flow["pkt_len_mean"],
            flow["bwd_pkts_per_sec"],
            flow["tot_pkts"],
            flow["flow_duration_s"],
        ]

    def _update_iso(self, flow: dict) -> float:
        """Update IsolationForest with a new flow and return the anomaly score.

        Returns 0.0 until enough flows have been collected to fit the model.
        Negative scores indicate anomalies (sklearn convention).
        """
        feats = self._iso_features(flow)
        self._iso_buffer.append(feats)

        if not self._iso_fitted and len(self._iso_buffer) >= self._ISO_FIT_THRESHOLD:
            self._iso = IsolationForest(n_estimators=100, contamination=0.05,
                                        random_state=42)
            self._iso.fit(self._iso_buffer)
            self._iso_fitted = True
            log.info("IsolationForest fitted on %d flows", len(self._iso_buffer))

        if self._iso_fitted and self._iso is not None:
            score = float(self._iso.decision_function([feats])[0])
            return score

        return 0.0

    # ── SHAP ──────────────────────────────────────────────────────────────────

    def _top3_shap(self, explainer, feature_vector: np.ndarray,
                   feature_names: list[str]) -> list[list]:
        """Return top-3 features by absolute SHAP value as compact triples."""
        try:
            shap_values = explainer.shap_values(feature_vector)
            # For multi-class, shap_values is a list of arrays (one per class).
            # Sum absolute values across classes to get overall feature importance.
            if isinstance(shap_values, list):
                importance = np.sum(np.abs(np.array(shap_values)), axis=0)[0]
            else:
                importance = np.abs(shap_values[0])

            top3_idx = np.argsort(importance)[::-1][:3]
            result = []
            for i in top3_idx:
                result.append([
                    feature_names[i],
                    float(feature_vector[0, i]),
                    float(importance[i]),
                ])
            return result
        except Exception as exc:
            log.warning("SHAP failed for this flow: %s", exc)
            return []

    # ── Public API ────────────────────────────────────────────────────────────

    def predict(self, flow: dict) -> dict | None:
        """Run inference on a completed flow dict.

        Active path: MultiWindowIF anomaly detection via online_detector.
        Returns a baselining status dict during the warmup period, a full
        alert dict once detection is active, or None for unsupported protocols.
        """
        result = _if_process_flow(flow)
        if result is None:
            return None   # unsupported protocol

        # During baselining — return a lightweight status update for the dashboard
        if result["baselining"]:
            return {
                "type":     "baselining",
                "protocol": result["protocol"],
                "progress": result["progress"],
            }

        t_infer_ns = time.time_ns()   # OIF complete — stamp before dict construction

        proto = flow["protocol"]
        return {
            "flow_id":     str(uuid.uuid4()),
            "ts":          flow["first_pkt_ns"] / 1e9,
            "src_ip":      flow["src_ip"],
            "dst_ip":      flow["dst_ip"],
            "src_port":    flow["src_port"],
            "dst_port":    flow["dst_port"],
            "proto":       result["protocol"],
            "duration":    flow["flow_duration_s"],
            "fwd_pkts":    flow["tot_fwd_pkts"],
            "verdict": {
                "label":      result["verdict"],   # CRITICAL / HIGH / INFO
                "severity":   result["verdict"],
                "confidence": result["scores"]["composite"],
            },
            "scores":      result["scores"],       # fast/medium/slow/composite
            "attribution": result["attribution"],  # top-3 OIF path-depth attribution
            # Pipeline latency timestamps (nanoseconds, CLOCK_REALTIME)
            "_timing": {
                "flow_ts_ns":  flow.get("first_pkt_ns", 0),
                "t_socket_ns": flow.get("t_socket_ns", 0),
                "t_infer_ns":  t_infer_ns,
            },
        }

    # ── Legacy supervised TCP path (not called — feature set mismatch) ────────
    # Re-enable when extra_trees_tcp.pkl is retrained on the updated feature set.

    def _predict_supervised_tcp_legacy(self, flow: dict) -> dict:
        """Supervised ExtraTrees classification. Kept for reference only."""
        vec        = extract_tcp(flow)
        proba      = self._tcp_model.predict_proba(vec)[0]
        best_idx   = int(np.argmax(proba))
        int_class  = self._tcp_classes[best_idx]
        label      = self._tcp_label_map[int_class]
        confidence = float(proba[best_idx])
        severity   = TCP_SEVERITY.get(label, "HIGH")
        vec_for_shap = self._tcp_model.named_steps["scaler"].transform(vec)
        shap_triples = self._top3_shap(self._tcp_explainer, vec_for_shap,
                                       TCP_FEATURE_NAMES)
        return {
            "label":      label,
            "label_id":   int_class,
            "confidence": confidence,
            "severity":   severity,
            "shap":       shap_triples,
        }
