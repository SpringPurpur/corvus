# online_detector.py — multi-window streaming anomaly detection for TCP and UDP.
#
# Uses River's HalfSpaceTrees (Tan et al., IJCAI 2011) — a streaming anomaly
# detector that maintains mass profiles across a sliding window. Chosen over
# CapyMOA OnlineIsolationForest (Leveni et al., ICML 2024) for the same
# detection quality without Java/PyTorch dependencies.
#
# Three models per protocol at different window sizes (256/1024/4096) weighted
# 0.20/0.30/0.50 toward the slowest model. Slower windows are more resistant
# to concept-drift poisoning — a flood must outlast 4096 flows to materially
# shift the composite score.
#
# Explainability: path-depth attribution traverses each tree in the ensemble
# and weights features by isolation depth. This is a snapshot explanation
# anchored to the model state at detection time — the epistemically correct
# answer to "why was this flow anomalous right now."

import logging
from collections import defaultdict
from dataclasses import dataclass
from typing import NamedTuple

import numpy as np
from river.anomaly import HalfSpaceTrees
from sklearn.preprocessing import RobustScaler

log = logging.getLogger(__name__)

# ── Feature definitions ────────────────────────────────────────────────────────
#
# Selected on three principles from the network measurement literature:
#   1. Temporal regularity (Paxson & Floyd 1995, Leland et al. 1994)
#   2. Traffic asymmetry (Mirkovic & Reiher 2004)
#   3. Multi-dimensional anomaly signatures (Lakhina et al. 2004)
#
# Ratios (syn_flag_ratio, fwd_act_data_ratio, down_up_ratio) are bounded [0,1]
# and duration-independent, per RFC 7011 flow record conventions.

TCP_IF_FEATURES: list[tuple[str, callable]] = [
    ("fwd_pkts_per_sec",   lambda r: r["fwd_pkts_per_sec"]),
    ("bwd_pkts_per_sec",   lambda r: r["bwd_pkts_per_sec"]),
    ("pkt_len_mean",       lambda r: r["pkt_len_mean"]),
    ("pkt_len_std",        lambda r: r["pkt_len_std"]),
    ("flow_duration_s",    lambda r: r["flow_duration_s"]),
    ("flow_iat_mean",      lambda r: r["flow_iat_mean"]),
    ("fwd_iat_std",        lambda r: r["fwd_iat_std"]),
    ("init_fwd_win_bytes", lambda r: float(r["init_fwd_win_bytes"])),
    ("syn_flag_ratio",     lambda r: r["syn_flag_ratio"]),
    ("fwd_act_data_ratio", lambda r: r["fwd_act_data_pkts"] / max(r["tot_fwd_pkts"], 1)),
]

UDP_IF_FEATURES: list[tuple[str, callable]] = [
    ("fwd_pkts_per_sec",  lambda r: r["fwd_pkts_per_sec"]),
    ("bwd_pkts_per_sec",  lambda r: r["bwd_pkts_per_sec"]),
    ("pkt_len_mean",      lambda r: r["pkt_len_mean"]),
    ("pkt_len_std",       lambda r: r["pkt_len_std"]),
    ("flow_duration_s",   lambda r: r["flow_duration_s"]),
    ("flow_iat_mean",     lambda r: r["flow_iat_mean"]),
    ("fwd_iat_std",       lambda r: r["fwd_iat_std"]),
    ("down_up_ratio",     lambda r: r["tot_bwd_bytes"] / max(r["tot_fwd_bytes"], 1)),
    ("bwd_pkt_len_max",   lambda r: float(r["bwd_pkt_len_max"])),
]

TCP_IF_FEATURE_NAMES = [name for name, _ in TCP_IF_FEATURES]
UDP_IF_FEATURE_NAMES = [name for name, _ in UDP_IF_FEATURES]


def _extract(flow: dict, features: list[tuple[str, callable]]) -> np.ndarray:
    return np.array([fn(flow) for _, fn in features], dtype=np.float64)


def _to_river_dict(x: np.ndarray, names: list[str]) -> dict[str, float]:
    """River expects a feature dict {name: value}."""
    return {name: float(x[i]) for i, name in enumerate(names)}


# ── Multi-window result types ──────────────────────────────────────────────────

class WindowScores(NamedTuple):
    fast:      float
    medium:    float
    slow:      float
    composite: float   # 0.20×fast + 0.30×medium + 0.50×slow


@dataclass
class Attribution:
    """Top-3 feature attributions from path-depth traversal."""
    # Each entry: (feature_name, normalised_attribution, raw_value)
    # attribution: [0,1] — fraction of total isolation depth attributed to this feature
    # raw_value: actual value from the flow, shown alongside baseline median
    features: list[tuple[str, float, float]]


# ── Core multi-window detector ─────────────────────────────────────────────────

class MultiWindowIF:
    """Three HalfSpaceTrees models at window sizes 256/1024/4096.

    Weighted composite score (0.20/0.30/0.50) gives the slow model majority
    influence, resisting poisoning by sustained floods.
    """

    _WINDOWS = (256, 1024, 4096)
    _WEIGHTS = (0.20, 0.30, 0.50)

    # Flows scoring above this threshold are not trained on — prevents attack
    # traffic from shifting the model's definition of normal (selective training).
    TRAIN_THRESHOLD = 0.60

    # Alert thresholds on composite score
    _THRESHOLD_CRITICAL = 0.75
    _THRESHOLD_HIGH     = 0.60

    def __init__(self, feature_names: list[str], protocol: str) -> None:
        self.feature_names = feature_names
        self.protocol      = protocol
        n_features         = len(feature_names)

        # River HalfSpaceTrees — height=ceil(log2(window_size)) by default.
        # n_trees=25 matches River's default; sufficient for stable scoring.
        self._models: list[HalfSpaceTrees] = [
            HalfSpaceTrees(
                n_trees=25,
                height=15,
                window_size=w,
                seed=42 + i,
            )
            for i, w in enumerate(self._WINDOWS)
        ]

        # RobustScaler fitted during baselining. Uses median/IQR rather than
        # mean/std — less sensitive to extreme values if any attack traffic
        # slips through during the warmup period.
        self._scaler        = RobustScaler()
        self._scaler_fitted = False

        # Baselining — accumulate raw feature vectors until BASELINE_FLOWS,
        # then fit the scaler and seed all three models. Scores are suppressed
        # until baselining is complete (returns None from process()).
        self._baseline_buffer: list[np.ndarray] = []
        self._baseline_complete = False
        self.BASELINE_FLOWS = self._WINDOWS[2]   # wait for slow window to fill

        self._n_trained = 0

    # ── Baselining ────────────────────────────────────────────────────────────

    @property
    def is_ready(self) -> bool:
        return self._baseline_complete

    @property
    def baseline_progress(self) -> float:
        if self._baseline_complete:
            return 1.0
        return min(len(self._baseline_buffer) / self.BASELINE_FLOWS, 1.0)

    def _complete_baseline(self) -> None:
        X = np.array(self._baseline_buffer)
        self._scaler.fit(X)
        self._scaler_fitted = True

        # Seed all three models on the baseline corpus.
        for raw in self._baseline_buffer:
            x_scaled  = self._scaler.transform(raw.reshape(1, -1))[0]
            x_dict    = _to_river_dict(x_scaled, self.feature_names)
            for model in self._models:
                model.learn_one(x_dict)

        self._baseline_complete = True
        self._baseline_buffer.clear()
        log.info("[%s IF] Baseline complete on %d flows — detection active",
                 self.protocol, self.BASELINE_FLOWS)

    # ── Inference ─────────────────────────────────────────────────────────────

    def process(self, raw: np.ndarray) -> tuple[WindowScores, Attribution] | None:
        """Score a flow, optionally train, return scores and attribution.

        Returns None during baselining. After baselining, returns
        (WindowScores, Attribution). High-scoring flows are not trained on
        (selective training) to resist concept-drift poisoning.
        """
        if not self._baseline_complete:
            self._baseline_buffer.append(raw)
            if len(self._baseline_buffer) >= self.BASELINE_FLOWS:
                self._complete_baseline()
            return None

        x_scaled = self._scaler.transform(raw.reshape(1, -1))[0]
        x_dict   = _to_river_dict(x_scaled, self.feature_names)

        scores = tuple(m.score_one(x_dict) for m in self._models)
        composite = sum(w * s for w, s in zip(self._WEIGHTS, scores))

        window_scores = WindowScores(
            fast=scores[0], medium=scores[1], slow=scores[2],
            composite=composite,
        )

        attribution = self._attribute(x_scaled, raw)

        # Selective training — only update on likely-benign flows.
        if composite < self.TRAIN_THRESHOLD:
            for model in self._models:
                model.learn_one(x_dict)
            self._n_trained += 1

        return window_scores, attribution

    # ── Path-depth attribution ─────────────────────────────────────────────────

    def _attribute(self, x_scaled: np.ndarray, x_raw: np.ndarray) -> Attribution:
        """Depth-weighted feature attribution over all trees and all models.

        For each tree, we walk the path taken by x_scaled and record which
        feature caused each split. Features at shallow depth caused earlier
        isolation — they contributed more to the anomaly score and receive
        higher weight (1/(depth+1)). Model weights (0.20/0.30/0.50) are
        applied so the slow model's trees dominate the attribution.

        Uses tree.walk() rather than manual traversal — River's HSTBranch.walk()
        handles the < vs <= split direction correctly and avoids depending on
        internal node structure. Each item in model.trees is already the root
        HSTBranch (no .root accessor exists).

        This is a snapshot: the explanation reflects model state at detection
        time, which is the correct temporal anchor for an IDS alert.
        """
        x_dict      = _to_river_dict(x_scaled, self.feature_names)
        feat_scores: dict[int, float] = defaultdict(float)

        for model, model_weight in zip(self._models, self._WEIGHTS):
            for tree in model.trees:
                # walk() yields every node from root to leaf; leaf has no .feature
                for depth, node in enumerate(tree.walk(x_dict)):
                    if not hasattr(node, "feature"):
                        continue
                    feat_idx = self.feature_names.index(node.feature)
                    feat_scores[feat_idx] += model_weight / (depth + 1)

        total  = sum(feat_scores.values()) or 1.0
        ranked = sorted(feat_scores.items(), key=lambda kv: kv[1], reverse=True)

        top = [
            (self.feature_names[idx], score / total, float(x_raw[idx]))
            for idx, score in ranked[:3]
        ]
        return Attribution(features=top)

    # ── Baseline statistics for dashboard context ──────────────────────────────

    def baseline_stats(self) -> dict[str, dict[str, float]]:
        """Median and IQR per feature from the fitted RobustScaler.

        Used by the dashboard to show 'value: X  baseline: Y ± Z' next to
        each attribution bar. Only available after baselining completes.
        """
        if not self._scaler_fitted:
            return {}
        return {
            name: {
                "median": float(self._scaler.center_[i]),
                "iqr":    float(self._scaler.scale_[i]),
            }
            for i, name in enumerate(self.feature_names)
        }


# ── Module-level detector instances ───────────────────────────────────────────
#
# One per protocol, instantiated at import time, shared across inference calls.
# Not thread-safe — must be called from the single inference worker thread.

tcp_detector = MultiWindowIF(TCP_IF_FEATURE_NAMES, protocol="TCP")
udp_detector = MultiWindowIF(UDP_IF_FEATURE_NAMES, protocol="UDP")


def process_flow(flow: dict) -> dict | None:
    """Extract features for the flow's protocol and run MultiWindowIF.

    Returns a baselining status dict during warmup, a full result dict
    during detection, or None for unsupported protocols.
    """
    proto = flow["protocol"]

    if proto == 6:
        detector = tcp_detector
        features = TCP_IF_FEATURES
    elif proto == 17:
        detector = udp_detector
        features = UDP_IF_FEATURES
    else:
        log.debug("Unsupported protocol %d — skipping", proto)
        return None

    raw    = _extract(flow, features)
    result = detector.process(raw)

    proto_str = "TCP" if proto == 6 else "UDP"

    if result is None:
        return {
            "baselining": True,
            "progress":   detector.baseline_progress,
            "protocol":   proto_str,
        }

    scores, attribution = result

    if scores.composite >= MultiWindowIF._THRESHOLD_CRITICAL:
        severity = "CRITICAL"
    elif scores.composite >= MultiWindowIF._THRESHOLD_HIGH:
        severity = "HIGH"
    else:
        severity = "INFO"

    return {
        "baselining": False,
        "protocol":   proto_str,
        "scores": {
            "fast":      scores.fast,
            "medium":    scores.medium,
            "slow":      scores.slow,
            "composite": scores.composite,
        },
        "verdict":  severity,
        "attribution": [
            {
                "feature":  name,
                "score":    attr_score,
                "value":    raw_val,
                "baseline": detector.baseline_stats().get(name, {}),
            }
            for name, attr_score, raw_val in attribution.features
        ],
    }
