# online_detector.py — multi-window OnlineIsolationForest for TCP and UDP anomaly detection.
#
# Two separate detectors (tcp_detector, udp_detector) each run three IsolationForest
# models at different window sizes. Slower windows are weighted more heavily to resist
# concept-drift poisoning during sustained flood attacks.
#
# Detection is suppressed during the baselining period (first BASELINE_FLOWS flows).
# After baselining, selective training skips flows that already score as anomalous,
# preventing the model from learning attack patterns as normal.
#
# Explainability: path-depth attribution traverses each tree and weights features by
# how early in the isolation path they appear. This is a snapshot explanation — it
# reflects the model state at the moment the flow was scored, which is the correct
# temporal anchor for a detection event.

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import NamedTuple

import numpy as np
from capymoa.anomaly import OnlineIsolationForest
from capymoa.stream import Schema
from sklearn.preprocessing import RobustScaler

log = logging.getLogger(__name__)

# ── Feature definitions ────────────────────────────────────────────────────────
#
# Features selected based on three principles from the network measurement literature:
#   1. Temporal regularity (Paxson & Floyd 1995, Leland et al. 1994)
#   2. Traffic asymmetry (Mirkovic & Reiher 2004)
#   3. Multi-dimensional anomaly signatures (Lakhina et al. 2004)
#
# Ratios (syn_flag_ratio, fwd_act_data_ratio, down_up_ratio) are used rather than
# raw counts — they are bounded and duration-independent (RFC 7011 convention).

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
    # fwd_act_data_pkts / tot_fwd_pkts — fraction of fwd packets carrying payload
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
    # tot_bwd_bytes / tot_fwd_bytes — amplification asymmetry
    ("down_up_ratio",     lambda r: r["tot_bwd_bytes"] / max(r["tot_fwd_bytes"], 1)),
    ("bwd_pkt_len_max",   lambda r: float(r["bwd_pkt_len_max"])),
]

TCP_IF_FEATURE_NAMES = [name for name, _ in TCP_IF_FEATURES]
UDP_IF_FEATURE_NAMES = [name for name, _ in UDP_IF_FEATURES]


def _extract(flow: dict, features: list[tuple[str, callable]]) -> np.ndarray:
    return np.array([fn(flow) for _, fn in features], dtype=np.float64)


# ── Multi-window result ────────────────────────────────────────────────────────

class WindowScores(NamedTuple):
    fast:      float
    medium:    float
    slow:      float
    composite: float   # 0.20×fast + 0.30×medium + 0.50×slow


@dataclass
class Attribution:
    """Top-N feature attributions from path-depth analysis."""
    features: list[tuple[str, float, float]]   # (name, attribution, raw_value)
    # attribution: normalised contribution [0,1], higher = more responsible for anomaly
    # raw_value: the actual feature value from the flow, for analyst context


# ── Core multi-window detector ─────────────────────────────────────────────────

class MultiWindowIF:
    """Three OnlineIsolationForest models at different window sizes.

    Slower windows are weighted more heavily (0.20/0.30/0.50) to resist
    concept-drift poisoning — a sustained flood must outlast the slow window
    (4096 flows) before it materially shifts the composite score.
    """

    _WINDOWS  = (256, 1024, 4096)
    _WEIGHTS  = (0.20, 0.30, 0.50)
    _N_TREES  = 100

    # Selective training threshold — flows scoring above this are not trained on,
    # preventing attack traffic from being learned as normal behaviour.
    TRAIN_THRESHOLD = 0.60

    def __init__(self, feature_names: list[str], protocol: str) -> None:
        self.feature_names = feature_names
        self.protocol      = protocol
        n_features         = len(feature_names)

        self._schema = Schema.from_custom(
            feature_names=feature_names,
            dataset_name=f"{protocol}_flows",
        )

        self._models: list[OnlineIsolationForest] = [
            OnlineIsolationForest(
                schema=self._schema,
                num_trees=self._N_TREES,
                window_size=w,
                growth_criterion="adaptive",
                random_seed=42 + i,
            )
            for i, w in enumerate(self._WINDOWS)
        ]

        # RobustScaler — fit during baselining. Uses median and IQR so extreme
        # values from attack traffic (if seen during baseline) skew it less than
        # StandardScaler would.
        self._scaler          = RobustScaler()
        self._scaler_fitted   = False

        # Baselining — accumulate flows until BASELINE_FLOWS, then fit scaler
        # and train all three models. Scores are suppressed during this period.
        self._baseline_buffer: list[np.ndarray] = []
        self._baseline_complete = False
        self.BASELINE_FLOWS   = self._WINDOWS[2]   # wait for slow window to fill

        self._n_trained = 0

    # ── Baselining ────────────────────────────────────────────────────────────

    @property
    def is_ready(self) -> bool:
        """True once baselining is complete and scores are reliable."""
        return self._baseline_complete

    @property
    def baseline_progress(self) -> float:
        """Progress toward baseline completion [0.0, 1.0]."""
        if self._baseline_complete:
            return 1.0
        return min(len(self._baseline_buffer) / self.BASELINE_FLOWS, 1.0)

    def _complete_baseline(self) -> None:
        X = np.array(self._baseline_buffer)
        self._scaler.fit(X)
        self._scaler_fitted = True

        # Train all three models on the baseline corpus.
        for raw in self._baseline_buffer:
            x_scaled  = self._scaler.transform(raw.reshape(1, -1))[0]
            instance  = self._schema.create_instance(x_scaled)
            for model in self._models:
                model.train(instance)

        self._baseline_complete = True
        self._baseline_buffer.clear()
        log.info("[%s IF] Baseline complete on %d flows — detection active",
                 self.protocol, self.BASELINE_FLOWS)

    # ── Inference ─────────────────────────────────────────────────────────────

    def process(self, raw: np.ndarray) -> tuple[WindowScores, Attribution] | None:
        """Score a flow and optionally train the models.

        Returns None during the baselining period. After baselining, returns
        (WindowScores, Attribution). Training is skipped if the composite score
        exceeds TRAIN_THRESHOLD (selective training — poisoning defence).
        """
        if not self._baseline_complete:
            self._baseline_buffer.append(raw)
            if len(self._baseline_buffer) >= self.BASELINE_FLOWS:
                self._complete_baseline()
            return None

        x_scaled = self._scaler.transform(raw.reshape(1, -1))[0]
        instance = self._schema.create_instance(x_scaled)

        scores = tuple(m.score_instance(instance) for m in self._models)
        composite = sum(w * s for w, s in zip(self._WEIGHTS, scores))

        window_scores = WindowScores(
            fast=scores[0], medium=scores[1], slow=scores[2],
            composite=composite,
        )

        attribution = self._attribute(x_scaled, raw)

        # Selective training — only train on likely-benign flows.
        if composite < self.TRAIN_THRESHOLD:
            for model in self._models:
                model.train(instance)
            self._n_trained += 1

        return window_scores, attribution

    # ── Path-depth attribution ─────────────────────────────────────────────────

    def _attribute(self, x_scaled: np.ndarray, x_raw: np.ndarray) -> Attribution:
        """Compute feature attribution by traversing isolation paths.

        For each tree in each model, we walk the path taken by x_scaled and
        accumulate a depth-weighted score for each feature that caused a split.
        Features that appear early in the path (low depth) caused isolation sooner
        — they contributed more to the anomaly score — so they receive higher weight.

        Scores are weighted by model weight (slow model contributes more) then
        normalised to sum to 1.0 across the top features.
        """
        feat_scores: dict[int, float] = defaultdict(float)

        for model, model_weight in zip(self._models, self._WEIGHTS):
            for tree in model.trees:
                node  = tree.root
                depth = 0
                while not node.is_leaf:
                    feat_idx = node.split_feature
                    # Earlier split = higher contribution; depth+1 avoids div-by-zero
                    feat_scores[feat_idx] += model_weight / (depth + 1)
                    if x_scaled[feat_idx] < node.split_value:
                        node = node.left
                    else:
                        node = node.right
                    depth += 1

        total = sum(feat_scores.values()) or 1.0
        ranked = sorted(feat_scores.items(), key=lambda kv: kv[1], reverse=True)

        top = [
            (self.feature_names[idx], score / total, float(x_raw[idx]))
            for idx, score in ranked[:3]
        ]
        return Attribution(features=top)

    # ── Baseline statistics for dashboard context ──────────────────────────────

    def baseline_stats(self) -> dict[str, dict[str, float]]:
        """Return median and IQR for each feature from the fitted scaler.

        Used by the dashboard to show 'value: X  baseline median: Y' alongside
        attribution bars. Only available after baselining is complete.
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
# Instantiated once at startup and shared across all inference worker calls.
# Not thread-safe — inference worker must call process() from a single thread.

tcp_detector = MultiWindowIF(TCP_IF_FEATURE_NAMES, protocol="TCP")
udp_detector = MultiWindowIF(UDP_IF_FEATURE_NAMES, protocol="UDP")


def process_flow(flow: dict) -> dict | None:
    """Entry point for the inference worker.

    Extracts features for the appropriate protocol, runs MultiWindowIF,
    and returns a structured result dict ready for alert assembly.
    Returns None during baselining or for unsupported protocols.
    """
    proto = flow["protocol"]

    if proto == 6:
        detector  = tcp_detector
        features  = TCP_IF_FEATURES
        feat_names = TCP_IF_FEATURE_NAMES
    elif proto == 17:
        detector  = udp_detector
        features  = UDP_IF_FEATURES
        feat_names = UDP_IF_FEATURE_NAMES
    else:
        log.debug("Unsupported protocol %d — skipping", proto)
        return None

    raw = _extract(flow, features)
    result = detector.process(raw)

    if result is None:
        # Still baselining
        return {
            "baselining": True,
            "progress":   detector.baseline_progress,
            "protocol":   "TCP" if proto == 6 else "UDP",
        }

    scores, attribution = result
    proto_str = "TCP" if proto == 6 else "UDP"

    # Severity from composite score
    if scores.composite >= 0.75:
        severity = "CRITICAL"
    elif scores.composite >= 0.60:
        severity = "HIGH"
    else:
        severity = "INFO"

    return {
        "baselining": False,
        "protocol":   proto_str,
        "scores":     {
            "fast":      scores.fast,
            "medium":    scores.medium,
            "slow":      scores.slow,
            "composite": scores.composite,
        },
        "verdict": severity,
        "attribution": [
            {
                "feature":    name,
                "score":      attr_score,
                "value":      raw_val,
                "baseline":   detector.baseline_stats().get(name, {}),
            }
            for name, attr_score, raw_val in attribution.features
        ],
    }
