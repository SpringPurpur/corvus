# online_detector.py — multi-window streaming anomaly detection for TCP and UDP.
#
# Implements Online Isolation Forest (Leveni et al., ICML 2024) natively in Python.
# The algorithm maintains adaptive histogram trees that grow and collapse as data
# arrives and departs the sliding window — no batch retraining, no Java dependency.
#
# Three models per protocol at different window sizes (256/1024/4096) weighted
# 0.20/0.30/0.50. Slower windows resist poisoning: a flood must outlast 4096 flows
# to materially shift the slow window's definition of normal.
#
# Explainability: path-depth attribution over OIF trees. Splits are data-adaptive
# (chosen from actual observed ranges), so the feature at each split node is the
# one that most effectively partitioned the data around this point — more meaningful
# than HST's random half-space cuts.
#
# Reference: Leveni F., Cassales G.W., Pfahringer B., Bifet A., Boracchi G.
#   "Online Isolation Forest." ICML 2024, PMLR v235.

import logging
import math
import pickle
import random
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

import numpy as np
from sklearn.preprocessing import RobustScaler

import config as _cfg_module

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
    ("flow_iat_mean",      lambda r: r["flow_iat_mean"] / 1_000_000.0),  # ns → ms
    ("fwd_iat_std",        lambda r: r["fwd_iat_std"]   / 1_000_000.0),  # ns → ms
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
    ("flow_iat_mean",     lambda r: r["flow_iat_mean"] / 1_000_000.0),  # ns → ms
    ("fwd_iat_std",       lambda r: r["fwd_iat_std"]   / 1_000_000.0),  # ns → ms
    ("down_up_ratio",     lambda r: r["tot_bwd_bytes"] / max(r["tot_fwd_bytes"], 1)),
    ("bwd_pkt_len_max",   lambda r: float(r["bwd_pkt_len_max"])),
]

TCP_IF_FEATURE_NAMES = [name for name, _ in TCP_IF_FEATURES]
UDP_IF_FEATURE_NAMES = [name for name, _ in UDP_IF_FEATURES]


def _extract(flow: dict, features: list[tuple[str, callable]]) -> np.ndarray:
    return np.array([fn(flow) for _, fn in features], dtype=np.float64)


def _to_oif_dict(x: np.ndarray, names: list[str]) -> dict[str, float]:
    return {name: float(x[i]) for i, name in enumerate(names)}


# ── Online Isolation Forest — Leveni et al. ICML 2024 ─────────────────────────

@dataclass
class _OIFNode:
    """A node in an Online Isolation Tree.

    Internal nodes have split_feature/split_value set and non-None children.
    Leaves have split_feature=None and no children.

    h   — count of points currently in this node's sliding window.
    min_val / max_val — bounding box of all points that have passed through
                        this node and are still in the window. Updated on
                        learn (expand) and approximated on unlearn (shrink
                        from children, since raw points are not stored).
    """
    depth:         int
    h:             int
    min_val:       dict[str, float]
    max_val:       dict[str, float]
    split_feature: str | None           = None
    split_value:   float | None         = None
    left:          "_OIFNode | None"    = field(default=None, repr=False)
    right:         "_OIFNode | None"    = field(default=None, repr=False)

    @property
    def is_leaf(self) -> bool:
        return self.split_feature is None


class OnlineIsolationTree:
    """Single tree in an Online Isolation Forest.

    Grows when a leaf accumulates enough points (adaptive threshold = η×2^depth)
    and collapses when a branch loses too many (same threshold applied on unlearn).
    Scoring is path length + leaf correction, same formula as classical iForest.
    """

    def __init__(
        self,
        feature_names:   list[str],
        max_leaf_samples: int  = 32,
        rng:             random.Random | None = None,
    ) -> None:
        self.feature_names    = feature_names
        self.max_leaf_samples = max_leaf_samples
        self._rng             = rng or random.Random()
        self.root: _OIFNode | None = None

    # ── split criterion ───────────────────────────────────────────────────────

    def _threshold(self, depth: int) -> int:
        # Adaptive criterion from Leveni et al. §3: deeper nodes require
        # exponentially more data before splitting, keeping trees balanced.
        return self.max_leaf_samples * (1 << depth)

    def _leaf_correction(self, h: int) -> float:
        # Expected additional path length inside a non-empty leaf, mirroring
        # classical iForest's c(n) leaf correction (Liu et al. 2008).
        # Returns 0 when h ≤ η — no meaningful subtree to estimate.
        if h <= self.max_leaf_samples:
            return 0.0
        return math.log2(h / self.max_leaf_samples)

    # ── learn ─────────────────────────────────────────────────────────────────

    def learn_one(self, x: dict[str, float], max_depth: int) -> None:
        if self.root is None:
            self.root = _OIFNode(
                depth=0, h=1,
                min_val={f: x[f] for f in self.feature_names},
                max_val={f: x[f] for f in self.feature_names},
            )
            return
        self._learn(self.root, x, max_depth)

    def _learn(self, node: _OIFNode, x: dict[str, float], max_depth: int) -> None:
        node.h += 1
        for f in self.feature_names:
            if x[f] < node.min_val[f]:
                node.min_val[f] = x[f]
            if x[f] > node.max_val[f]:
                node.max_val[f] = x[f]

        if node.is_leaf:
            if node.h >= self._threshold(node.depth) and node.depth < max_depth:
                self._split(node)
        else:
            child = node.left if x[node.split_feature] < node.split_value else node.right
            self._learn(child, x, max_depth)

    def _split(self, node: _OIFNode) -> None:
        """Convert a leaf to an internal node by choosing a random axis-parallel split.

        Split feature is chosen uniformly at random from features that have
        non-zero range (only features with variation can usefully split).
        Child counts are estimated by assuming the h points are distributed
        uniformly over the bounding box — same assumption as the paper's
        Algorithm 2, which samples h points from U(R) to set child heights.
        """
        candidates = [
            f for f in self.feature_names
            if node.max_val[f] > node.min_val[f]
        ]
        if not candidates:
            # All features are constant in this region — cannot split.
            return

        q = self._rng.choice(candidates)
        p = self._rng.uniform(node.min_val[q], node.max_val[q])

        frac_left = (p - node.min_val[q]) / (node.max_val[q] - node.min_val[q])
        h_left  = max(round(node.h * frac_left), 1)
        h_right = max(node.h - h_left, 1)

        left_max       = dict(node.max_val);  left_max[q]  = p
        right_min      = dict(node.min_val);  right_min[q] = p

        node.split_feature = q
        node.split_value   = p
        node.left  = _OIFNode(node.depth + 1, h_left,  dict(node.min_val), left_max)
        node.right = _OIFNode(node.depth + 1, h_right, right_min,          dict(node.max_val))

    # ── unlearn ───────────────────────────────────────────────────────────────

    def unlearn_one(self, x: dict[str, float]) -> None:
        if self.root is None:
            return
        self._unlearn(self.root, x)
        if self.root.h <= 0:
            self.root = None

    def _unlearn(self, node: _OIFNode, x: dict[str, float]) -> None:
        node.h -= 1

        if node.is_leaf:
            return

        # Collapse this branch if it no longer has enough data to justify
        # its depth — mirrors the unlearn criterion in Algorithm 3.
        if node.h < self._threshold(node.depth):
            self._collapse(node)
            return

        child = node.left if x[node.split_feature] < node.split_value else node.right
        self._unlearn(child, x)

        # Approximate bounding box update from children.
        # We can't recompute exact bounds without storing all points,
        # so we shrink from children — the box can only tighten here,
        # which is acceptable since it's used for split sampling only.
        for f in self.feature_names:
            node.min_val[f] = min(node.left.min_val[f], node.right.min_val[f])
            node.max_val[f] = max(node.left.max_val[f], node.right.max_val[f])

    def _collapse(self, node: _OIFNode) -> None:
        """Collapse an internal node back into a leaf.

        The combined bounding box is taken from children before nulling them.
        Python GC reclaims the entire collapsed subtree.
        """
        node.min_val = {
            f: min(node.left.min_val[f], node.right.min_val[f])
            for f in self.feature_names
        }
        node.max_val = {
            f: max(node.left.max_val[f], node.right.max_val[f])
            for f in self.feature_names
        }
        node.split_feature = None
        node.split_value   = None
        node.left          = None
        node.right         = None

    # ── score ─────────────────────────────────────────────────────────────────

    def score_one(self, x: dict[str, float]) -> float:
        """Return path depth + leaf correction for x in this tree."""
        if self.root is None:
            return 0.0
        return self._path_depth(self.root, x)

    def _path_depth(self, node: _OIFNode, x: dict[str, float]) -> float:
        if node.is_leaf:
            return node.depth + self._leaf_correction(node.h)
        child = node.left if x[node.split_feature] < node.split_value else node.right
        return self._path_depth(child, x)

    # ── attribution ───────────────────────────────────────────────────────────

    def attribute_path(
        self,
        x:            dict[str, float],
        model_weight: float,
        feat_scores:  dict[str, float],
    ) -> None:
        """Walk the path for x, accumulating depth-weighted attribution.

        Features at shallower depth isolated x more — weight by 1/(depth+1).
        model_weight scales by the window model's contribution to composite.
        """
        node  = self.root
        depth = 0
        while node is not None and not node.is_leaf:
            feat_scores[node.split_feature] += model_weight / (depth + 1)
            node  = node.left if x[node.split_feature] < node.split_value else node.right
            depth += 1


class OnlineIsolationForest:
    """Ensemble of OnlineIsolationTrees with a sliding window.

    Each new point is learned into all trees. When the window fills, the
    oldest point is explicitly unlearned — no batch retraining.

    Anomaly score = 2^(-E[depth] / c(ω, η)) where c(ω, η) = log₂(ω/η).
    This is the same normalisation as classical iForest adapted for the
    online setting (paper §3.2). Score ∈ (0,1), higher = more anomalous.
    """

    def __init__(
        self,
        feature_names:    list[str],
        n_trees:          int = 32,
        window_size:      int = 2048,
        max_leaf_samples: int = 32,
        subsample:        float = 1.0,
        seed:             int = 42,
    ) -> None:
        self.feature_names    = feature_names
        self.window_size      = window_size
        self.max_leaf_samples = max_leaf_samples
        self.subsample        = subsample

        # max_depth = log₂(ω/η) — the depth at which a fully grown tree
        # contains exactly one point per leaf (Liu et al. 2008 §3).
        self.max_depth        = max(1, int(math.log2(window_size / max_leaf_samples)))
        # Normalization: expected average depth for a uniform dataset.
        self._norm            = float(self.max_depth)

        self._rng    = random.Random(seed)
        self._trees  = [
            OnlineIsolationTree(feature_names, max_leaf_samples, random.Random(seed + i))
            for i in range(n_trees)
        ]
        # Sliding window stored as a plain deque — managed manually so we
        # can unlearn the ejected point before it leaves the deque.
        self._window: deque[dict[str, float]] = deque()

    def learn_one(self, x: dict[str, float]) -> None:
        if len(self._window) >= self.window_size:
            old = self._window.popleft()
            for tree in self._trees:
                tree.unlearn_one(old)

        self._window.append(x)
        for tree in self._trees:
            if self.subsample < 1.0 and self._rng.random() >= self.subsample:
                continue
            tree.learn_one(x, self.max_depth)

    def score_one(self, x: dict[str, float]) -> float:
        if not self._window:
            return 0.5
        depths     = [t.score_one(x) for t in self._trees]
        mean_depth = sum(depths) / len(depths)
        return 2.0 ** (-mean_depth / (self._norm + 1e-10))

    def attribute(
        self,
        x:            dict[str, float],
        model_weight: float,
        feat_scores:  dict[str, float],
    ) -> None:
        """Accumulate path-depth attribution across all trees."""
        for tree in self._trees:
            tree.attribute_path(x, model_weight, feat_scores)


# ── Multi-window result types ──────────────────────────────────────────────────

class WindowScores(NamedTuple):
    fast:      float
    medium:    float
    slow:      float
    composite: float   # 0.20×fast + 0.30×medium + 0.50×slow


# ── Multi-window OIF detector ──────────────────────────────────────────────────

class MultiWindowOIF:
    """Three OnlineIsolationForest models at window sizes 256/1024/4096.

    Weighted composite score (0.20/0.30/0.50) gives the slow model majority
    influence, resisting poisoning by sustained floods. All three models share
    the same feature set and are kept in sync (learn_one / selective training
    applied identically).
    """

    _WINDOWS = (256, 1024, 4096)
    _WEIGHTS = (0.20, 0.30, 0.50)

    # Flows scoring at or above this threshold are withheld from training —
    # prevents attack traffic from shifting the model's definition of normal.
    # Set above threshold_high (0.60) so that borderline HIGH flows are still
    # trained on, preventing model drift when false positives occur.
    TRAIN_THRESHOLD = 0.72

    # Scale factor for the out-of-range (OOR) augmentation score.
    # OIF trees assign paths of maximum depth to points outside their training
    # bounding box, producing a score ≈ 0.5 that falls below TRAIN_THRESHOLD.
    # The OOR term catches this regime: oor_score = 1 - exp(-deviation/OOR_SCALE),
    # where deviation = max |x_scaled[i]| (L∞ norm in RobustScaler space, unit = IQR).
    # At OOR_SCALE=25: deviation ≥ 22.9 IQR → oor_score ≥ 0.60 (HIGH);
    #                  deviation ≥ 34.6 IQR → oor_score ≥ 0.75 (CRITICAL).
    # Volumetric floods deviate thousands of IQR on rate features — still CRITICAL.
    # Scale=10 was too aggressive: tight-IQR features (uniform baseline) triggered
    # false positives at 9 IQR, which is reachable by natural traffic variation.
    OOR_SCALE = 25.0

    # Save to disk every N trained flows so a mid-session restart loses at
    # most this many flows' worth of learned structure.
    _SAVE_INTERVAL = 200

    def __init__(self, feature_names: list[str], protocol: str,
                 baseline_flows: int | None = None,
                 save_path: str | Path | None = None) -> None:
        self.feature_names = feature_names
        self.protocol      = protocol
        self._save_path    = Path(save_path) if save_path else None

        self._models: list[OnlineIsolationForest] = [
            OnlineIsolationForest(
                feature_names=feature_names,
                n_trees=32,
                window_size=w,
                max_leaf_samples=8,
                seed=42 + i,
            )
            for i, w in enumerate(self._WINDOWS)
        ]

        # RobustScaler fitted during baselining. Uses median/IQR rather than
        # mean/std — less sensitive to extremes in the warmup period.
        self._scaler        = RobustScaler()
        self._scaler_fitted = False

        self._baseline_buffer:   list[np.ndarray] = []
        self._baseline_complete = False
        # TCP: wait for the slow window (4096) — continuous traffic makes this
        # achievable quickly. UDP: medium window (1024) — ensures both the fast
        # and medium models complete at least one full window cycle before
        # detection activates; sparse UDP traffic makes 4096 impractical.
        self.BASELINE_FLOWS = baseline_flows if baseline_flows is not None else self._WINDOWS[2]

        self._n_trained  = 0
        self._n_seen     = 0   # flows processed after baseline complete
        self._n_rejected = 0   # flows withheld from training (composite ≥ TRAIN_THRESHOLD)
        self._score_buf: deque[float] = deque(maxlen=500)  # rolling composite scores

    # ── baselining ────────────────────────────────────────────────────────────

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

        # Prevent zero-IQR collapse: sklearn sets scale_=1.0 when a feature
        # has zero IQR in the baseline (e.g., every flow has the same TCP window
        # size, or fwd_iat_std=0 for all 2-packet flows). Division by 1 raw unit
        # (milliseconds, bytes, pkts/s) produces enormous deviations for any
        # non-zero value, triggering false-positive OOR scores on every flow.
        #
        # Floors represent the expected natural IQR for each feature in normal
        # traffic — NOT just "above zero". Setting them too small defeats the
        # purpose: flow_duration_s floor=0.0005s means a 60ms HTTP flow deviates
        # 120 IQR (CRITICAL). Floors must cover the typical spread of the feature
        # across legitimate flows so that natural variation stays within 1-2 IQR.
        #
        # Time/IAT features: HTTP flows range 1ms–500ms duration, 1ms–100ms IAT.
        # Rate features: 1–50 pkts/s for normal interactive traffic.
        _FLOORS: dict[str, float] = {
            "fwd_pkts_per_sec":   1.0,    # pkts/s — 1 pkt/s spread is meaningful
            "bwd_pkts_per_sec":   1.0,    # pkts/s
            "pkt_len_mean":       4.0,    # bytes
            "pkt_len_std":        4.0,    # bytes
            "flow_duration_s":    0.05,   # 50 ms — covers HTTP 1ms–500ms range
            "flow_iat_mean":      10.0,   # ms — covers typical HTTP IAT spread
            "fwd_iat_std":        5.0,    # ms
            "init_fwd_win_bytes": 64.0,   # bytes
            "syn_flag_ratio":     0.02,
            "fwd_act_data_ratio": 0.02,
            "down_up_ratio":      0.02,
            "bwd_pkt_len_max":    4.0,    # bytes
        }
        for i, name in enumerate(self.feature_names):
            floor = _FLOORS.get(name, 1.0)
            if self._scaler.scale_[i] < floor:
                log.info("[%s OIF] scale floor applied: %s  %.4g → %.4g",
                         self.protocol, name, self._scaler.scale_[i], floor)
                self._scaler.scale_[i] = floor

        # Seed each model on the tail of the baseline corpus — only the last
        # window_size flows matter because the OIF sliding window evicts older
        # points as new ones arrive. Seeding 4096 flows into a 256-window model
        # performs 3840 wasted learn+unlearn cycles; seeding only the tail 256
        # gives identical final tree state in 16× less work. This keeps the
        # seeding step from blocking Thread 2 for several minutes.
        X_scaled = np.array([
            self._scaler.transform(raw.reshape(1, -1))[0]
            for raw in self._baseline_buffer
        ])
        for model, window_size in zip(self._models, self._WINDOWS):
            tail = X_scaled[-window_size:]
            for x_scaled_row in tail:
                x_dict = _to_oif_dict(x_scaled_row, self.feature_names)
                model.learn_one(x_dict)

        self._baseline_complete = True
        self._baseline_buffer.clear()
        log.info("[%s OIF] Baseline complete on %d flows — detection active",
                 self.protocol, self.BASELINE_FLOWS)
        self.save()

    # ── persistence ───────────────────────────────────────────────────────────

    def save(self) -> None:
        """Pickle the detector to _save_path. No-op if no path was set."""
        if self._save_path is None:
            return
        try:
            self._save_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._save_path.with_suffix(".pkl.tmp")
            with open(tmp, "wb") as f:
                pickle.dump(self, f, protocol=pickle.HIGHEST_PROTOCOL)
            tmp.replace(self._save_path)
            log.debug("[%s OIF] Saved to %s (%d trained)",
                      self.protocol, self._save_path, self._n_trained)
        except Exception:
            log.warning("[%s OIF] Failed to save model", self.protocol, exc_info=True)

    @classmethod
    def load(cls, path: str | Path) -> "MultiWindowOIF":
        """Load a pickled detector. Raises on any error — caller handles fallback."""
        with open(path, "rb") as f:
            obj = pickle.load(f)
        if not isinstance(obj, cls):
            raise TypeError(f"Expected MultiWindowOIF, got {type(obj)}")
        return obj

    def _compatible_with(self, feature_names: list[str]) -> bool:
        return self.feature_names == feature_names

    # ── inference ─────────────────────────────────────────────────────────────

    def process(self, raw: np.ndarray) -> tuple[WindowScores, list[dict]] | None:
        """Score a flow. Returns None during baselining.

        After baselining: returns (WindowScores, top-3 attribution list).
        Flows scoring below TRAIN_THRESHOLD are trained on; high-scoring
        flows are withheld to prevent poisoning.
        """
        if not self._baseline_complete:
            self._baseline_buffer.append(raw)
            if len(self._baseline_buffer) >= self.BASELINE_FLOWS:
                self._complete_baseline()
            return None

        x_scaled      = self._scaler.transform(raw.reshape(1, -1))[0]
        max_deviation = float(np.max(np.abs(x_scaled)))
        oor_score     = 1.0 - math.exp(-max_deviation / self.OOR_SCALE)

        if oor_score >= 0.55 or log.isEnabledFor(logging.DEBUG):
            # Log which feature is driving the OOR score — essential for
            # diagnosing false positives. At INFO level only fires when oor
            # is near-threshold; at DEBUG level fires for every flow.
            worst_i   = int(np.argmax(np.abs(x_scaled)))
            worst_dev = float(np.abs(x_scaled[worst_i]))
            log.debug("[%s OIF] oor=%.3f worst=%s dev=%.1f IQR",
                      self.protocol, oor_score,
                      self.feature_names[worst_i], worst_dev)

        if oor_score >= self.TRAIN_THRESHOLD:
            # Fast path: extreme outlier determined by the OOR term alone.
            # Skip the 96-tree OIF traversal — it adds nothing for points this
            # far outside the training bounding box, and avoiding it keeps
            # queue drain time low during flood bursts (~0.3ms vs ~8ms per flow).
            # Attribution is a single out-of-range entry naming the worst feature.
            composite  = oor_score
            worst_feat = self.feature_names[int(np.argmax(np.abs(x_scaled)))]
            window_scores = WindowScores(fast=oor_score, medium=oor_score,
                                         slow=oor_score, composite=oor_score)
            attribution = [{
                "feature":  worst_feat,
                "score":    1.0,
                "value":    float(raw[self.feature_names.index(worst_feat)]),
                "baseline": self.baseline_stats().get(worst_feat, {}),
            }]
        else:
            # Normal path: full OIF scoring + path-depth attribution.
            x_dict    = _to_oif_dict(x_scaled, self.feature_names)
            scores    = tuple(m.score_one(x_dict) for m in self._models)
            composite = max(sum(w * s for w, s in zip(self._WEIGHTS, scores)), oor_score)
            window_scores = WindowScores(
                fast=scores[0], medium=scores[1], slow=scores[2],
                composite=composite,
            )
            attribution = self._attribute(x_dict, raw)

        self._n_seen += 1
        self._score_buf.append(composite)

        if composite < self.TRAIN_THRESHOLD:
            # Only reachable via the normal path — x_dict is defined.
            for model in self._models:
                model.learn_one(x_dict)
            self._n_trained += 1
            if self._n_trained % self._SAVE_INTERVAL == 0:
                self.save()
        else:
            self._n_rejected += 1

        return window_scores, attribution, oor_score

    # ── path-depth attribution ─────────────────────────────────────────────────

    def _attribute(
        self,
        x_dict: dict[str, float],
        x_raw:  np.ndarray,
    ) -> list[dict]:
        """Depth-weighted attribution over all trees and all window models.

        Splits in OIF trees are chosen from the actual observed data range —
        unlike HST's random half-spaces, they reflect real traffic structure.
        A feature that appears at depth 0 (root) isolated this flow from all
        baseline traffic in a single cut; depth 3 means four cuts were needed.

        Model weights (0.20/0.30/0.50) are applied so the slow model's trees
        dominate — matching their dominance in the composite score.
        """
        feat_scores: dict[str, float] = defaultdict(float)

        for model, model_weight in zip(self._models, self._WEIGHTS):
            model.attribute(x_dict, model_weight, feat_scores)

        total  = sum(feat_scores.values()) or 1.0
        ranked = sorted(feat_scores.items(), key=lambda kv: kv[1], reverse=True)

        stats = self.baseline_stats()
        return [
            {
                "feature":  name,
                "score":    score / total,
                "value":    float(x_raw[self.feature_names.index(name)]),
                "baseline": stats.get(name, {}),
            }
            for name, score in ranked[:3]
        ]

    # ── health metrics ─────────────────────────────────────────────────────────

    def metrics(self) -> dict:
        """Runtime health metrics for the dashboard Model Health panel.

        rejection_rate rising during an attack means the poisoning defence is
        working — anomalous flows are being withheld from training. A falling
        rate after an attack ends reflects the slow window forgetting the attack
        distribution and returning to normal.
        """
        buf = list(self._score_buf)
        arr = np.array(buf) if buf else np.array([0.0])
        return {
            "n_seen":         self._n_seen,
            "n_trained":      self._n_trained,
            "n_rejected":     self._n_rejected,
            "rejection_rate": self._n_rejected / max(self._n_seen, 1),
            "score_p50":      float(np.percentile(arr, 50)),
            "score_p95":      float(np.percentile(arr, 95)),
            "score_recent":   buf[-20:],   # last 20 scores for sparkline
        }

    # ── baseline statistics for dashboard context ──────────────────────────────

    def baseline_stats(self) -> dict[str, dict[str, float]]:
        """Median and IQR per feature from the fitted RobustScaler.

        Used by the dashboard to show 'value: X  baseline: Y ± Z'
        next to each attribution bar.
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
# One per protocol, shared across inference calls from the single worker thread.
# On startup, try to load a previously saved model so baselining is skipped.
# If the saved file is absent, corrupt, or was built on a different feature set,
# fall back to a fresh instance silently.

_MODEL_DIR = Path("/app/models")


def _load_or_create(
    feature_names: list[str],
    protocol: str,
    filename: str,
    baseline_flows: int | None = None,
) -> "MultiWindowOIF":
    path = _MODEL_DIR / filename
    if path.exists():
        try:
            detector = MultiWindowOIF.load(path)
            if detector._compatible_with(feature_names):
                # Overwrite the pickled path with the current one — in case
                # the models dir differs across environments.
                detector._save_path = path
                log.info("[%s OIF] Loaded saved model from %s (%d trained, baseline=%s)",
                         protocol, path, detector._n_trained,
                         "complete" if detector.is_ready else "incomplete")
                return detector
            log.warning("[%s OIF] Saved model has different feature set — starting fresh", protocol)
        except Exception:
            log.warning("[%s OIF] Could not load %s — starting fresh", protocol, path, exc_info=True)

    return MultiWindowOIF(feature_names, protocol=protocol,
                          baseline_flows=baseline_flows, save_path=path)


tcp_detector = _load_or_create(TCP_IF_FEATURE_NAMES, "TCP", "tcp_oif.pkl")
udp_detector = _load_or_create(UDP_IF_FEATURE_NAMES, "UDP", "udp_oif.pkl",
                                baseline_flows=_cfg_module.cfg.baseline_udp)


def reset_detector(protocol: str) -> None:
    """Discard a trained detector and start fresh baselining.

    Deletes the persisted pkl so the next startup also starts clean.
    Called when the analyst triggers 'Reset baseline' from the dashboard —
    useful after clearing an attack to prevent attack flows from polluting
    the baseline going forward.
    """
    global tcp_detector, udp_detector
    cfg = _cfg_module.cfg

    if protocol in ("TCP", "all"):
        pkl = _MODEL_DIR / "tcp_oif.pkl"
        if pkl.exists():
            pkl.unlink()
        tcp_detector = MultiWindowOIF(
            TCP_IF_FEATURE_NAMES, protocol="TCP", save_path=pkl,
        )
        log.info("[TCP OIF] Baseline reset — re-baselining on %d flows", cfg.baseline_tcp)

    if protocol in ("UDP", "all"):
        pkl = _MODEL_DIR / "udp_oif.pkl"
        if pkl.exists():
            pkl.unlink()
        udp_detector = MultiWindowOIF(
            UDP_IF_FEATURE_NAMES, protocol="UDP",
            baseline_flows=cfg.baseline_udp, save_path=pkl,
        )
        log.info("[UDP OIF] Baseline reset — re-baselining on %d flows", cfg.baseline_udp)


def process_flow(flow: dict) -> dict | None:
    """Entry point: extract features, run MultiWindowOIF, return result dict.

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

    scores, attribution, oor_score = result

    # Read thresholds from the live config — analyst can adjust via dashboard
    # without restarting the inference engine.
    cfg = _cfg_module.cfg
    if scores.composite >= cfg.threshold_critical:
        severity = "CRITICAL"
    elif scores.composite >= cfg.threshold_high:
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
            "oor":       oor_score,   # out-of-range component; dominates for floods/scans
        },
        "verdict":     severity,
        "attribution": attribution,
    }
