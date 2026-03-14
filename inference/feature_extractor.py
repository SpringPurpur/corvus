# feature_extractor.py — maps flow_dict fields to model feature vectors.
#
# Feature names must match exactly what the models were trained on — a name
# mismatch silently produces wrong predictions, not an error. The order of
# entries in TCP_FEATURES / UDP_FEATURES defines the column order of the
# numpy array passed to predict_proba.

import numpy as np

# ── TCP feature set (8 features) ─────────────────────────────────────────────

TCP_FEATURES: list[tuple[str, callable]] = [
    ("Init Fwd Win Byts", lambda r: r["init_fwd_win_bytes"]),
    ("Fwd Seg Size Min",  lambda r: r["fwd_seg_size_min"]),
    ("RST Flag Cnt",      lambda r: r["rst_flag_cnt"]),
    ("Bwd Pkt Len Std",   lambda r: r["bwd_pkt_len_std"]),
    ("Fwd Act Data Pkts", lambda r: r["fwd_act_data_pkts"]),
    ("PSH Flag Cnt",      lambda r: r["psh_flag_cnt"]),
    ("Bwd Pkts/s",        lambda r: r["bwd_pkts_per_sec"]),
    ("Pkt Len Mean",      lambda r: r["pkt_len_mean"]),
]

# ── UDP feature set (8 features) ─────────────────────────────────────────────

UDP_FEATURES: list[tuple[str, callable]] = [
    ("TotLen Fwd Pkts", lambda r: r["tot_fwd_bytes"]),
    ("Tot Fwd Pkts",    lambda r: r["tot_fwd_pkts"]),
    ("Fwd Pkt Len Max", lambda r: r["fwd_pkt_len_max"]),
    ("Down/Up Ratio",   lambda r: r["tot_bwd_bytes"] / max(r["tot_fwd_bytes"], 1)),
    ("Flow Duration",   lambda r: r["flow_duration_s"]),
    ("Flow IAT Mean",   lambda r: r["flow_iat_mean"]),
    ("Fwd IAT Std",     lambda r: r["fwd_iat_std"]),
    ("Bwd Pkts/s",      lambda r: r["bwd_pkts_per_sec"]),
]

TCP_FEATURE_NAMES = [name for name, _ in TCP_FEATURES]
UDP_FEATURE_NAMES = [name for name, _ in UDP_FEATURES]


def extract_tcp(flow: dict) -> np.ndarray:
    """Return a (1, 8) float32 array for the TCP model."""
    return np.array([[fn(flow) for _, fn in TCP_FEATURES]], dtype=np.float32)


def extract_udp(flow: dict) -> np.ndarray:
    """Return a (1, 8) float32 array for the UDP model."""
    return np.array([[fn(flow) for _, fn in UDP_FEATURES]], dtype=np.float32)
