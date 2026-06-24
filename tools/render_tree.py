#!/usr/bin/env python3
"""render_tree.py - Render an OIF tree from a saved pkl file or live endpoint.

Usage (pkl — no app needed):
    python tools/render_tree.py --pkl inference/models/tcp_oif.pkl
    python tools/render_tree.py --pkl inference/models/udp_oif.pkl --model 1 --tree 3

Usage (live endpoint — app must be running):
    python tools/render_tree.py --proto TCP --model 2 --tree 0

Common options:
    --model {0,1,2}    Window: 0=fast(256), 1=medium(1024), 2=slow(4096)  (default: 2)
    --tree N           Tree index 0-31 (default: 0)
    --depth N          Max depth to render (default: 4)
    --out FILE         Output PNG path (default: oif_tree.png)

Requires: pip install graphviz
          sudo dnf install graphviz   (or apt/brew equivalent)
For live mode also: pip install requests
"""

import argparse
import os
import pickle
import sys
from pathlib import Path

try:
    import graphviz
except ImportError:
    sys.exit("pip install graphviz")


WINDOW_LABELS = {0: "Fast (256)", 1: "Medium (1024)", 2: "Slow (4096)"}

COL_SPLIT_FILL   = "#1e3a5f"
COL_SPLIT_STROKE = "#93c4e0"
COL_LEAF_FILL    = "#1b4332"
COL_LEAF_STROKE  = "#95d5b2"
COL_BG           = "#0d1117"
COL_EDGE         = "#adb5bd"
COL_FONT         = "#ffffff"
COL_EDGE_L       = "#52b788"
COL_EDGE_R       = "#e63946"


# ── pkl loading ──────────────────────────────────────────────────────────────

def load_from_pkl(pkl_path: str, model: int, tree: int, max_depth: int) -> dict:
    """Unpickle a MultiWindowOIF and extract a tree snapshot dict."""
    # Make inference/ importable so pickle can resolve class definitions
    repo_root = Path(__file__).resolve().parent.parent
    inf_dir   = str(repo_root / "inference")
    if inf_dir not in sys.path:
        sys.path.insert(0, inf_dir)

    with open(pkl_path, "rb") as f:
        det = pickle.load(f)

    oif = det._models[model]
    if tree >= len(oif._trees):
        sys.exit(f"tree {tree} out of range (n_trees={len(oif._trees)})")

    t = oif._trees[tree]
    if t._root < 0:
        sys.exit("Tree not initialised — pkl was saved before baseline completed")

    feat_names = oif.feature_names

    def _dump(node_id: int) -> dict:
        if node_id < 0:
            return {"type": "leaf", "samples": 0}
        h  = int(t._h[node_id])
        d  = int(t._depth[node_id])
        fi = int(t._feat_idx[node_id])
        if fi < 0 or d >= max_depth:
            return {"type": "leaf", "samples": h, "depth": d}
        return {
            "type":      "split",
            "feature":   feat_names[fi],
            "threshold": round(float(t._threshold[node_id]), 6),
            "samples":   h,
            "depth":     d,
            "left":      _dump(int(t._left[node_id])),
            "right":     _dump(int(t._right[node_id])),
        }

    # Infer protocol from filename
    stem  = Path(pkl_path).stem            # e.g. "tcp_oif"
    proto = "TCP" if "tcp" in stem.lower() else "UDP"

    return {
        "proto":       proto,
        "model":       model,
        "window_size": det._WINDOWS[model],
        "tree_index":  tree,
        "max_depth":   max_depth,
        "n_trained":   det._n_trained,
        "tree":        _dump(t._root),
    }


# ── live endpoint loading ─────────────────────────────────────────────────────

def fetch_snapshot(host, port, key, proto, model, tree, depth) -> dict:
    try:
        import requests
    except ImportError:
        sys.exit("pip install requests  (needed for live-endpoint mode)")

    url     = f"http://{host}:{port}/dev/tree_snapshot"
    params  = dict(proto=proto, model=model, tree=tree, max_depth=depth)
    headers = {"X-API-Key": key} if key else {}
    r = requests.get(url, params=params, headers=headers, timeout=10)
    if r.status_code == 503:
        sys.exit(f"503 — {r.json().get('detail', 'detector not ready')}")
    r.raise_for_status()
    return r.json()


# ── graphviz rendering ────────────────────────────────────────────────────────

def add_node(dot: graphviz.Digraph, node: dict, parent_id: str | None,
             edge_label: str, counter: list) -> str:
    nid = f"n{counter[0]}"
    counter[0] += 1

    if node["type"] == "split":
        thr = node["threshold"]
        thr_s = f"{thr:.3e}" if abs(thr) > 0 and (abs(thr) >= 1e4 or abs(thr) < 0.01) \
                else f"{thr:.4g}"
        label = (
            f"<<TABLE BORDER='0' CELLBORDER='0' CELLSPACING='2'>"
            f"<TR><TD><FONT POINT-SIZE='11'><B>{node['feature']}</B></FONT></TD></TR>"
            f"<TR><TD><FONT POINT-SIZE='10' COLOR='{COL_SPLIT_STROKE}'>≤ {thr_s}</FONT></TD></TR>"
            f"<TR><TD><FONT POINT-SIZE='9' COLOR='{COL_EDGE}'>n = {node['samples']}</FONT></TD></TR>"
            f"</TABLE>>"
        )
        dot.node(nid, label=label, shape="box", style="filled,rounded",
                 fillcolor=COL_SPLIT_FILL, color=COL_SPLIT_STROKE,
                 fontcolor=COL_FONT, fontname="Helvetica")
    else:
        label = (
            f"<<TABLE BORDER='0' CELLBORDER='0' CELLSPACING='1'>"
            f"<TR><TD><FONT POINT-SIZE='10' COLOR='{COL_LEAF_STROKE}'><B>leaf</B></FONT></TD></TR>"
            f"<TR><TD><FONT POINT-SIZE='9' COLOR='{COL_EDGE}'>n = {node.get('samples', 0)}</FONT></TD></TR>"
            f"</TABLE>>"
        )
        dot.node(nid, label=label, shape="box", style="filled,rounded",
                 fillcolor=COL_LEAF_FILL, color=COL_LEAF_STROKE,
                 fontcolor=COL_FONT, fontname="Helvetica")

    if parent_id is not None:
        col = COL_EDGE_L if edge_label == "≤" else COL_EDGE_R
        dot.edge(parent_id, nid, label=f" {edge_label}",
                 color=col, fontcolor=col, fontsize="9", fontname="Helvetica")

    if node["type"] == "split":
        add_node(dot, node["left"],  nid, "≤", counter)
        add_node(dot, node["right"], nid, ">", counter)

    return nid


def render(snapshot: dict, out_path: str) -> None:
    proto  = snapshot["proto"]
    window = WINDOW_LABELS[snapshot["model"]]
    tidx   = snapshot["tree_index"]
    ntrain = snapshot["n_trained"]
    mdepth = snapshot["max_depth"]

    title = (
        f"{proto} — OIF tree #{tidx} | window: {window} | "
        f"n_trained: {ntrain} | shown depth: 0–{mdepth - 1}"
    )

    dot = graphviz.Digraph(name="oif_tree", comment=title, format="png")
    dot.attr(rankdir="TB", bgcolor=COL_BG,
             label=f"<<FONT COLOR='{COL_EDGE}' POINT-SIZE='11'>{title}</FONT>>",
             labelloc="t", fontname="Helvetica", nodesep="0.4", ranksep="0.6")

    add_node(dot, snapshot["tree"], parent_id=None, edge_label="", counter=[0])

    base = out_path.removesuffix(".png")
    dot.render(base, cleanup=True)
    print(f"Saved: {out_path}")


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pkl",   default=None,
                   help="Path to tcp_oif.pkl or udp_oif.pkl (no app needed)")
    p.add_argument("--host",  default="localhost")
    p.add_argument("--port",  default=8765, type=int)
    p.add_argument("--key",   default=os.environ.get("CORVUS_API_KEY", ""))
    p.add_argument("--proto", default="TCP", choices=["TCP", "UDP"],
                   help="Used only in live-endpoint mode")
    p.add_argument("--model", default=2, type=int, choices=[0, 1, 2])
    p.add_argument("--tree",  default=0, type=int)
    p.add_argument("--depth", default=4, type=int)
    p.add_argument("--out",   default="oif_tree.png")
    args = p.parse_args()

    if args.pkl:
        print(f"Loading {args.pkl} — model={WINDOW_LABELS[args.model]}, "
              f"tree={args.tree}, depth≤{args.depth} …")
        snapshot = load_from_pkl(args.pkl, args.model, args.tree, args.depth)
    else:
        print(f"Fetching {args.proto} tree #{args.tree} "
              f"(model={WINDOW_LABELS[args.model]}, depth≤{args.depth}) …")
        snapshot = fetch_snapshot(args.host, args.port, args.key,
                                  args.proto, args.model, args.tree, args.depth)

    render(snapshot, args.out)


if __name__ == "__main__":
    main()