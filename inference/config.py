# config.py — runtime configuration with persistence.
#
# Settings are loaded from /app/config.json on startup. If the file is absent
# (first run) defaults are used. The analyst can update settings via the
# dashboard settings panel; changes are written atomically and take effect
# immediately without a restart.
#
# Only analyst-facing parameters live here. Internal OIF parameters
# (n_trees, window sizes, max_leaf_samples) are not exposed — they are
# algorithm design choices, not operational knobs.

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path

log = logging.getLogger(__name__)

_CONFIG_PATH = Path("/app/config.json")


@dataclass
class AppConfig:
    # Alert severity thresholds — OIF composite score (0–1).
    # Raise to reduce false positives; lower to catch more marginal anomalies.
    # threshold_critical raised 0.75 → 0.80 to match TRAIN_THRESHOLD (0.80):
    # flows the model refuses to train on are the same flows shown as CRITICAL.
    threshold_high:     float = 0.60
    threshold_critical: float = 0.80

    # Flows required before detection activates per protocol.
    # TCP can tolerate the larger value because HTTP/SSH traffic is continuous.
    # UDP is sparse so the medium window (1024) is the practical limit.
    baseline_tcp: int = 4096
    baseline_udp: int = 1024


def _load(path: Path) -> AppConfig:
    if not path.exists():
        return AppConfig()
    try:
        data = json.loads(path.read_text())
        fields = AppConfig.__dataclass_fields__
        return AppConfig(**{k: v for k, v in data.items() if k in fields})
    except Exception:
        log.warning("Could not load config from %s — using defaults", path, exc_info=True)
        return AppConfig()


def save(cfg: "AppConfig", path: Path = _CONFIG_PATH) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(asdict(cfg), indent=2))
        tmp.replace(path)
        log.debug("Config saved to %s", path)
    except Exception:
        log.warning("Could not save config to %s", path, exc_info=True)


# Module-level singleton — imported by other modules.
cfg: AppConfig = _load(_CONFIG_PATH)


def update(new_cfg: AppConfig) -> None:
    """Replace the runtime config and persist to disk."""
    global cfg
    cfg = new_cfg
    save(cfg)