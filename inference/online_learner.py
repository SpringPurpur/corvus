# online_learner.py — GaussianNB partial_fit on analyst feedback.
#
# When an analyst corrects a label via the dashboard, the corrected flow
# features are fed into a GaussianNB classifier that learns incrementally.
# This provides a lightweight correction layer on top of the static pkl models.
#
# The online model is not used for primary inference — it supplements the
# main classifier and its predictions are logged for analysis.

import logging
from typing import Any

import numpy as np
from sklearn.naive_bayes import GaussianNB

log = logging.getLogger(__name__)


class OnlineLearner:
    def __init__(self) -> None:
        self._model = GaussianNB()
        self._n_samples = 0

    def update(self, features: list[float], label: str) -> None:
        """Incrementally train on a single corrected flow.

        features — the same feature vector used for primary inference.
        label    — the analyst-corrected class label string.
        """
        X = np.array([features], dtype=np.float64)
        y = np.array([label])
        self._model.partial_fit(X, y)
        self._n_samples += 1
        log.info("OnlineLearner updated: label=%s n_samples=%d", label, self._n_samples)

    def predict(self, features: list[float]) -> tuple[str, float] | None:
        """Return (label, confidence) if the online model has enough data, else None.

        Requires at least 2 distinct classes before making predictions.
        """
        if self._n_samples < 2:
            return None
        X = np.array([features], dtype=np.float64)
        try:
            label = self._model.predict(X)[0]
            proba = self._model.predict_proba(X)[0]
            confidence = float(np.max(proba))
            return str(label), confidence
        except Exception as exc:
            log.warning("OnlineLearner predict failed: %s", exc)
            return None
