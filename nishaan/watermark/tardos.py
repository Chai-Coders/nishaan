"""Collusion-resistant fingerprinting with symmetric Tardos codes.

Each decryption session gets a binary codeword X (length m). Bit i is drawn
from Bernoulli(p_i), with the secret per-document biases p_i following the
arcsine distribution on [t, 1-t], t = 1/(300c).

Accusation (Skoric et al. symmetric score), for extracted symbols y_i:

    y=1:  x=1 -> +sqrt((1-p)/p)      x=0 -> -sqrt(p/(1-p))
    y=0:  x=0 -> +sqrt(p/(1-p))      x=1 -> -sqrt((1-p)/p)

For an innocent user every term has mean 0 and variance 1 independently of
what the colluders did (their codeword is independent of the leaked copy), so
the false-accusation probability is bounded rigorously by a Chernoff bound
computed from the exact per-position distributions; colluders' scores sum to
~2m/pi under the marking assumption, so at least one colluder is accused.
Erased positions (unreadable, or mixed by averaging) are simply skipped.
"""
from __future__ import annotations

import math

import numpy as np
from scipy.optimize import minimize_scalar

from ..crypto.sym import shake

SCHEME = "nishaan-wordshift-tardos/v1"


def _uniform(key: bytes, label: bytes, n: int) -> np.ndarray:
    raw = shake(b"nishaan/tardos/" + label + b"/" + key, 8 * n)
    ints = np.frombuffer(raw, dtype=">u8").astype(np.uint64) >> np.uint64(11)
    return ints.astype(np.float64) / float(1 << 53)


class FingerprintCode:
    def __init__(self, doc_secret: bytes, m: int, c: int = 2):
        self.secret = doc_secret
        self.m = int(m)
        self.c = int(c)
        self.t = 1.0 / (300.0 * self.c)
        tp = math.asin(math.sqrt(self.t))
        r = tp + (math.pi / 2 - 2 * tp) * _uniform(doc_secret, b"bias", self.m)
        self.p = np.sin(r) ** 2
        self.g1 = np.sqrt((1 - self.p) / self.p)   # weight when symbols agree on the rarer side
        self.g0 = np.sqrt(self.p / (1 - self.p))
        self.bound = math.sqrt((1 - self.t) / self.t)

    def codeword(self, session_seed: bytes) -> np.ndarray:
        u = _uniform(self.secret + session_seed, b"codeword", self.m)
        return (u < self.p).astype(np.int8)

    def assignment(self, n_slots: int) -> np.ndarray:
        """Keyed interleaving: slot j carries codeword position pos[j]."""
        order = np.argsort(_uniform(self.secret, b"interleave", n_slots), kind="stable")
        pos = np.empty(n_slots, dtype=np.int64)
        pos[order] = np.arange(n_slots) % self.m
        return pos

    def score(self, y: np.ndarray, x: np.ndarray) -> float:
        """y in {1, 0, -1 (erased)}; x in {0,1}."""
        s = np.where(y == 1, np.where(x == 1, self.g1, -self.g0),
                     np.where(y == 0, np.where(x == 0, self.g0, -self.g1), 0.0))
        return float(s.sum())

    # ------------------------------------------------------------------ rigorous error bounds
    def _innocent_terms(self, y: np.ndarray):
        """Per read position, the two-point distribution of an innocent user's score term."""
        read = y != -1
        p, yy = self.p[read], y[read]
        g1, g0 = self.g1[read], self.g0[read]
        v_hi = np.where(yy == 1, g1, g0)          # innocent happens to carry the leaked symbol
        q_hi = np.where(yy == 1, p, 1 - p)
        v_lo = np.where(yy == 1, -g0, -g1)
        return v_hi, q_hi, v_lo

    def tail_bound(self, y: np.ndarray, score: float) -> float:
        """Chernoff bound on P(innocent score >= score), exact per-position MGFs (rigorous:
        an innocent codeword is independent of the leaked copy, bits ~ Bernoulli(p_i))."""
        if score <= 0:
            return 1.0
        v_hi, q_hi, v_lo = self._innocent_terms(y)
        if len(v_hi) == 0:
            return 1.0
        lq_hi, lq_lo = np.log(q_hi), np.log1p(-q_hi)

        def f(lam):
            return float(np.logaddexp(lq_hi + lam * v_hi, lq_lo + lam * v_lo).sum() - lam * score)

        r = minimize_scalar(f, bounds=(0.0, 20.0), method="bounded", options={"xatol": 1e-6})
        return float(min(1.0, math.exp(min(0.0, r.fun))))

    def threshold_for(self, y: np.ndarray, eps: float) -> float:
        """Smallest score whose innocent-tail bound is <= eps (bisection)."""
        v_hi, _, _ = self._innocent_terms(y)
        lo, hi = 0.0, float(v_hi.sum()) + 1.0
        if self.tail_bound(y, hi) > eps:
            return float("inf")
        for _ in range(60):
            mid = (lo + hi) / 2
            if self.tail_bound(y, mid) <= eps:
                hi = mid
            else:
                lo = mid
        return hi


def choose_code_length(n_slots: int, c: int = 2) -> int:
    """Use every slot, aiming for ~2x repetition, within [64, 512]."""
    return int(max(64, min(512, n_slots // 2)))
