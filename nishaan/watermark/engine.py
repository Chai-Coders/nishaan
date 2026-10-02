"""High-level watermark API: plan -> embed -> extract -> decode -> accuse."""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .extract import Extraction, extract_raster, extract_vector
from .pdftext import rewrite
from .plan import Plan, make_plan
from .render import load_image, render_pdf
from .tardos import SCHEME, FingerprintCode, choose_code_length

DEFAULT_DELTA_PT = 0.35       # word displacement (points); invisible, survives screenshots
SYMBOL_THRESHOLD = 0.35       # |mean soft value| below this -> erasure


def code_for(doc_secret: bytes, plan: Plan, code_len: int | None = None) -> FingerprintCode:
    return FingerprintCode(doc_secret, code_len or choose_code_length(len(plan.slots)))


def shifts_for(plan: Plan, code: FingerprintCode, session_seed: bytes, delta: float) -> dict[int, float]:
    x = code.codeword(session_seed)
    pos = code.assignment(len(plan.slots))
    return {s.wid: (delta if x[pos[j]] else -delta) for j, s in enumerate(plan.slots)}


def embed(pdf_bytes: bytes, plan: Plan, code: FingerprintCode, session_seed: bytes,
          delta: float = DEFAULT_DELTA_PT) -> bytes:
    out, _ = rewrite(pdf_bytes, "embed", shifts_for(plan, code, session_seed, delta))
    return out


@dataclass
class Symbols:
    y: np.ndarray            # 1 / 0 / -1 (erased) per codeword position
    strength: np.ndarray     # |mean soft value| per position
    m_eff: int

    def summary(self) -> dict:
        return {"code_length": int(len(self.y)), "positions_read": int(self.m_eff),
                "erased": int((self.y == -1).sum())}


def decode(ext: Extraction, code: FingerprintCode) -> Symbols:
    pos = code.assignment(len(ext.values))
    v = np.clip(ext.values, -2.0, 2.0)
    ok = ~np.isnan(v)
    sums = np.bincount(pos[ok], weights=v[ok], minlength=code.m)
    cnt = np.bincount(pos[ok], minlength=code.m)
    mean = np.where(cnt > 0, sums / np.maximum(cnt, 1), 0.0)
    y = np.full(code.m, -1, dtype=np.int8)
    y[mean > SYMBOL_THRESHOLD] = 1
    y[mean < -SYMBOL_THRESHOLD] = 0
    y[cnt == 0] = -1
    return Symbols(y, np.abs(mean), int((y != -1).sum()))


def accuse(sym: Symbols, code: FingerprintCode, candidates: dict[str, bytes], eps: float = 1e-6) -> dict:
    """Score every candidate session; accuse those above the eps-threshold."""
    z = code.threshold_for(sym.y, eps)
    rows = []
    for sid, seed in candidates.items():
        x = code.codeword(seed)
        sc = code.score(sym.y, x)
        read = sym.y != -1
        agree = float((x[read] == sym.y[read]).mean()) if read.any() else 0.0
        rows.append({"session_id": sid, "score": round(sc, 2), "accused": sc > z,
                     "bit_agreement": round(agree, 4),
                     "false_positive_bound": code.tail_bound(sym.y, sc)})
    rows.sort(key=lambda r: -r["score"])
    return {"threshold": round(z, 2), "eps": eps, "m_eff": sym.m_eff, "code_length": code.m,
            "candidates": rows, "accused": [r["session_id"] for r in rows if r["accused"]]}


def extract_any(data: bytes, filename: str, original_pdf: bytes, plan: Plan, delta: float) -> Extraction:
    """Choose the vector path for PDFs with a usable text layer, raster otherwise."""
    name = filename.lower()
    if name.endswith(".pdf") or data[:5] == b"%PDF-":
        try:
            ext = extract_vector(data, plan, delta)
            if ext.measured >= max(20, len(plan.slots) // 10):
                return ext
        except Exception:
            pass
        return extract_raster(render_pdf(data, 200), original_pdf, plan, delta)
    return extract_raster([load_image(data)], original_pdf, plan, delta)


__all__ = ["DEFAULT_DELTA_PT", "SCHEME", "make_plan", "code_for", "embed", "decode", "accuse",
           "extract_any", "extract_vector", "extract_raster", "Plan"]
