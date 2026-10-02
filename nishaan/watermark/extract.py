"""Watermark extraction from leaked copies.

Extraction is *informed*: the forensic authority holds the original document,
so every measurement is relative to the original geometry.

* Vector path (leaked PDF with a text layer): word sequences are aligned with
  the original, a global affine transform (re-saving, re-pagination scaling,
  "print to PDF") is fitted on all glyphs, and each word's residual offset
  along its baseline is its symbol.
* Raster path (screenshot, phone photo, scan, image-only PDF): the image is
  registered to a render of the original (SIFT + RANSAC homography, refined with
  ECC), then each word's sub-pixel shift is estimated with Lucas-Kanade on the
  word patch. Never-shifted anchor words calibrate residual registration error.

Both return one soft value per slot: ~+1 / -1 for a +delta / -delta shift,
NaN when the word could not be measured (cropped, occluded, missing page).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from difflib import SequenceMatcher

import cv2
import numpy as np

from .plan import Plan, Slot, leaked_words
from .render import render_pdf

RASTER_DPI = 200.0


@dataclass
class Extraction:
    values: np.ndarray                 # per-slot soft symbol (shift / delta), NaN if unmeasured
    method: str
    pages: dict = field(default_factory=dict)   # diagnostics per leaked page
    measured: int = 0

    def summary(self) -> dict:
        v = self.values[~np.isnan(self.values)]
        return {"method": self.method, "slots": int(len(self.values)), "measured": int(len(v)),
                "mean_abs": round(float(np.mean(np.abs(v))), 3) if len(v) else None, "pages": self.pages}


# ============================================================================ vector

def _shingles(words: list[str]) -> set:
    s = "".join(w.lower() for w in words)
    return {s[i:i + 5] for i in range(max(0, len(s) - 4))}


def _robust_affine(src: np.ndarray, dst: np.ndarray, iters: int = 4):
    """Least-squares affine dst ~ A @ [src,1] with outlier rejection."""
    keep = np.ones(len(src), bool)
    A = None
    for _ in range(iters):
        if keep.sum() < 6:
            return None, keep
        X = np.hstack([src[keep], np.ones((keep.sum(), 1))])
        A, *_ = np.linalg.lstsq(X, dst[keep], rcond=None)
        res = np.linalg.norm(np.hstack([src, np.ones((len(src), 1))]) @ A - dst, axis=1)
        med = np.median(res[keep])
        mad = np.median(np.abs(res[keep] - med)) + 1e-6
        new = res < max(med + 6 * mad, 4 * 0.5)
        if np.array_equal(new, keep):
            break
        keep = new
    return A, keep


def extract_vector(leaked_pdf: bytes, plan: Plan, delta: float) -> Extraction:
    words = leaked_words(leaked_pdf)
    n = len(plan.slots)
    vals = np.full(n, np.nan)
    diag = {}
    by_page: dict[int, list[tuple[int, Slot]]] = {}
    for j, s in enumerate(plan.slots):
        by_page.setdefault(s.page, []).append((j, s))
    orig_sh = {p: _shingles([s.text for _, s in lst]) for p, lst in by_page.items()}
    used_orig = set()
    for lp, lw in enumerate(words):
        if not lw:
            continue
        lsh = _shingles([w for w, _ in lw])
        best, best_sim = None, 0.0
        for p, osh in orig_sh.items():
            sim = len(lsh & osh) / max(1, len(osh))
            if sim > best_sim and p not in used_orig:
                best, best_sim = p, sim
        if best is None or best_sim < 0.2:
            diag[lp] = {"matched_page": None}
            continue
        used_orig.add(best)
        olist = by_page[best]
        sm = SequenceMatcher(None, [s.text for _, s in olist], [w for w, _ in lw], autojunk=False)
        pairs = []   # (slot j, glyph index in slot, leaked x, y, orig x, y)
        for a, b, size in sm.get_matching_blocks():
            for k in range(size):
                j, s = olist[a + k]
                lg = lw[b + k][1]
                if len(lg) != len(s.glyphs):
                    continue
                for gi, (og, lgl) in enumerate(zip(s.glyphs, lg)):
                    pairs.append((j, og[1], og[2], lgl[1], lgl[2]))
        if len(pairs) < 10:
            diag[lp] = {"matched_page": best, "pairs": len(pairs)}
            continue
        P = np.array(pairs, dtype=float)
        A, keep = _robust_affine(P[:, 1:3], P[:, 3:5])
        if A is None:
            continue
        # map leaked positions back into the original frame
        M = np.array([[A[0, 0], A[1, 0]], [A[0, 1], A[1, 1]]])
        t = A[2]
        back = (P[:, 3:5] - t) @ np.linalg.inv(M).T
        resid = back - P[:, 1:3]
        per_slot: dict[int, list] = {}
        for (j, *_), r, k in zip(pairs, resid, keep):
            if not k:                       # glyph rejected by the robust fit (misaligned word)
                continue
            d = plan.slots[j].direction
            per_slot.setdefault(j, []).append(r[0] * d[0] + r[1] * d[1])
        for j, lst in per_slot.items():
            v = float(np.median(lst)) / delta
            if abs(v) <= 3.0 and len(lst) >= max(1, len(plan.slots[j].glyphs) // 2):
                vals[j] = v                 # otherwise unreadable, not a wrong symbol
        diag[lp] = {"matched_page": best, "similarity": round(best_sim, 3), "glyph_pairs": len(pairs),
                    "slots_measured": len(per_slot),
                    "affine_scale": round(float(np.sqrt(abs(np.linalg.det(M)))), 5)}
    return Extraction(vals, "vector", diag, int((~np.isnan(vals)).sum()))


# ============================================================================ raster

_SIFT = None


def _sift():
    global _SIFT
    if _SIFT is None:
        _SIFT = cv2.SIFT_create(nfeatures=6000)
    return _SIFT


def _scale_to(img: np.ndarray, max_side: int) -> tuple[np.ndarray, float]:
    s = max_side / max(img.shape)
    if s >= 1:
        return img, 1.0
    return cv2.resize(img, (int(img.shape[1] * s), int(img.shape[0] * s)), interpolation=cv2.INTER_AREA), s


class _Features:
    """SIFT keypoints for one image, computed once at <= 1400 px."""

    def __init__(self, img: np.ndarray):
        small, self.scale = _scale_to(img, 1400)
        self.kp, self.desc = _sift().detectAndCompute(small, None)
        self.thumb = cv2.resize(img, (48, 64), interpolation=cv2.INTER_AREA).astype(np.float32)


def _homography(lf: _Features, rf: _Features) -> tuple[np.ndarray | None, int]:
    """Homography mapping leaked-image pixels -> reference pixels (both full res)."""
    if lf.desc is None or rf.desc is None or len(lf.kp) < 8 or len(rf.kp) < 8:
        return None, 0
    matches = cv2.BFMatcher(cv2.NORM_L2).knnMatch(lf.desc, rf.desc, k=2)
    good = [m for m, n2 in (p for p in matches if len(p) == 2) if m.distance < 0.75 * n2.distance]
    if len(good) < 12:
        return None, len(good)
    src = np.float32([lf.kp[m.queryIdx].pt for m in good]) / lf.scale
    dst = np.float32([rf.kp[m.trainIdx].pt for m in good]) / rf.scale
    H, mask = cv2.findHomography(src, dst, cv2.RANSAC, 3.0 / rf.scale, maxIters=5000, confidence=0.999)
    if H is None:
        return None, 0
    return H, int(mask.sum())


def _ecc_refine(ref: np.ndarray, warped: np.ndarray) -> np.ndarray:
    """Sub-pixel refinement; returns homography W such that warped(W x) ~ ref(x)."""
    s = 0.35
    r = cv2.resize(ref, None, fx=s, fy=s, interpolation=cv2.INTER_AREA).astype(np.float32)
    w = cv2.resize(warped, None, fx=s, fy=s, interpolation=cv2.INTER_AREA).astype(np.float32)
    W = np.eye(3, dtype=np.float32)
    try:
        _, W = cv2.findTransformECC(r, w, W, cv2.MOTION_HOMOGRAPHY,
                                    (cv2.TERM_CRITERIA_EPS | cv2.TERM_CRITERIA_COUNT, 60, 1e-5), None, 5)
    except cv2.error:
        return np.eye(3)
    S = np.diag([s, s, 1.0])
    return np.linalg.inv(S) @ W.astype(float) @ S


def _patch_shift(ref: np.ndarray, leak: np.ndarray, valid: np.ndarray, slot: Slot,
                 scale: float) -> float | None:
    x0, top, x1, bottom = slot.bbox
    pad = 3
    c0, c1 = int(x0 * scale) - pad, int(np.ceil(x1 * scale)) + pad
    r0, r1 = int(top * scale) - pad, int(np.ceil(bottom * scale)) + pad
    if c0 < 1 or r0 < 1 or c1 >= ref.shape[1] - 1 or r1 >= ref.shape[0] - 1:
        return None
    if valid[r0:r1, c0:c1].min() < 0.99:
        return None
    R = ref[r0:r1, c0:c1].astype(np.float64)
    L = leak[r0:r1, c0:c1].astype(np.float64)
    if R.std() < 8:
        return None
    # photometric normalisation: L ~ a R + b
    a, b = np.polyfit(R.ravel(), L.ravel(), 1)
    if a <= 0.05:
        return None
    L = (L - b) / a
    ux, uy = slot.direction[0], -slot.direction[1]   # image y axis points down
    m = 8
    if r0 - m < 0 or c0 - m < 0 or r1 + m > ref.shape[0] or c1 + m > ref.shape[1]:
        return None
    win = ref[r0 - m:r1 + m, c0 - m:c1 + m].astype(np.float32)
    d = 0.0
    for _ in range(4):
        if d:
            M = np.float32([[1, 0, d * ux], [0, 1, d * uy]])
            Rs = cv2.warpAffine(win, M, (win.shape[1], win.shape[0]), flags=cv2.INTER_CUBIC,
                                borderMode=cv2.BORDER_REPLICATE)[m:-m, m:-m].astype(np.float64)
        else:
            Rs = R
        gy, gx = np.gradient(Rs)
        g = gx * ux + gy * uy
        den = (g * g).sum()
        if den < 1e-6:
            return None
        step = -((L - Rs) * g).sum() / den
        d += step
        if abs(step) < 0.01:
            break
    if abs(d) > 4:
        return None
    return d / scale    # points


def _smooth_residual(points: np.ndarray, shifts: np.ndarray, anchors_pts: np.ndarray,
                     anchor_shifts: np.ndarray) -> np.ndarray:
    """Remove slowly varying registration error. Fit on zero-shift anchors when there are
    enough of them, otherwise on all words (the +/- delta symbols average out)."""
    def design(p):
        x, y = p[:, 0] / 600.0, p[:, 1] / 800.0
        return np.stack([np.ones_like(x), x, y, x * y, x * x, y * y], 1)

    if len(anchors_pts) >= 20:
        P, S = anchors_pts, anchor_shifts
    else:
        P, S = points, shifts
    if len(P) < 8:
        return shifts - np.median(S) if len(S) else shifts
    X = design(P)
    w = np.ones(len(S))
    coef = np.zeros(X.shape[1])
    for _ in range(5):
        Wx = X * w[:, None]
        coef, *_ = np.linalg.lstsq(Wx, S * w, rcond=None)
        r = S - X @ coef
        c = 1.345 * (np.median(np.abs(r)) / 0.6745 + 1e-6)
        w = np.where(np.abs(r) <= c, 1.0, c / np.abs(r))
    return shifts - design(points) @ coef


def extract_raster(images: list[np.ndarray], original_pdf: bytes, plan: Plan, delta: float,
                   dpi: float = RASTER_DPI) -> Extraction:
    refs = render_pdf(original_pdf, dpi)
    ref_feats: dict[int, _Features] = {}
    scale = dpi / 72.0
    n = len(plan.slots)
    vals = np.full(n, np.nan)
    diag = {}
    used = set()
    for li, img in enumerate(images):
        lf = _Features(img)
        # try the most similar-looking pages first; stop at a confident match
        def thumb_dist(pi):
            t = cv2.resize(refs[pi], (48, 64), interpolation=cv2.INTER_AREA).astype(np.float32)
            return float(np.abs(t - lf.thumb).mean())
        order = sorted((pi for pi in range(len(refs)) if pi not in used), key=thumb_dist)
        best = (None, 0, None)
        for pi in order:
            if pi not in ref_feats:
                ref_feats[pi] = _Features(refs[pi])
            H, inl = _homography(lf, ref_feats[pi])
            if H is not None and inl > best[1]:
                best = (pi, inl, H)
            if best[1] >= 150:
                break
        pi, inliers, H = best
        if pi is None or inliers < 25:
            diag[li] = {"matched_page": None, "inliers": inliers}
            continue
        used.add(pi)
        ref = refs[pi]
        hh, ww = ref.shape
        warped = cv2.warpPerspective(img, H, (ww, hh), flags=cv2.INTER_CUBIC, borderValue=255)
        valid = cv2.warpPerspective(np.ones_like(img, dtype=np.float32), H, (ww, hh), flags=cv2.INTER_NEAREST)
        W = _ecc_refine(ref, warped)
        warped = cv2.warpPerspective(warped, W, (ww, hh), flags=cv2.INTER_CUBIC | cv2.WARP_INVERSE_MAP,
                                     borderValue=255)
        valid = cv2.warpPerspective(valid, W, (ww, hh), flags=cv2.INTER_NEAREST | cv2.WARP_INVERSE_MAP)
        idx, pts, sh = [], [], []
        for j, s in plan.slots_on_page(pi):
            d = _patch_shift(ref, warped, valid, s, scale)
            if d is not None:
                idx.append(j)
                pts.append([(s.bbox[0] + s.bbox[2]) / 2, (s.bbox[1] + s.bbox[3]) / 2])
                sh.append(d)
        apts, ash = [], []
        for s in plan.anchors:
            if s.page != pi:
                continue
            d = _patch_shift(ref, warped, valid, s, scale)
            if d is not None:
                apts.append([(s.bbox[0] + s.bbox[2]) / 2, (s.bbox[1] + s.bbox[3]) / 2])
                ash.append(d)
        if not idx:
            diag[li] = {"matched_page": pi, "inliers": inliers, "slots_measured": 0}
            continue
        corrected = _smooth_residual(np.array(pts), np.array(sh), np.array(apts).reshape(-1, 2), np.array(ash))
        for j, d in zip(idx, corrected):
            vals[j] = d / delta
        diag[li] = {"matched_page": pi, "inliers": inliers, "slots_measured": len(idx),
                    "anchors_measured": len(ash),
                    "est_scale": round(float(np.sqrt(abs(np.linalg.det(H[:2, :2])))), 4)}
    return Extraction(vals, "raster", diag, int((~np.isnan(vals)).sum()))
