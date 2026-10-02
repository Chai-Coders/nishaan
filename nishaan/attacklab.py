"""Attack lab: measured robustness and visual identity (supplement item 8).

For each watermark strength delta it embeds fingerprints for six sessions, then
runs realistic leak routes and collusion attacks against the copy of one
"leaker", and records whether the forensic pipeline accuses exactly the right
people, how far the score clears the false-accusation threshold, and the
visual-identity metrics (PSNR/SSIM) next to a viewer-to-viewer baseline.

    python -m nishaan attack-lab [--doc brief.pdf] [--deltas 0.2,0.35,0.5] [--quick]
"""
from __future__ import annotations

import html
import io
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import cv2
import numpy as np
import pikepdf
import pdfplumber
from skimage.metrics import peak_signal_noise_ratio, structural_similarity

from .watermark import engine as E
from .watermark.render import render_pdf, visual_metrics

SESSIONS = ["alice", "bob", "carol", "dev", "erin", "frank"]
LEAKER = "bob"
COLLUDERS = ("alice", "bob")


# ---------------------------------------------------------------------------- attacks

def _jpeg(img, q):
    return cv2.imdecode(cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, q])[1], 0)


def _resave(pdf: bytes) -> bytes:
    p = pikepdf.open(io.BytesIO(pdf))
    buf = io.BytesIO()
    p.save(buf, object_stream_mode=pikepdf.ObjectStreamMode.generate, compress_streams=True,
           recompress_flate=True, linearize=True)
    return buf.getvalue()


def _print_scan(img300: np.ndarray, rng) -> np.ndarray:
    x = cv2.GaussianBlur(img300, (0, 0), 1.1).astype(np.float32)
    x = 255 * (x / 255) ** 1.15                                      # toner gamma
    x += rng.normal(0, 5, x.shape)                                   # sensor noise
    h, w = x.shape
    M = cv2.getRotationMatrix2D((w / 2, h / 2), 0.8, 1.0)            # skewed on the glass
    x = cv2.warpAffine(np.clip(x, 0, 255).astype(np.uint8), M, (w, h), borderValue=245)
    return _jpeg(x, 85)


def _phone_photo(img200: np.ndarray, rng) -> np.ndarray:
    h, w = img200.shape
    pad = 120
    canvas = np.full((h + 2 * pad, w + 2 * pad), 90, np.uint8)
    canvas[pad:pad + h, pad:pad + w] = img200
    H, W = canvas.shape
    src = np.float32([[pad, pad], [pad + w, pad], [pad + w, pad + h], [pad, pad + h]])
    j = 0.03 * w
    dst = src + rng.uniform(-j, j, src.shape).astype(np.float32)
    P = cv2.getPerspectiveTransform(src, dst)
    x = cv2.warpPerspective(canvas, P, (W, H), borderValue=90).astype(np.float32)
    grad = np.linspace(0.82, 1.0, W)[None, :] * np.linspace(0.9, 1.0, H)[:, None]
    x = x * grad
    x = cv2.GaussianBlur(x, (0, 0), 1.0) + rng.normal(0, 4, x.shape)
    return _jpeg(np.clip(x, 0, 255).astype(np.uint8), 80)


def build_attacks(copies: dict, src: bytes, plan, code, seeds, delta, quick=False):
    """Yields (name, group, kind, payload, expected_set)."""
    rng = np.random.default_rng(7)
    leak = copies[LEAKER]
    p0 = lambda c, dpi: render_pdf(c, dpi, pages=[0])[0]  # noqa: E731
    yield "Forwarded PDF (as delivered)", "digital", "pdf", leak, {LEAKER}
    yield "Re-saved PDF (recompressed, linearised)", "digital", "pdf", _resave(leak), {LEAKER}
    yield "Screenshot 96 DPI (100% zoom)", "screen", "img", [p0(leak, 96)], {LEAKER}
    yield "Screenshot 150 DPI", "screen", "img", [p0(leak, 150)], {LEAKER}
    if not quick:
        yield "JPEG quality 90", "compression", "img", [_jpeg(p0(leak, 150), 90)], {LEAKER}
    yield "JPEG quality 60", "compression", "img", [_jpeg(p0(leak, 150), 60)], {LEAKER}
    if not quick:
        yield "JPEG quality 40", "compression", "img", [_jpeg(p0(leak, 150), 40)], {LEAKER}
    im = p0(leak, 150)
    h, w = im.shape
    yield "Crop (top 50% of page)", "geometric", "img", [im[: h // 2, :]], {LEAKER}
    M = cv2.getRotationMatrix2D((w / 2, h / 2), 3.0, 0.85)
    yield "Rotate 3 deg + scale 85%", "geometric", "img", [cv2.warpAffine(im, M, (w, h), borderValue=255)], {LEAKER}
    yield "Print & scan (300 DPI, blur, skew, noise)", "physical", "img", [_print_scan(p0(leak, 300), rng)], {LEAKER}
    yield "Phone photo (perspective, lighting, JPEG)", "physical", "img", [_phone_photo(p0(leak, 200), rng)], {LEAKER}
    a, b = copies[COLLUDERS[0]], copies[COLLUDERS[1]]
    # collusion 1: page-level interleave
    pa, pb = pikepdf.open(io.BytesIO(a)), pikepdf.open(io.BytesIO(b))
    out = pikepdf.new()
    for i in range(len(pa.pages)):
        out.pages.append((pa if i % 2 == 0 else pb).pages[i])
    buf = io.BytesIO()
    out.save(buf)
    yield "Collusion: pages interleaved from 2 copies", "collusion", "pdf", buf.getvalue(), set(COLLUDERS)
    # collusion 2: word-level splice (each word taken from either copy)
    sa = E.shifts_for(plan, code, seeds[COLLUDERS[0]], delta)
    sb = E.shifts_for(plan, code, seeds[COLLUDERS[1]], delta)
    mix = {k: (sa[k] if rng.random() < 0.5 else sb[k]) for k in sa}
    from .watermark.pdftext import rewrite
    yield "Collusion: words spliced from 2 copies", "collusion", "pdf", rewrite(src, "embed", mix)[0], set(COLLUDERS)
    # collusion 3: pixel averaging
    avg = ((p0(a, 150).astype(np.float32) + p0(b, 150)) / 2).astype(np.uint8)
    yield "Collusion: 2 screenshots averaged", "collusion", "img", [avg], set(COLLUDERS)


def _text_only(pdf: bytes) -> str:
    with pdfplumber.open(io.BytesIO(pdf)) as d:
        return "\n".join(p.extract_text() or "" for p in d.pages)


# ---------------------------------------------------------------------------- baselines

def viewer_baseline(src: bytes, dpi: int = 150) -> dict:
    out = {}
    a = render_pdf(src, dpi, pages=[0])[0]
    if shutil.which("pdftoppm"):
        with tempfile.TemporaryDirectory() as td:
            Path(td, "a.pdf").write_bytes(src)
            subprocess.run(["pdftoppm", "-r", str(dpi), "-gray", "-f", "1", "-l", "1", "a.pdf", "p"], cwd=td,
                           check=True, capture_output=True)
            f = next(Path(td).glob("p*.pgm"))
            b = cv2.imread(str(f), 0)
            hh, ww = min(a.shape[0], b.shape[0]), min(a.shape[1], b.shape[1])
            out["Same file, PDFium vs Poppler viewer"] = {
                "psnr": round(float(peak_signal_noise_ratio(a[:hh, :ww], b[:hh, :ww], data_range=255)), 2),
                "ssim": round(float(structural_similarity(a[:hh, :ww], b[:hh, :ww], data_range=255)), 4)}
    p = pikepdf.open(io.BytesIO(src))
    p.pages[0].contents_add(p.make_stream(b"1 0 0 1 0.35 0 cm"), prepend=True)
    buf = io.BytesIO()
    p.save(buf)
    b = render_pdf(buf.getvalue(), dpi, pages=[0])[0]
    out["Same file, scrolled 0.35 pt"] = {"psnr": round(float(peak_signal_noise_ratio(a, b, data_range=255)), 2),
                                          "ssim": round(float(structural_similarity(a, b, data_range=255)), 4)}
    return out


# ---------------------------------------------------------------------------- runner

def run_lab(doc: str | None = None, out_dir: str = "attack_lab", deltas=(0.2, 0.35, 0.5),
            quick: bool = False, progress=print) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    if doc:
        src = Path(doc).read_bytes()
        doc_name = Path(doc).name
    else:
        import sys
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "demo"))
        from make_sample_docs import make_reportlab
        make_reportlab(out / "sample.pdf")
        src = (out / "sample.pdf").read_bytes()
        doc_name = "generated sample brief"
    if quick:
        deltas = [0.35]
    plan = E.make_plan(src)
    results = {"document": doc_name, "slots": len(plan.slots), "pages": len(plan.pages),
               "sessions": SESSIONS, "leaker": LEAKER, "colluders": list(COLLUDERS),
               "baseline": viewer_baseline(src), "deltas": [], "text_copy": None}
    for delta in deltas:
        secret = os.urandom(32)
        code = E.code_for(secret, plan)
        seeds = {s: os.urandom(32) for s in SESSIONS}
        copies = {s: E.embed(src, plan, code, seeds[s], delta) for s in SESSIONS}
        vis = visual_metrics(src, copies[LEAKER])
        progress(f"delta {delta} pt: PSNR {vis['psnr_db_min']} dB, SSIM {vis['ssim_min']}")
        rows = []
        for name, group, kind, payload, expected in build_attacks(copies, src, plan, code, seeds, delta, quick):
            t = time.time()
            ext = (E.extract_vector(payload, plan, delta) if kind == "pdf"
                   else E.extract_raster(payload, src, plan, delta))
            sym = E.decode(ext, code)
            acc = E.accuse(sym, code, seeds)
            accused = set(acc["accused"])
            innocent_hit = accused - expected
            if innocent_hit:
                verdict = "FALSE ACCUSATION"
            elif accused == expected:
                verdict = "attributed" if len(expected) == 1 else "both colluders caught"
            elif accused:
                verdict = f"{len(accused)} of {len(expected)} colluders caught"
            else:
                verdict = "inconclusive"
            sc = {c["session_id"]: c["score"] for c in acc["candidates"]}
            best_expected = max(sc[e] for e in expected)
            best_innocent = max(v for k, v in sc.items() if k not in expected)
            x = code.codeword(seeds[LEAKER])
            read = sym.y != -1
            rows.append({"attack": name, "group": group, "verdict": verdict, "accused": sorted(accused),
                         "ok": not innocent_hit and bool(accused & expected),
                         "score": round(best_expected, 1), "threshold": acc["threshold"],
                         "ratio": round(best_expected / acc["threshold"], 2) if acc["threshold"] else None,
                         "max_innocent_score": round(best_innocent, 1),
                         "positions_read": int(sym.m_eff), "code_length": code.m,
                         "bit_agreement_leaker": round(float((x[read] == sym.y[read]).mean()), 4) if read.any() else None,
                         "seconds": round(time.time() - t, 1)})
            progress(f"  {name:45s} {verdict:22s} score/threshold {rows[-1]['ratio']}")
        results["deltas"].append({"delta_pt": delta, "visual": vis, "attacks": rows})
        if results["text_copy"] is None:
            txt = _text_only(copies[LEAKER])
            results["text_copy"] = {"chars": len(txt), "note": "Plain-text copy/paste removes word geometry; "
                                    "the word-shift channel cannot attribute it (text-layer channel is roadmap)."}
    (out / "attack_lab.json").write_text(json.dumps(results, indent=1))
    (out / "attack_lab.html").write_text(render_html(results))
    return out / "attack_lab.html"


# ---------------------------------------------------------------------------- report

def render_html(r: dict) -> str:
    esc = html.escape
    deltas = r["deltas"]
    attacks = [a["attack"] for a in deltas[0]["attacks"]]
    # chart: score/threshold ratio per attack, one bar per delta
    bar_h, gap, left, width = 12, 10, 290, 420
    n_d = len(deltas)
    max_ratio = max([a["ratio"] or 0 for d in deltas for a in d["attacks"]] + [2])
    rows_svg = []
    y = 20
    palette = ["#9db7d5", "#2f6db5", "#173d6b"]
    for name in attacks:
        rows_svg.append(f'<text x="{left - 8}" y="{y + n_d * bar_h / 2 + 4}" text-anchor="end" class="lbl">{esc(name)}</text>')
        for k, d in enumerate(deltas):
            a = next(x for x in d["attacks"] if x["attack"] == name)
            v = a["ratio"] or 0
            wv = width * min(v, max_ratio) / max_ratio
            col = palette[k % len(palette)] if a["ok"] else "#c94a3a"
            rows_svg.append(f'<rect x="{left}" y="{y + k * bar_h}" width="{wv:.1f}" height="{bar_h - 2}" fill="{col}">'
                            f'<title>delta {d["delta_pt"]} pt: {esc(a["verdict"])}, score/threshold {v}</title></rect>')
        y += n_d * bar_h + gap
    x1 = left + width / max_ratio
    chart = (f'<svg viewBox="0 0 {left + width + 40} {y + 30}" class="chart" role="img" '
             f'aria-label="Score over threshold per attack">'
             f'<line x1="{x1:.1f}" x2="{x1:.1f}" y1="10" y2="{y}" class="thr"/>'
             f'<text x="{x1 + 4:.1f}" y="{y + 16}" class="lbl">threshold (score = Z, P(false accusation) &le; 1e-6)</text>'
             + "".join(rows_svg) + "</svg>")
    legend = " ".join(f'<span class="key" style="background:{palette[k % 3]}"></span>&delta; = {d["delta_pt"]} pt'
                      for k, d in enumerate(deltas)) + ' <span class="key" style="background:#c94a3a"></span>not attributed'

    vis_rows = "".join(f'<tr><td>Watermarked copy, &delta; = {d["delta_pt"]} pt</td><td>{d["visual"]["psnr_db_min"]}</td>'
                       f'<td>{d["visual"]["ssim_min"]}</td></tr>' for d in deltas)
    base_rows = "".join(f'<tr class="base"><td>{esc(k)}</td><td>{v["psnr"]}</td><td>{v["ssim"]}</td></tr>'
                        for k, v in r["baseline"].items())
    tables = []
    for d in deltas:
        trs = "".join(
            f'<tr><td>{esc(a["attack"])}</td><td class="{"ok" if a["ok"] else "bad"}">{esc(a["verdict"])}</td>'
            f'<td>{a["score"]}</td><td>{a["threshold"]}</td><td>{a["max_innocent_score"]}</td>'
            f'<td>{a["positions_read"]}/{a["code_length"]}</td><td>{a["bit_agreement_leaker"]}</td>'
            f'<td>{a["seconds"]}</td></tr>' for a in d["attacks"])
        okc = sum(a["ok"] for a in d["attacks"])
        tables.append(f'<h3>&delta; = {d["delta_pt"]} pt &middot; {okc}/{len(d["attacks"])} attributed</h3>'
                      '<div class="scroll"><table><tr><th>Leak route / attack</th><th>Verdict</th><th>Score</th>'
                      '<th>Threshold</th><th>Max innocent</th><th>Positions read</th><th>Bit agreement (leaker)</th>'
                      f'<th>s</th></tr>{trs}</table></div>')
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Nishaan attack lab</title>
<style>
:root{{--bg:#f7f8fa;--fg:#17202b;--mut:#5b6573;--line:#d9dee5;--card:#fff}}
@media (prefers-color-scheme:dark){{:root{{--bg:#11151b;--fg:#e6e9ee;--mut:#97a1ae;--line:#2a313b;--card:#171c23}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
main{{max-width:1040px;margin:0 auto;padding:24px 16px 60px}}
h1{{font-size:26px;margin:0 0 4px}} h2{{font-size:19px;margin:32px 0 8px}} h3{{font-size:16px;margin:22px 0 6px}}
.mut{{color:var(--mut)}} .card{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}}
table{{border-collapse:collapse;width:100%;font-size:13.5px}} td,th{{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left}}
th{{color:var(--mut);font-weight:600}} .ok{{color:#2e7d4f;font-weight:600}} .bad{{color:#c94a3a;font-weight:600}}
tr.base td{{color:var(--mut);font-style:italic}} .scroll{{overflow-x:auto}}
.chart{{width:100%;height:auto}} .chart .lbl{{font-size:11px;fill:var(--fg)}} .chart .thr{{stroke:var(--fg);stroke-dasharray:4 3}}
.key{{display:inline-block;width:12px;height:12px;border-radius:2px;margin:0 4px 0 12px;vertical-align:-1px}}
</style></head><body><main>
<h1>Attack lab</h1>
<p class="mut">Document: {esc(r['document'])} &middot; {r['pages']} pages &middot; {r['slots']} watermark slots &middot;
{len(r['sessions'])} recipient sessions &middot; leaker <b>{r['leaker']}</b>, colluders <b>{' + '.join(r['colluders'])}</b>.
Accusation requires P(an innocent recipient reaches the score) &le; 10<sup>-6</sup> (Chernoff bound).</p>
<h2>Visual identity</h2>
<div class="card"><p class="mut" style="margin-top:0">Pixel metrics at 150 DPI against the unmarked original. Italic rows are the same
<i>unmodified</i> file viewed two ordinary ways: the watermark changes the page less than switching PDF viewer does.</p>
<table><tr><th>Comparison</th><th>PSNR (dB)</th><th>SSIM</th></tr>{vis_rows}{base_rows}</table></div>
<h2>Robustness: score relative to the false-accusation threshold</h2>
<div class="card"><div class="mut" style="font-size:13px">{legend}</div>{chart}</div>
{''.join(tables)}
<h2>Known limit</h2><p>{esc(r['text_copy']['note'])}</p>
</main></body></html>"""
