"""Rendering, perceptual hashes and visual-identity metrics (all offline)."""
from __future__ import annotations

import io

import numpy as np
import pypdfium2 as pdfium
from PIL import Image
from skimage.metrics import peak_signal_noise_ratio, structural_similarity


def render_pdf(pdf_bytes: bytes, dpi: float = 150, pages: list[int] | None = None) -> list[np.ndarray]:
    """Grayscale uint8 renders (white background)."""
    doc = pdfium.PdfDocument(pdf_bytes)
    out = []
    try:
        for i in range(len(doc)):
            if pages is not None and i not in pages:
                continue
            img = doc[i].render(scale=dpi / 72.0, grayscale=True).to_pil()
            out.append(np.asarray(img.convert("L"), dtype=np.uint8))
    finally:
        doc.close()
    return out


def page_count(pdf_bytes: bytes) -> int:
    doc = pdfium.PdfDocument(pdf_bytes)
    try:
        return len(doc)
    finally:
        doc.close()


def load_image(data: bytes) -> np.ndarray:
    img = Image.open(io.BytesIO(data))
    return np.asarray(img.convert("L"), dtype=np.uint8)


def dhash(gray: np.ndarray, size: int = 16) -> str:
    """Difference hash of a page render (perceptual, identical for all watermarked copies)."""
    small = np.asarray(Image.fromarray(gray).resize((size + 1, size), Image.LANCZOS), dtype=np.int16)
    bits = (small[:, 1:] > small[:, :-1]).flatten()
    v = 0
    for b in bits:
        v = (v << 1) | int(b)
    return f"{v:0{size * size // 4}x}"


def hamming_hex(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def visual_metrics(pdf_a: bytes, pdf_b: bytes, dpi: float = 150) -> dict:
    ra, rb = render_pdf(pdf_a, dpi), render_pdf(pdf_b, dpi)
    psnr, ssim, maxd, changed = [], [], 0, 0
    for a, b in zip(ra, rb):
        if np.array_equal(a, b):
            psnr.append(float("inf"))
            ssim.append(1.0)
            continue
        psnr.append(float(peak_signal_noise_ratio(a, b, data_range=255)))
        ssim.append(float(structural_similarity(a, b, data_range=255)))
        d = np.abs(a.astype(int) - b.astype(int))
        maxd = max(maxd, int(d.max()))
        changed += int((d > 32).sum())
    finite = [p for p in psnr if p != float("inf")]
    return {"dpi": dpi, "pages": len(ra),
            "psnr_db_min": round(min(finite), 2) if finite else None,
            "ssim_min": round(min(ssim), 5),
            "ssim_mean": round(float(np.mean(ssim)), 5),
            "pixels_changed_gt32": changed,
            "same_page_hashes": all(dhash(a) == dhash(b) for a, b in zip(ra, rb))}
