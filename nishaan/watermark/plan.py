"""Slot planning: which words carry fingerprint symbols, and where they are.

The plan is a deterministic function of the original PDF, so the recipient
client (embedding) and the forensic tool (extraction) derive the same plan
independently. Word geometry is measured once by rendering a *probe* copy in
which each word is wrapped in marked content and reading glyph origins back
with pdfplumber.
"""
from __future__ import annotations

import io
from collections import defaultdict
from dataclasses import asdict, dataclass

import pdfplumber

from ..crypto.sym import obj_hash
from . import pdftext as T

PLAN_VERSION = 1
MIN_SIZE_PT = 5.0


@dataclass
class Slot:
    page: int
    wid: int
    text: str
    glyphs: list           # [[text, x, y], ...] glyph origins in PDF user space (y up)
    bbox: list             # [x0, top, x1, bottom] in points, top-left origin
    direction: list        # baseline unit vector
    size: float            # font size in points


@dataclass
class Plan:
    version: int
    pages: list            # [{"w": .., "h": ..}]
    slots: list            # [Slot]  words that carry fingerprint symbols
    n_words: int
    anchors: list          # [Slot]  line-start/line-end words: never shifted (registration anchors)

    def to_json(self) -> dict:
        return {"version": self.version, "pages": self.pages, "n_words": self.n_words,
                "slots": [asdict(s) for s in self.slots], "anchors": [asdict(s) for s in self.anchors]}

    @classmethod
    def from_json(cls, d: dict) -> "Plan":
        return cls(d["version"], d["pages"], [Slot(**s) for s in d["slots"]], d["n_words"],
                   [Slot(**s) for s in d.get("anchors", [])])

    @property
    def hash(self) -> str:
        return obj_hash(self.to_json())

    def slots_on_page(self, page: int) -> list[tuple[int, Slot]]:
        return [(j, s) for j, s in enumerate(self.slots) if s.page == page]


def make_plan(pdf_bytes: bytes) -> Plan:
    probe, models = T.rewrite(pdf_bytes, "probe")
    words = {w.wid: w for m in models for w in m.words.values()}
    glyphs: dict[int, list] = defaultdict(list)
    pages = []
    with pdfplumber.open(io.BytesIO(probe)) as doc:
        for pi, page in enumerate(doc.pages):
            pages.append({"w": float(page.width), "h": float(page.height)})
            for c in page.chars:
                if c.get("tag") == T.PROBE_TAG and isinstance(c.get("mcid"), int) and c["mcid"] >= T.PROBE_BASE:
                    glyphs[c["mcid"] - T.PROBE_BASE].append(c)
    slots, anchors = [], []
    for wid in sorted(words):
        w = words[wid]
        cs = glyphs.get(wid, [])
        if not cs or not w.visible:
            continue
        text = "".join(c["text"] for c in cs)
        if not any(ch.isalnum() for ch in text) or w.size < MIN_SIZE_PT:
            continue
        target = anchors if (w.line_start or w.line_end) else slots
        target.append(Slot(
            page=w.page, wid=wid, text=text,
            glyphs=[[c["text"], round(c["matrix"][4], 4), round(c["matrix"][5], 4)] for c in cs],
            bbox=[round(min(c["x0"] for c in cs), 3), round(min(c["top"] for c in cs), 3),
                  round(max(c["x1"] for c in cs), 3), round(max(c["bottom"] for c in cs), 3)],
            direction=[round(w.direction[0], 6), round(w.direction[1], 6)],
            size=round(w.size, 3)))
    return Plan(PLAN_VERSION, pages, slots, len(words), anchors)


def leaked_words(pdf_bytes: bytes) -> list[list[tuple[str, list]]]:
    """Every word of a (possibly leaked) PDF with glyph origins, segmented exactly like make_plan."""
    probe, models = T.rewrite(pdf_bytes, "probe")
    glyphs: dict[int, list] = defaultdict(list)
    n_pages = len(models)
    with pdfplumber.open(io.BytesIO(probe)) as doc:
        for page in doc.pages:
            for c in page.chars:
                if c.get("tag") == T.PROBE_TAG and isinstance(c.get("mcid"), int) and c["mcid"] >= T.PROBE_BASE:
                    glyphs[c["mcid"] - T.PROBE_BASE].append(c)
    out: list[list] = [[] for _ in range(n_pages)]
    for m in models:
        for wid in sorted(m.words):
            cs = glyphs.get(wid)
            if cs:
                out[m.words[wid].page].append(
                    ("".join(c["text"] for c in cs), [[c["text"], c["matrix"][4], c["matrix"][5]] for c in cs]))
    return out
