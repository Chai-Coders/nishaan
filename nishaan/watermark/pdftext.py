"""PDF content-stream interpreter for word-level geometric watermarking.

The engine works on arbitrary text PDFs (ReportLab, LaTeX, LibreOffice/Word,
Chromium "print to PDF", ...) without font metrics:

1. Every text-showing operator (Tj, TJ, ', ") is decoded through the font's
   ToUnicode CMap / encoding and split into *word segments* (breaks at space
   glyphs and at large TJ gaps; LaTeX has no space glyphs at all).
2. Segments are grouped into *words* inside a text line; a word may span several
   operators (Chromium positions every glyph with its own Tj).
3. Each segment is re-emitted as its own ``TJ`` operator. To move a word by
   +d points along the baseline we emit ``[-n <glyphs> +n] TJ`` with
   n = d * 1000 / (Tfs * Th * s); the trailing +n restores the text position,
   so nothing else on the page moves. This is invisible structural editing:
   glyphs, fonts and every other byte of drawing are untouched.

Modes: ``probe`` wraps each segment in marked content carrying the word id
(used once to measure word geometry via pdfplumber), ``embed`` applies shifts.
"""
from __future__ import annotations

import io
import math
import re
from dataclasses import dataclass, field

import pikepdf
from pikepdf import Array, ContentStreamInstruction, Name, Operator, String

PROBE_TAG = "NshProbe"
PROBE_BASE = 1_000_000
GAP_BREAK = -200          # TJ number (thousandths of em) treated as a word gap
LINE_OPS = {"Tm", "Td", "TD", "T*"}

_SPACES = {" ", " ", " ", " ", " ", "\t", "\r", "\n"}


# ============================================================================ fonts

def _parse_hex_unicode(h: str) -> str:
    b = bytes.fromhex(h)
    try:
        return b.decode("utf-16-be")
    except UnicodeDecodeError:
        return ""


def parse_tounicode(data: bytes) -> dict[int, str]:
    text = data.decode("latin-1")
    m: dict[int, str] = {}
    for block in re.findall(r"beginbfchar(.*?)endbfchar", text, re.S):
        for src, dst in re.findall(r"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]*)>", block):
            m[int(src, 16)] = _parse_hex_unicode(dst)
    for block in re.findall(r"beginbfrange(.*?)endbfrange", text, re.S):
        for lo, hi, rest in re.findall(r"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(\[[^\]]*\]|<[0-9A-Fa-f]*>)", block):
            lo_i, hi_i = int(lo, 16), int(hi, 16)
            if hi_i - lo_i > 65535:
                continue
            if rest.startswith("["):
                for i, d in enumerate(re.findall(r"<([0-9A-Fa-f]*)>", rest)):
                    m[lo_i + i] = _parse_hex_unicode(d)
            else:
                base = bytes.fromhex(rest[1:-1])
                if not base:
                    continue
                for i in range(hi_i - lo_i + 1):
                    v = int.from_bytes(base, "big") + i
                    try:
                        m[lo_i + i] = v.to_bytes(len(base), "big").decode("utf-16-be")
                    except (UnicodeDecodeError, OverflowError):
                        pass
    return m


@dataclass
class FontInfo:
    code_len: int                 # 1 or 2 bytes per code
    to_unicode: dict[int, str]
    space_codes: set[int]
    segmentable: bool = True

    def codes(self, raw: bytes) -> list[int]:
        if self.code_len == 2:
            if len(raw) % 2:
                raw = raw + b"\x00"
            return [int.from_bytes(raw[i:i + 2], "big") for i in range(0, len(raw), 2)]
        return list(raw)

    def is_space(self, code: int) -> bool:
        return code in self.space_codes


def font_info(font) -> FontInfo:
    try:
        subtype = str(font.get("/Subtype", ""))
    except Exception:
        subtype = ""
    tu: dict[int, str] = {}
    try:
        if "/ToUnicode" in font:
            tu = parse_tounicode(font.ToUnicode.read_bytes())
    except Exception:
        tu = {}
    if subtype == "/Type0":
        enc = str(font.get("/Encoding", ""))
        two = enc in ("/Identity-H", "/Identity-V")
        spaces = {c for c, u in tu.items() if u in _SPACES}
        return FontInfo(2, tu, spaces, segmentable=two)
    spaces = {c for c, u in tu.items() if u in _SPACES}
    if not tu:
        spaces = {32}
        try:
            enc = font.get("/Encoding")
            if isinstance(enc, pikepdf.Dictionary) and "/Differences" in enc:
                code = 0
                for item in enc.Differences:
                    if isinstance(item, int) or hasattr(item, "__int__") and not isinstance(item, Name):
                        code = int(item)
                    else:
                        if str(item) == "/space":
                            spaces.add(code)
                        elif code == 32:
                            spaces.discard(32)
                        code += 1
        except Exception:
            pass
    return FontInfo(1, tu, spaces)


# ============================================================================ matrices

def _mul(m1, m2):
    a1, b1, c1, d1, e1, f1 = m1
    a2, b2, c2, d2, e2, f2 = m2
    return (a1 * a2 + b1 * c2, a1 * b2 + b1 * d2, c1 * a2 + d1 * c2, c1 * b2 + d1 * d2,
            e1 * a2 + f1 * c2 + e2, e1 * b2 + f1 * d2 + f2)


IDENT = (1.0, 0.0, 0.0, 1.0, 0.0, 0.0)


# ============================================================================ model

@dataclass
class Segment:
    word: int | None              # word id (None for pure-space / unsegmentable runs)
    elems: list                   # pikepdf Strings and numbers
    n_per_pt: float               # TJ units per point of baseline displacement
    text: str


@dataclass
class Show:
    prefix: list                  # instructions emitted before (e.g. T* for the ' operator)
    segments: list[Segment]


@dataclass
class Word:
    wid: int
    page: int
    line_start: bool = False
    line_end: bool = False
    visible: bool = True
    direction: tuple = (1.0, 0.0)
    size: float = 0.0
    text: str = ""


@dataclass
class PageModel:
    items: list = field(default_factory=list)   # ContentStreamInstruction | inline image | Show
    words: dict = field(default_factory=dict)   # wid -> Word


def _num(x) -> float:
    return float(x)


def _resources_fonts(page) -> dict:
    try:
        res = page.obj.get("/Resources")
        if res is None:
            res = page.resources
        fonts = res.get("/Font", {})
        return {str(k): v for k, v in fonts.items()}
    except Exception:
        return {}


def analyse_page(page, page_index: int, wid_start: int = 0) -> PageModel:
    fonts_raw = _resources_fonts(page)
    finfo: dict[str, FontInfo] = {}
    model = PageModel()
    ctm = IDENT
    # graphics-state text parameters
    gs = {"font": None, "size": 0.0, "Tc": 0.0, "Tw": 0.0, "Tz": 100.0, "TL": 0.0, "Ts": 0.0, "Tr": 0}
    stack = []
    tm = tlm = IDENT
    in_bt = False
    wid = wid_start
    cur_word: Word | None = None
    line_words: list[Word] = []

    def end_word():
        nonlocal cur_word
        cur_word = None

    def end_line():
        nonlocal line_words
        end_word()
        if line_words:
            line_words[-1].line_end = True
            line_words[0].line_start = True
        line_words = []

    def get_font(name):
        if name not in finfo:
            f = fonts_raw.get(name)
            finfo[name] = font_info(f) if f is not None else FontInfo(1, {}, {32})
        return finfo[name]

    pos_changed = True
    baseline = None               # (origin_x, origin_y, dir_x, dir_y, size) of current line
    last_op_glyphs = 0

    instrs = pikepdf.parse_content_stream(page)
    for ins in instrs:
        if isinstance(ins, pikepdf.ContentStreamInlineImage):
            model.items.append(ins)
            continue
        op = str(ins.operator)
        ops = list(ins.operands)
        if op == "q":
            stack.append((ctm, dict(gs)))
        elif op == "Q":
            if stack:
                ctm, gs = stack.pop()
        elif op == "cm" and len(ops) == 6:
            ctm = _mul(tuple(_num(o) for o in ops), ctm)
            pos_changed = True
        elif op == "BT":
            in_bt = True
            tm = tlm = IDENT
            pos_changed = True
        elif op == "ET":
            in_bt = False
        elif op == "Tf" and len(ops) == 2:
            gs["font"], gs["size"] = str(ops[0]), _num(ops[1])
        elif op in ("Tc", "Tw", "Tz", "TL", "Ts") and len(ops) == 1:
            gs[op] = _num(ops[0])
        elif op == "Tr" and ops:
            gs["Tr"] = int(_num(ops[0]))
        elif op == "Tm" and len(ops) == 6:
            tm = tlm = tuple(_num(o) for o in ops)
            pos_changed = True
        elif op in ("Td", "TD") and len(ops) == 2:
            tx, ty = _num(ops[0]), _num(ops[1])
            if op == "TD":
                gs["TL"] = -ty
            tlm = _mul((1, 0, 0, 1, tx, ty), tlm)
            tm = tlm
            pos_changed = True
        elif op == "T*":
            tlm = _mul((1, 0, 0, 1, 0, -gs["TL"]), tlm)
            tm = tlm
            pos_changed = True

        if op not in ("Tj", "TJ", "'", '"'):
            model.items.append(ins)
            continue

        # ---------------------------------------------------------------- text showing
        prefix = []
        if op == "'":
            tlm = _mul((1, 0, 0, 1, 0, -gs["TL"]), tlm)
            tm = tlm
            pos_changed = True
            prefix.append(ContentStreamInstruction([], Operator("T*")))
            arr = [ops[0]]
        elif op == '"':
            gs["Tw"], gs["Tc"] = _num(ops[0]), _num(ops[1])
            tlm = _mul((1, 0, 0, 1, 0, -gs["TL"]), tlm)
            tm = tlm
            pos_changed = True
            prefix += [ContentStreamInstruction([ops[0]], Operator("Tw")),
                       ContentStreamInstruction([ops[1]], Operator("Tc")),
                       ContentStreamInstruction([], Operator("T*"))]
            arr = [ops[2]]
        elif op == "Tj":
            arr = [ops[0]]
        else:
            arr = list(ops[0]) if ops else []

        if pos_changed:
            # geometric line detection: same baseline => same line
            mm = _mul(tm, ctm)
            sc = math.hypot(mm[0], mm[1]) or 1.0
            dx, dy = mm[0] / sc, mm[1] / sc
            usize = abs(gs["size"]) * math.hypot(mm[2], mm[3]) or 1.0
            new_line = True
            if baseline is not None:
                bx, by, bdx, bdy, bsize = baseline
                vx, vy = mm[4] - bx, mm[5] - by
                perp = abs(-bdy * vx + bdx * vy)
                along = bdx * vx + bdy * vy
                same_dir = dx * bdx + dy * bdy > 0.99
                new_line = not (same_dir and perp < 0.3 * max(bsize, usize) and along > -0.5 * bsize)
            if new_line:
                end_line()
                baseline = (mm[4], mm[5], dx, dy, usize)
            elif last_op_glyphs != 1:
                # repositioning inside a line separates words unless the producer places glyph by glyph
                end_word()
            pos_changed = False

        fi = get_font(gs["font"])
        m = _mul(tm, ctm)
        s = math.hypot(m[0], m[1])
        th = gs["Tz"] / 100.0
        denom = gs["size"] * th * s
        n_per_pt = 1000.0 / denom if abs(denom) > 1e-9 else 0.0
        direction = (m[0] / s, m[1] / s) if s > 1e-12 else (1.0, 0.0)
        visible = gs["Tr"] not in (3, 7) and n_per_pt != 0.0
        user_size = abs(gs["size"]) * math.hypot(m[2], m[3])

        segments: list[Segment] = []
        cur_elems: list = []
        cur_text = []

        def flush(word_obj):
            nonlocal cur_elems, cur_text
            if cur_elems:
                segments.append(Segment(word_obj.wid if word_obj else None, cur_elems, n_per_pt,
                                        "".join(cur_text)))
            cur_elems, cur_text = [], []

        def start_word():
            nonlocal cur_word, wid
            cur_word = Word(wid, page_index, visible=visible, direction=direction, size=user_size)
            model.words[wid] = cur_word
            line_words.append(cur_word)
            wid += 1

        for el in arr:
            if isinstance(el, String):
                raw = bytes(el)
                if not fi.segmentable:
                    # cannot decode codes: the whole string becomes (part of) one word
                    if cur_word is None:
                        start_word()
                    cur_elems.append(el)
                    cur_text.append("?")
                    continue
                codes = fi.codes(raw)
                run = bytearray()
                run_word = cur_word
                for c in codes:
                    cb = c.to_bytes(fi.code_len, "big")
                    if fi.is_space(c):
                        # close the word; spaces travel unshifted on their own
                        if run:
                            cur_elems.append(String(bytes(run)))
                            run = bytearray()
                        flush(cur_word)
                        end_word()
                        segments.append(Segment(None, [String(cb)], n_per_pt, " "))
                        continue
                    if cur_word is None:
                        if run:
                            cur_elems.append(String(bytes(run)))
                            run = bytearray()
                        flush(None)
                        start_word()
                    run += cb
                    cur_text.append(fi.to_unicode.get(c, "?"))
                    cur_word.text += fi.to_unicode.get(c, "?")
                if run:
                    cur_elems.append(String(bytes(run)))
            else:
                v = _num(el)
                if v <= GAP_BREAK:
                    cur_elems.append(el)
                    flush(cur_word)
                    end_word()
                else:
                    cur_elems.append(el)
        flush(cur_word)
        model.items.append(Show(prefix, segments))
        last_op_glyphs = sum(len(seg.text) for seg in segments if seg.word is not None)
    end_line()
    return model


# ============================================================================ emission

def _fmt(x: float):
    return float(f"{x:.4f}")


def _merge(elems: list) -> list:
    """Merge adjacent strings and adjacent numbers so the TJ array looks like ordinary kerning."""
    out: list = []
    for e in elems:
        if isinstance(e, String):
            if out and isinstance(out[-1], String):
                out[-1] = String(bytes(out[-1]) + bytes(e))
            else:
                out.append(String(bytes(e)))
        else:
            v = float(e)
            if out and not isinstance(out[-1], String):
                out[-1] = out[-1] + v
            else:
                out.append(v)
    res = []
    for e in out:
        if isinstance(e, String):
            res.append(e)
        elif abs(e) > 1e-6:
            res.append(int(e) if float(e).is_integer() else _fmt(e))
    return res


def emit_page(model: PageModel, mode: str, shifts: dict[int, float] | None = None) -> bytes:
    """mode: 'probe' | 'embed' | 'plain'. shifts: word id -> baseline displacement (points).

    In 'embed' mode each original text operator is re-emitted as ONE TJ whose
    inter-word numbers absorb the word shifts (indistinguishable from kerning).
    """
    shifts = shifts or {}
    out = []
    for it in model.items:
        if not isinstance(it, Show):
            out.append(it)
            continue
        out.extend(it.prefix)
        if mode == "probe":
            for seg in it.segments:
                tj = ContentStreamInstruction([Array(list(seg.elems))], Operator("TJ"))
                if seg.word is not None:
                    out.append(ContentStreamInstruction(
                        [Name("/" + PROBE_TAG), pikepdf.Dictionary(MCID=PROBE_BASE + seg.word)],
                        Operator("BDC")))
                    out.append(tj)
                    out.append(ContentStreamInstruction([], Operator("EMC")))
                else:
                    out.append(tj)
            continue
        elems: list = []
        cur = 0.0
        for seg in it.segments:
            target = 0.0
            if mode == "embed" and seg.word is not None and seg.n_per_pt:
                target = shifts.get(seg.word, 0.0) * seg.n_per_pt
            if abs(target - cur) > 1e-9:
                elems.append(-(target - cur))      # negative TJ number moves the pen right
                cur = target
            elems.extend(seg.elems)
        if abs(cur) > 1e-9:
            elems.append(cur)                      # restore the pen: nothing after this op moves
        out.append(ContentStreamInstruction([Array(_merge(elems))], Operator("TJ")))
    return pikepdf.unparse_content_stream(out)


def analyse(pdf: pikepdf.Pdf) -> list[PageModel]:
    models = []
    wid = 0
    for i, page in enumerate(pdf.pages):
        m = analyse_page(page, i, wid)
        wid += len(m.words)
        models.append(m)
    return models


def rewrite(pdf_bytes: bytes, mode: str, shifts: dict[int, float] | None = None) -> tuple[bytes, list[PageModel]]:
    pdf = pikepdf.open(io.BytesIO(pdf_bytes))
    models = analyse(pdf)
    for page, model in zip(pdf.pages, models):
        page.obj.Contents = pdf.make_stream(emit_page(model, mode, shifts))
    buf = io.BytesIO()
    # deterministic output: no random /ID, stable object order
    pdf.save(buf, deterministic_id=True, compress_streams=True,
             object_stream_mode=pikepdf.ObjectStreamMode.preserve)
    return buf.getvalue(), models
