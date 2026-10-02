"""Generate fictional sample documents for the demo and the test corpus.

All content is invented exercise material (no real operational data).

    python demo/make_sample_docs.py [outdir]

Produces briefing.pdf (ReportLab) and, when the tools are installed, the same
text rendered by pdflatex, LibreOffice and Chromium so the watermark engine can
be tested on PDFs from different producers.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

TITLE = "Exercise SAGAR KAVACH-26: Coastal Logistics Coordination Brief"
BANNER = "RESTRICTED  //  EXERCISE MATERIAL - FICTIONAL SAMPLE DATA"

SECTIONS = [
    ("1. Purpose",
     ["This brief sets out the logistics coordination framework for the fictional training exercise "
      "SAGAR KAVACH-26. It is distributed to a limited group of planning officers so that replenishment "
      "windows, berthing slots and communication schedules can be deconflicted before the exercise begins. "
      "Every figure, unit and location in this document is invented for demonstration purposes only.",
      "Recipients are reminded that the document is individually issued. Each decrypted copy is unique to the "
      "officer who opened it, and every opening event is recorded on the offline provenance ledger maintained by "
      "the exercise control cell. Forwarding, photographing or printing the brief outside the planning cell is "
      "not permitted under the exercise handling instructions."]),
    ("2. Situation",
     ["The exercise area is divided into three notional sectors named North Shoal, Central Reach and Southern "
      "Approaches. Weather for the planning period is assumed to be moderate, with sea state three and visibility "
      "above eight nautical miles during daylight hours. Shore support will be provided from two notional "
      "logistics hubs, referred to in this document as Hub Alpha and Hub Bravo.",
      "Participating units will arrive in two waves. The first wave assembles at Hub Alpha on Day 1 and conducts "
      "harbour training until Day 3. The second wave joins at sea on Day 4, after which the combined group "
      "rehearses replenishment at sea, boarding drills and a coordinated search pattern exercise.",
      "Planning staff should assume that no satellite connectivity is available during the exercise. All "
      "coordination traffic will use the closed exercise network and courier exchange of removable media, "
      "mirroring the air-gapped conditions under which this attribution system is designed to operate."]),
    ("3. Replenishment Windows",
     ["Replenishment windows are allocated to avoid congestion at the logistics hubs. Each window is three hours "
      "long and is assigned to one unit. Units unable to meet an allocated window must inform the control cell at "
      "least twelve hours in advance so that the slot can be reassigned to a unit on the reserve list.",
      "The table below lists the provisional allocation. Quantities are notional planning figures and are rounded "
      "to the nearest ten tonnes. The control cell will issue an amended table if the second wave arrival time "
      "changes by more than six hours."]),
    ("4. Communications Plan",
     ["Routine reports are due at 0600, 1200 and 1800 hours each day. Situation reports must include fuel state, "
      "stores remaining in days, defects affecting readiness and the expected position at the next reporting time. "
      "Units should keep messages short and use the agreed exercise brevity codes listed in Annex B.",
      "In the event of a simulated communications failure, units revert to the fallback schedule: a single "
      "consolidated report at 1500 hours delivered by the duty courier boat. The courier carries sealed removable "
      "media only, and the receiving officer verifies the media seal against the courier log before use.",
      "Any suspected compromise of exercise material must be reported immediately to the exercise control cell. "
      "The forensic cell can identify the exact copy that was disclosed from a photograph, screenshot or printout, "
      "and can produce a verifiable attribution report without relying on any online service."]),
    ("5. Coordinating Instructions",
     ["Harbour movements during the first wave are restricted to daylight hours. Pilots will be provided for "
      "all berthing manoeuvres at Hub Alpha. Units will maintain a minimum separation of two cables while "
      "manoeuvring in the approaches, and will monitor the exercise harbour channel continuously.",
      "Medical support is available at both hubs. A casualty evacuation drill will be held on Day 5, and all "
      "units are expected to nominate a coordinator for the drill by Day 2. Safety observers from the control "
      "cell will embark in selected units for the duration of the at-sea phase.",
      "Questions about this brief should be directed to the logistics planning officer of the exercise control "
      "cell through the closed exercise network. This document will be superseded by the final exercise order."]),
]

TABLE = [["Window", "Unit (notional)", "Hub", "Fuel (t)", "Stores (t)"],
         ["W1  Day 2  0800-1100", "Patrol Vessel Tarang", "Alpha", "120", "30"],
         ["W2  Day 2  1300-1600", "Survey Ship Sindhu", "Alpha", "90", "20"],
         ["W3  Day 3  0800-1100", "Frigate Vajra", "Bravo", "260", "60"],
         ["W4  Day 3  1300-1600", "Corvette Agni", "Bravo", "150", "40"],
         ["W5  Day 4  0900-1200", "Tanker Jalashwa (notional)", "At sea", "-", "-"],
         ["W6  Day 5  0800-1100", "Destroyer Pralay", "Alpha", "310", "70"]]


def make_reportlab(path: Path) -> None:
    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontName="Times-Roman", fontSize=11,
                          leading=15, alignment=TA_JUSTIFY, spaceAfter=7)
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontName="Helvetica-Bold", fontSize=16, leading=20)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName="Helvetica-Bold", fontSize=12.5,
                        spaceBefore=10, spaceAfter=4)

    def banner(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica-Bold", 8.5)
        canvas.setFillColor(colors.HexColor("#8a1c1c"))
        canvas.drawCentredString(A4[0] / 2, A4[1] - 12 * mm, BANNER)
        canvas.drawCentredString(A4[0] / 2, 10 * mm, BANNER)
        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(A4[0] - 20 * mm, 15 * mm, f"Page {doc.page}")
        canvas.restoreState()

    story = [Paragraph(TITLE, h1),
             Paragraph("Issued by: Exercise Control Cell (fictional)  |  Copy: individually watermarked", body),
             Spacer(1, 6)]
    for i, (head, paras) in enumerate(SECTIONS):
        story.append(Paragraph(head, h2))
        for p in paras:
            story.append(Paragraph(p, body))
        if head.startswith("3."):
            t = Table(TABLE, colWidths=[42 * mm, 52 * mm, 18 * mm, 18 * mm, 20 * mm])
            t.setStyle(TableStyle([("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 9),
                                   ("FONT", (0, 1), (-1, -1), "Helvetica", 9),
                                   ("GRID", (0, 0), (-1, -1), 0.4, colors.grey),
                                   ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e8edf3"))]))
            story += [Spacer(1, 4), t, Spacer(1, 8)]
        if i == 2:
            story.append(PageBreak())
    doc = SimpleDocTemplate(str(path), pagesize=A4, leftMargin=22 * mm, rightMargin=22 * mm,
                            topMargin=22 * mm, bottomMargin=22 * mm, title=TITLE,
                            author="Exercise Control Cell (fictional)")
    doc.build(story, onFirstPage=banner, onLaterPages=banner)


def _markdown() -> str:
    out = [f"# {TITLE}", "", f"**{BANNER}**", ""]
    for head, paras in SECTIONS:
        out += [f"## {head}", ""] + [p + "\n" for p in paras]
    return "\n".join(out)


def _html() -> str:
    parts = [f"<h1>{TITLE}</h1><p><b>{BANNER}</b></p>"]
    for head, paras in SECTIONS:
        parts.append(f"<h2>{head}</h2>" + "".join(f"<p>{p}</p>" for p in paras))
    return ("<html><head><meta charset='utf-8'><style>body{font-family:'DejaVu Serif',serif;"
            "font-size:11pt;line-height:1.45;margin:22mm;text-align:justify}</style></head><body>"
            + "".join(parts) + "</body></html>")


def make_latex(path: Path) -> bool:
    if not shutil.which("pdflatex"):
        return False
    body = [r"\documentclass[11pt,a4paper]{article}", r"\usepackage[margin=22mm]{geometry}",
            r"\begin{document}", r"\section*{" + TITLE.replace("&", r"\&") + "}",
            r"\textbf{" + BANNER.replace("//", "/") + "}"]
    for head, paras in SECTIONS:
        body.append(r"\subsection*{" + head + "}")
        body += [p.replace("%", r"\%") + "\n" for p in paras]
    body.append(r"\end{document}")
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "doc.tex").write_text("\n".join(body))
        r = subprocess.run(["pdflatex", "-interaction=nonstopmode", "doc.tex"], cwd=td,
                           capture_output=True, timeout=120)
        if r.returncode != 0 or not (Path(td) / "doc.pdf").exists():
            return False
        shutil.copy(Path(td) / "doc.pdf", path)
    return True


def make_libreoffice(path: Path) -> bool:
    if not (shutil.which("pandoc") and shutil.which("soffice")):
        return False
    with tempfile.TemporaryDirectory() as td:
        (Path(td) / "doc.md").write_text(_markdown())
        subprocess.run(["pandoc", "doc.md", "-o", "doc.docx"], cwd=td, check=True, timeout=120)
        subprocess.run(["soffice", "--headless", "--convert-to", "pdf", "doc.docx"], cwd=td,
                       capture_output=True, timeout=240)
        if not (Path(td) / "doc.pdf").exists():
            return False
        shutil.copy(Path(td) / "doc.pdf", path)
    return True


def make_chromium(path: Path) -> bool:
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except ImportError:
        return False
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page()
        pg.set_content(_html())
        pg.pdf(path=str(path), format="A4")
        b.close()
    return True


def main(outdir: str = "demo/docs") -> None:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    make_reportlab(out / "briefing.pdf")
    print("wrote", out / "briefing.pdf")
    for name, fn in (("briefing_latex.pdf", make_latex), ("briefing_libreoffice.pdf", make_libreoffice),
                     ("briefing_chromium.pdf", make_chromium)):
        try:
            ok = fn(out / name)
        except Exception as e:  # optional producers
            ok = False
            print("skip", name, e)
        if ok:
            print("wrote", out / name)


if __name__ == "__main__":
    main(*sys.argv[1:])
