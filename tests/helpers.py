import functools
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "demo"))


@functools.lru_cache(maxsize=1)
def sample_pdf() -> bytes:
    from make_sample_docs import make_reportlab
    d = Path(tempfile.mkdtemp())
    make_reportlab(d / "brief.pdf")
    return (d / "brief.pdf").read_bytes()


def new_workspace():
    from nishaan.workspace import Workspace
    return Workspace.init(Path(tempfile.mkdtemp()) / "ws")
