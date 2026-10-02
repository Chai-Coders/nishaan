import os
import unittest

import cv2
import numpy as np
from helpers import sample_pdf

from nishaan.watermark import engine as E
from nishaan.watermark.pdftext import rewrite
from nishaan.watermark.render import render_pdf


class TestWatermark(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = sample_pdf()
        cls.plan = E.make_plan(cls.src)
        cls.code = E.code_for(os.urandom(32), cls.plan)
        cls.seeds = {n: os.urandom(32) for n in ("alice", "bob", "carol", "dev")}
        cls.copies = {n: E.embed(cls.src, cls.plan, cls.code, s) for n, s in cls.seeds.items()}

    def accuse(self, ext):
        return E.accuse(E.decode(ext, self.code), self.code, self.seeds)

    def test_plan_is_deterministic(self):
        self.assertEqual(E.make_plan(self.src).hash, self.plan.hash)
        self.assertGreater(len(self.plan.slots), 200)

    def test_plain_rewrite_is_lossless(self):
        plain, _ = rewrite(self.src, "plain")
        for a, b in zip(render_pdf(self.src, 100), render_pdf(plain, 100)):
            self.assertEqual(int(np.abs(a.astype(int) - b.astype(int)).max()), 0)

    def test_copies_differ_but_same_text(self):
        import pdfplumber, io
        def text(b):
            with pdfplumber.open(io.BytesIO(b)) as d:
                return "".join(c["text"] for p in d.pages for c in p.chars)
        self.assertNotEqual(self.copies["alice"], self.copies["bob"])
        self.assertEqual(text(self.copies["alice"]), text(self.src))

    def test_vector_leak(self):
        r = self.accuse(E.extract_vector(self.copies["bob"], self.plan, E.DEFAULT_DELTA_PT))
        self.assertEqual(r["accused"], ["bob"])
        self.assertEqual(r["candidates"][0]["bit_agreement"], 1.0)

    def test_screenshot_jpeg_leak(self):
        img = render_pdf(self.copies["carol"], 110)[0]
        jpg = cv2.imdecode(cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 70])[1], 0)
        r = self.accuse(E.extract_raster([jpg], self.src, self.plan, E.DEFAULT_DELTA_PT))
        self.assertEqual(r["accused"], ["carol"])

    def test_rotated_scaled_photo(self):
        img = render_pdf(self.copies["dev"], 150)[0]
        h, w = img.shape
        M = cv2.getRotationMatrix2D((w / 2, h / 2), 3.0, 0.85)
        rot = cv2.warpAffine(img, M, (w, h), borderValue=255)
        r = self.accuse(E.extract_raster([rot], self.src, self.plan, E.DEFAULT_DELTA_PT))
        self.assertEqual(r["accused"], ["dev"])

    def test_collusion_averaging_catches_both(self):
        a, b = render_pdf(self.copies["alice"], 150)[0], render_pdf(self.copies["bob"], 150)[0]
        avg = ((a.astype(float) + b) / 2).astype(np.uint8)
        r = self.accuse(E.extract_raster([avg], self.src, self.plan, E.DEFAULT_DELTA_PT))
        self.assertTrue(set(r["accused"]) <= {"alice", "bob"} and r["accused"])
        self.assertNotIn("carol", r["accused"])
        self.assertNotIn("dev", r["accused"])

    def test_unrelated_document_accuses_nobody(self):
        r = self.accuse(E.extract_vector(self.src, self.plan, E.DEFAULT_DELTA_PT))   # unmarked original
        self.assertEqual(r["accused"], [])


if __name__ == "__main__":
    unittest.main()
