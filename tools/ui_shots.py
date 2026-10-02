"""Drive the console with a headless browser and capture screenshots (dev aid)."""
import sys, time
from playwright.sync_api import sync_playwright
URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8090"
OUT = sys.argv[2] if len(sys.argv) > 2 else "/tmp/shots"
import os; os.makedirs(OUT, exist_ok=True)
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1360, "height": 900})
    errs = []
    pg.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
    pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.goto(URL); pg.wait_for_timeout(800)
    pg.screenshot(path=f"{OUT}/00_setup.png")
    if pg.is_visible("#btn-init"):
        pg.click("#btn-init"); pg.wait_for_selector("#view-ledger:not([hidden])", timeout=120000); pg.wait_for_timeout(3500)
    pg.screenshot(path=f"{OUT}/01_ledger.png", full_page=True)
    pg.goto(URL + "/#send"); pg.wait_for_timeout(800)
    pg.click("#send-form button[type=submit]"); pg.wait_for_selector("#send-out .steps", timeout=120000)
    pg.screenshot(path=f"{OUT}/02_send.png", full_page=True)
    pg.goto(URL + "/#open"); pg.wait_for_timeout(800)
    for who in ["alice", "bob", "carol"]:
        pg.select_option("#open-who", who); pg.click("#open-btn")
        pg.wait_for_function("document.querySelector('#open-btn').disabled === false", timeout=120000); pg.wait_for_timeout(500)
    pg.screenshot(path=f"{OUT}/03_open.png", full_page=True)
    pg.goto(URL + "/#compare"); pg.wait_for_timeout(800)
    pg.click("#cmp-form button"); pg.wait_for_selector("#cmp-out .stats", timeout=120000)
    pg.screenshot(path=f"{OUT}/04_compare.png", full_page=True)
    pg.goto(URL + "/#trace"); pg.wait_for_timeout(800)
    opts = pg.eval_on_selector_all("#tr-a option", "els => els.map(e => e.value)")
    bob = [o for o in opts if o.startswith("bob/")][0]
    pg.select_option("#tr-a", bob); pg.select_option("#tr-kind", "photo")
    pg.click("#trace-sim button[type=submit]"); pg.wait_for_selector("#trace-out .verdict", timeout=300000)
    pg.click("#btn-verify"); pg.wait_for_selector("#verify-out:not([hidden])", timeout=300000)
    pg.screenshot(path=f"{OUT}/05_trace.png", full_page=True)
    pg.goto(URL + "/#audit"); pg.wait_for_timeout(800)
    pg.click("#btn-cp"); pg.wait_for_timeout(1500)
    pg.select_option("#tamper-form select[name=node]", "node-3")
    pg.click("#tamper-form button"); pg.wait_for_timeout(1200)
    pg.click("#btn-audit"); pg.wait_for_selector("#audit-out .auditnodes", timeout=120000); pg.wait_for_timeout(3500)
    pg.screenshot(path=f"{OUT}/06_audit.png", full_page=True)
    pg.goto(URL + "/#people"); pg.wait_for_timeout(800); pg.screenshot(path=f"{OUT}/07_people.png", full_page=True)
    pg.set_viewport_size({"width": 390, "height": 844}); pg.goto(URL + "/#trace"); pg.wait_for_timeout(1500)
    pg.screenshot(path=f"{OUT}/08_mobile.png", full_page=False)
    print("console errors:", errs)
    b.close()
