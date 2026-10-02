"use strict";
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
let S = null;            // last /api/state
let LANES = null;

function toast(msg, err = false) {
  const t = $("#toast");
  t.textContent = msg;
  t.className = "toast show" + (err ? " err" : "");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => (t.className = "toast"), err ? 7000 : 4000);
}

async function api(path, opts = {}) {
  const o = {...opts};
  if (o.json) { o.method = o.method || "POST"; o.headers = {"Content-Type": "application/json"}; o.body = JSON.stringify(o.json); delete o.json; }
  const r = await fetch(path, o);
  const ct = r.headers.get("content-type") || "";
  const data = ct.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error((data && data.error) || r.statusText);
  return data;
}

async function busy(btn, label, fn) {
  const old = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<span class="busy"></span>${esc(label)}`;
  try { return await fn(); }
  catch (e) { toast(e.message, true); }
  finally { btn.disabled = false; btn.innerHTML = old; }
}

const short = (h, n = 10) => (h ? String(h).slice(0, n) : "");
const nameOf = (sid) => (S?.subjects.find((x) => x.subject_id === sid)?.display_name) || sid;
const fmtTime = (iso) => iso ? iso.replace("T", " ").slice(0, 19) + " UTC" : "";
const docTitle = (id) => S?.docs[id]?.title || short(id, 8);

/* ------------------------------------------------------------------ routing */
function route() {
  const v = (location.hash || "#ledger").slice(1);
  if (S && !S.initialised) return show("setup");
  show("view-" + v);
  $$("#rail a").forEach((a) => a.classList.toggle("on", a.dataset.view === v));
  const hook = {ledger: loadBlocks, lab: labStatus, open: renderCopies}[v];
  if (hook) hook();
}
function show(id) { $$(".view").forEach((el) => (el.hidden = el.id !== id)); }
window.addEventListener("hashchange", route);

/* ------------------------------------------------------------------ state */
async function loadState() {
  S = await api("/api/state");
  if (!S.initialised) { $("#setup-root").textContent = "Workspace folder: " + S.root; $(".lanes").hidden = true; route(); return; }
  $(".lanes").hidden = false;
  $("#chainline").innerHTML = `Chain <b>${esc(S.chain_id)}</b> at height <b>${S.height}</b><br>` +
    `${S.mode === "http" ? "Nodes in separate processes" : "Nodes in this process"} · trust anchor <span class="mono">${short(S.trust_anchor, 16)}…</span>`;
  renderFacts(); renderSelects(); renderPeople(); renderCheckpoints(); renderCopies();
}

function renderFacts() {
  const a = S.algorithms || {};
  $("#facts").innerHTML = [
    ["Key encapsulation", a.kem], ["Signatures", a.sig], ["CA root", a.root_sig], ["Document cipher", a.aead],
    ["Hashing", a.hash], ["Commit quorum", `${S.quorum} of ${S.nodes.length} nodes (tolerates ${S.f} faulty)`],
    ["Key release", `${S.share_threshold} of ${S.nodes.length} node shares after commit`], ["Library", S.backend],
  ].map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join("");
}

function renderSelects() {
  const recips = S.subjects.filter((x) => x.role === "recipient");
  const active = (sid) => Object.values(S.certs).some((c) => c.subject_id === sid && c.status === "active");
  $("#recip-checks").innerHTML = recips.map((r) =>
    `<label><input type="checkbox" value="${esc(r.subject_id)}" ${active(r.subject_id) ? "" : "disabled"} ${["alice", "bob", "carol", "dev"].includes(r.subject_id) && active(r.subject_id) ? "checked" : ""}>${esc(r.display_name)}${active(r.subject_id) ? "" : " (revoked)"}</label>`).join("");
  const docs = Object.entries(S.docs).reverse();
  $("#open-doc").innerHTML = docs.length ? docs.map(([id, d]) => `<option value="${id}">${esc(d.title)} (${short(id, 8)})</option>`).join("")
    : `<option value="">Send a document first</option>`;
  fillWho();
  const copies = S.delivered.slice().reverse().map((c) => `<option value="${esc(c.id)}">${esc(nameOf(c.who))} · ${esc(docTitle(c.doc_id))} · session ${esc(c.session)}</option>`).join("")
    || `<option value="">Open a document first</option>`;
  ["#cmp-a", "#cmp-b", "#tr-a", "#tr-b"].forEach((s) => { const el = $(s); const v = el.value; el.innerHTML = copies; if (v) el.value = v; });
  if (S.delivered.length > 1 && $("#cmp-a").value === $("#cmp-b").value) $("#cmp-b").selectedIndex = 1;
  if (S.delivered.length > 1 && $("#tr-a").value === $("#tr-b").value) $("#tr-b").selectedIndex = 1;
  $("#tamper-node").innerHTML = S.nodes.map((n) => `<option>${n}</option>`).join("");
}
function fillWho() {
  const d = S.docs[$("#open-doc").value];
  const all = S.subjects.filter((x) => x.role === "recipient");
  $("#open-who").innerHTML = all.map((r) => `<option value="${esc(r.subject_id)}">${esc(r.display_name)}${d && !d.recipients.includes(r.subject_id) ? " (not a recipient)" : ""}</option>`).join("");
}
$("#open-doc").addEventListener("change", fillWho);

/* ------------------------------------------------------------------ ledger lanes */
async function loadLanes() {
  if (document.hidden || !S?.initialised) return;
  try { LANES = await api("/api/lanes"); } catch { return; }
  const L = LANES;
  const cols = [];
  for (let h = L.start; h <= L.top; h++) cols.push(h);
  $("#lanes").innerHTML = L.nodes.map((n) => {
    const bad = n.corrupted;
    const cls = !n.online ? "off" : bad ? "bad" : "";
    const flag = !n.online ? "offline" : bad ? "audit failed" : n.byzantine ? "malicious" : "";
    const blocks = cols.map((h) => {
      const b = n.blocks[h];
      if (b) {
        const t = b.types.includes("FORENSIC_ACCESS") ? "FORENSIC_ACCESS" : b.types.includes("DECRYPT_INTENT") ? "DECRYPT_INTENT" : "x";
        const ticks = "<span></span>".repeat(Math.min(b.sigs, 4));
        return `<div class="blk t-${t}" data-h="${h}" title="Block ${h} · ${esc(b.types.join(", "))} · hash ${b.hash}… · leader ${b.leader}${b.view ? " (view " + b.view + ")" : ""} · ${b.sigs} node signatures">${h}<div class="ticks">${ticks}</div></div>`;
      }
      if (bad && h === bad.height) return `<div class="blk broken" title="Block ${h} failed verification: ${esc(bad.reason)}">${h}</div>`;
      return `<div class="blk gap" title="Block ${h} not held by this node">${h}</div>`;
    }).join("");
    return `<div class="lane ${cls}"><div class="lname"><span class="dot"></span>${n.id}<span class="flag">${esc(flag)}</span></div><div class="track">${blocks}</div></div>`;
  }).join("") + `<div class="legend"><span><i></i>certificates, manifests, receipts</span><span><i style="background:var(--tint)"></i>decryption record</span><span><i style="background:var(--brass);border-color:var(--brass)"></i>investigation</span><span><i style="border-color:var(--signal)"></i>failed audit</span><span><i style="border-style:dashed;border-color:var(--rule)"></i>missing on this node</span></div>`;
  $("#lanes-caption").textContent = `Height ${L.top}. Each square is a block linked to the previous one by its hash; the dots under it are node signatures (${S.quorum} needed).`;
  renderNodeCtl();
}
$("#lanes").addEventListener("click", (e) => { const b = e.target.closest(".blk[data-h]"); if (b) openBlock(+b.dataset.h); });

async function openBlock(h) {
  try {
    const b = await api(`/api/block/${h}`);
    $("#block-json").textContent = JSON.stringify(b, (k, v) => (typeof v === "string" && v.length > 180 ? v.slice(0, 64) + `… (${v.length} chars)` : v), 1);
    $("#block-dlg").showModal();
  } catch (e) { toast(e.message, true); }
}

function renderNodeCtl() {
  if (!LANES) return;
  const local = LANES.mode !== "http";
  $("#node-ctl").innerHTML = `<tr><th>Node</th><th>State</th><th>Height</th><th>Simulate</th></tr>` + LANES.nodes.map((n) => {
    const st = !n.online ? `<span class="pill mut">offline</span>` : n.corrupted ? `<span class="pill bad">failed audit</span>` : n.byzantine ? `<span class="pill warn">malicious</span>` : `<span class="pill ok">healthy</span>`;
    const ctl = local ? `<button class="small" data-off="${n.id}" data-on="${n.online ? 1 : 0}">${n.online ? "Take offline" : "Bring online"}</button>
      <button class="small ${n.byzantine ? "" : "danger"}" data-byz="${n.id}" data-v="${n.byzantine ? "" : "forge"}">${n.byzantine ? "Make honest" : "Make malicious"}</button>` : `<span class="mut">stop the process</span>`;
    return `<tr><td><b>${n.id}</b></td><td>${st}</td><td>${n.height ?? "–"}</td><td>${ctl}</td></tr>`;
  }).join("");
  $("#node-hint").textContent = local ? "A malicious node, when it is leader, tries to alter the record it is proposing. Honest nodes refuse to sign it and the next leader commits the genuine record." : "";
}
$("#node-ctl").addEventListener("click", async (e) => {
  const b = e.target.closest("button"); if (!b) return;
  try {
    if (b.dataset.off) await api(`/api/node/${b.dataset.off}/offline`, {json: {on: b.dataset.on === "1"}});
    if (b.dataset.byz) await api(`/api/node/${b.dataset.byz}/byzantine`, {json: {mode: b.dataset.v}});
    loadLanes();
  } catch (er) { toast(er.message, true); }
});

async function loadBlocks() {
  try {
    const bl = await api("/api/blocks?n=14");
    $("#blocks").innerHTML = `<tr><th>Block</th><th>Committed</th><th>Leader</th><th>Signatures</th><th>Records</th></tr>` + bl.map((b) =>
      `<tr data-h="${b.height}"><td><b>${b.height}</b> <span class="mono mut">${short(b.hash, 8)}</span></td><td>${fmtTime(b.time)}</td><td>${b.leader}${b.view ? ` <span class="pill warn">view ${b.view}</span>` : ""}</td><td>${b.sigs} of ${S.nodes.length}</td><td>${b.txs.map((t) => `${esc(t.type.toLowerCase().replace(/_/g, " "))} <span class="mut">${esc(t.who)}</span>`).join("<br>")}</td></tr>`).join("");
  } catch (e) { /* ignore */ }
}
$("#blocks").addEventListener("click", (e) => { const r = e.target.closest("tr[data-h]"); if (r) openBlock(+r.dataset.h); });

/* ------------------------------------------------------------------ send */
$("#send-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const f = e.target, fd = new FormData(f);
  fd.set("recipients", $$("#recip-checks input:checked").map((x) => x.value).join(","));
  if (!f.file.files.length) fd.delete("file");
  busy(f.querySelector("button[type=submit]"), "Encrypting and committing…", async () => {
    const r = await api("/api/distribute", {method: "POST", body: fd});
    $("#send-out").innerHTML = `<div class="panel"><h3>Distributed</h3><ol class="steps">
      <li><div><b>Encrypted once</b><div class="mut">Document hash <span class="mono">${short(r.doc_hash, 24)}…</span></div></div></li>
      <li><div><b>Keys wrapped for ${r.recipients.length} recipients and the forensic cell</b><div class="mut">${r.recipients.map(nameOf).map(esc).join(", ")}</div></div></li>
      <li><div><b>Second key layer split ${r.threshold}-of-${S.nodes.length} across the ledger nodes</b></div></li>
      <li><div><b>Manifest committed at block ${r.block}</b><div class="mut">Leader ${r.leader}. ${r.slots} words will carry a ${r.code_len}-symbol fingerprint in every opened copy.</div></div></li></ol>
      <p><a href="#open">Open it as a recipient</a></p></div>`;
    await loadState(); $("#open-doc").value = r.doc_id; fillWho(); loadLanes();
  });
});

/* ------------------------------------------------------------------ open */
const STEP_TEXT = {
  manifest_verified: (s) => [`Checked the distribution manifest is on the ledger`, `Block ${s.block}: ${esc(s.title)}`],
  record_signed: (s) => [`Signed the decryption record with ${esc(s.alg)}`, `Session ${short(s.session_id, 8)} · watermark blind index ${esc(s.watermark_index)}`],
  record_committed: (s) => [`Record committed at block ${s.block} before any key was released`,
    `Leader ${s.leader}${s.view ? " after a view change" : ""} · prepare ${Object.values(s.prepare).filter((v) => v === "signed").length}/${Object.keys(s.prepare).length} · commit ${Object.values(s.commit).filter((v) => v === "signed").length}/${Object.keys(s.commit).length} signatures`],
  committee_shares: (s) => [`${Object.entries(s.released).filter(([, v]) => v === "released").map(([k]) => k).join(" and ")} released their key shares`, `${s.threshold} of ${S.nodes.length} needed; each share re-encrypted to the recipient's ML-KEM key`],
  decrypted: (s) => [`Decrypted with AES-256-GCM`, `${(s.bytes / 1024).toFixed(1)} KB, document hash verified`],
  watermarked: (s) => [`Fingerprinted this copy`, `${s.code_length}-symbol Tardos code spread over ${s.slots} words, shifts of ±${s.delta_pt} pt`],
  receipt_committed: (s) => [`Delivery receipt committed at block ${s.block}`, `Hash of the exact copy handed over: ${short(s.delivered_hash, 16)}…`],
  receipt_failed: (s) => [`Delivery receipt not recorded`, esc(s.error)],
};
$("#open-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const doc_id = $("#open-doc").value, who = $("#open-who").value;
  if (!doc_id) return toast("Send a document first", true);
  busy($("#open-btn"), "Opening…", async () => {
    const r = await api("/api/open", {json: {doc_id, who}});
    if (r.denied) {
      $("#open-out").innerHTML = `<div class="verdict v-none"><h3>Access refused</h3><p>${esc(r.error)}</p><p class="mut">Nothing was decrypted. Refusals happen before any key share is released.</p></div>`;
      loadLanes(); return;
    }
    $("#open-out").innerHTML = `<div class="panel"><h3>${esc(nameOf(who))} opened the document in ${r.seconds} s</h3><ol class="steps">${r.steps.map((s) => {
      const [a, b] = (STEP_TEXT[s.step] || ((x) => [x.step, ""]))(s); return `<li><div><b>${a}</b><div class="mut">${b}</div></div></li>`; }).join("")}</ol>
      <p style="margin-top:12px"><a class="btn" href="/api/copy/${encodeURI(r.copy)}" target="_blank">View this copy</a></p></div>`;
    await loadState(); loadLanes();
  });
});
function renderCopies() {
  if (!S?.delivered) return;
  $("#copies").innerHTML = S.delivered.length ? S.delivered.slice().reverse().map((c) =>
    `<a class="copy" href="/api/copy/${encodeURI(c.id)}" target="_blank"><img loading="lazy" src="/api/thumb/${encodeURI(c.id)}" alt="First page of ${esc(nameOf(c.who))}'s copy"><b>${esc(nameOf(c.who).split(",")[0])}</b><br><span class="mut">${esc(docTitle(c.doc_id))} · ${esc(c.session)}</span></a>`).join("")
    : `<p class="mut">No copies yet. Open a document above.</p>`;
}

/* ------------------------------------------------------------------ compare */
let blinkTimer = null;
$("#cmp-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const a = $("#cmp-a").value, b = $("#cmp-b").value;
  if (!a || !b || a === b) return toast("Choose two different copies", true);
  busy(e.target.querySelector("button"), "Rendering…", async () => {
    const r = await api("/api/compare", {json: {a, b}});
    const m = r.metrics;
    const na = nameOf(a.split("/")[0]).split(",")[0], nb = nameOf(b.split("/")[0]).split(",")[0];
    $("#cmp-out").innerHTML = `<div class="panel">
      <div class="stats">
        <div class="stat"><b>${r.same_text ? "Identical" : "Different"}</b><span>text, word for word</span></div>
        <div class="stat"><b>${r.words_moved} of ${r.words}</b><span>words in different positions on page 1</span></div>
        <div class="stat"><b>${m.ssim_min}</b><span>SSIM (1 = identical pixels)</span></div>
        <div class="stat"><b>${r.identical_bytes ? "Same" : "Distinct"}</b><span>files, forensically</span></div>
      </div>
      <div class="row-between"><h3>Zoomed body text, 300 DPI</h3><button id="blink" type="button">Blink between copies</button></div>
      <div class="zoom">
        <figure class="blink"><img id="blink-img" src="${r.a}" alt="Copy A text sample"><figcaption id="blink-cap">Copy A: ${esc(na)}</figcaption></figure>
        <figure id="fig-b"><img src="${r.b}" alt="Copy B text sample"><figcaption>Copy B: ${esc(nb)}</figcaption></figure>
        <figure><img src="${r.diff}" alt="Pixel difference"><figcaption>Pixel difference, amplified 4 times. Only word edges differ; no glyph changes.</figcaption></figure>
      </div>
      <p class="hint">PSNR ${m.psnr_db_min} dB, SSIM ${m.ssim_min} at ${m.dpi} DPI. For scale, the same unmodified file opened in two different PDF viewers scores about 17.8 dB and 0.905.</p></div>`;
    clearInterval(blinkTimer); blinkTimer = null;
    $("#blink").onclick = () => {
      const img = $("#blink-img"), cap = $("#blink-cap"), fb = $("#fig-b");
      if (blinkTimer) { clearInterval(blinkTimer); blinkTimer = null; img.src = r.a; cap.textContent = "Copy A: " + na; fb.hidden = false; $("#blink").textContent = "Blink between copies"; return; }
      let on = false; fb.hidden = true; $("#blink").textContent = "Stop blinking";
      blinkTimer = setInterval(() => { on = !on; img.src = on ? r.b : r.a; cap.textContent = on ? "Copy B: " + nb : "Copy A: " + na; }, 550);
    };
  });
});

/* ------------------------------------------------------------------ trace */
$("#tr-kind").addEventListener("change", (e) => ($("#tr-b-wrap").hidden = e.target.value !== "collusion"));
function runTrace(form, fd) {
  busy(form.querySelector("button[type=submit]"), "Investigating…", async () => {
    $("#trace-out").innerHTML = `<p class="mut"><span class="busy"></span>Logging the investigation on the ledger, decrypting the original through the committee, measuring every word…</p>`;
    try {
      const r = await api("/api/investigate", {method: "POST", body: fd});
      renderVerdict(r);
    } catch (e) { $("#trace-out").innerHTML = ""; throw e; }
    await loadState(); loadLanes();
  });
}
$("#trace-sim").addEventListener("submit", (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  if (fd.get("kind") !== "collusion") fd.delete("copy_b");
  if (!fd.get("copy_a")) return toast("Open a document first", true);
  runTrace(e.target, fd);
});
$("#trace-up").addEventListener("submit", (e) => { e.preventDefault(); runTrace(e.target, new FormData(e.target)); });

function renderVerdict(r) {
  const fp = r.fingerprint, F = r.findings;
  const names = F.map((f) => f.display_name);
  let cls = "v-ok", head, sub;
  if (r.status === "VERIFIED") {
    head = esc(names[0]);
    sub = `decrypted the copy that leaked. ${F[0].exact_copy ? "The file is byte-identical to the copy delivered to them." : "Matched by the fingerprint in the word positions."}`;
  } else if (r.status === "VERIFIED_COLLUSION") {
    head = names.map(esc).join(" and ");
    sub = "contributed to the leaked copy. Their copies were combined; each one's fingerprint survives.";
  } else if (r.status === "INCONCLUSIVE") {
    cls = "v-none"; head = "Not enough evidence to accuse anyone";
    sub = `Only ${fp.symbols.positions_read} of ${fp.symbols.code_length} fingerprint symbols could be read. The leading candidate stays below the threshold, so nobody is named.`;
  } else if (r.status === "CHECKS_FAILED") {
    cls = "v-none"; head = "Fingerprint matched, but a ledger check failed"; sub = "See the failed checks below.";
  } else { cls = "v-none"; head = "No recipient matches this file"; sub = "It may be another document, or too little of it survived."; }
  const cands = fp.candidates;
  const maxv = Math.max(fp.threshold * 1.25, ...cands.map((c) => c.score), 1);
  const bars = cands.map((c) => `<div class="sb ${c.accused ? "acc" : ""}"><span>${esc(c.display_name.split(",")[0])}</span>
     <div class="bar"><span style="width:${Math.max(0, c.score) / maxv * 100}%"></span><div class="thr" style="left:${fp.threshold / maxv * 100}%"></div></div>
     <span>${Math.round(c.score) || 0}</span></div>`).join("");
  const checks = F.map((f) => `<h3 style="margin-top:18px">Checks for ${esc(f.display_name.split(",")[0])}</h3><ul class="checklist">${f.checks.map((c) =>
     `<li class="${c.ok ? "" : c.required === false ? "info" : "fail"}"><div>${esc(c.check)}${c.detail ? `<small>${esc(c.detail)}</small>` : ""}</div></li>`).join("")}</ul>
     <dl class="facts" style="margin-top:10px"><dt>Decrypted</dt><dd>${fmtTime(f.decryption_timestamp)} (ledger time)</dd><dt>Record</dt><dd>block ${f.ledger_block}, <span class="mono">${short(f.ledger_block_hash, 20)}…</span></dd>
     <dt>Device</dt><dd>${esc(f.device_context?.os || "")} · ${esc(f.device_context?.device_id || "")}</dd><dt>Merkle proof</dt><dd>${f.merkle_proof.length ? f.merkle_proof.length + " sibling hashes to the block root" : "record is the only one in its block (root = record hash)"}</dd>
     <dt>False accusation</dt><dd>${f.false_positive_bound == null ? "exact copy: matched by its signed delivery receipt" : "probability at most " + f.false_positive_bound.toExponential(1)}</dd></dl>`).join("");
  const ex = fp.extraction;
  $("#trace-out").innerHTML = `<div class="verdict ${cls}">
    <p class="mut" style="margin:0">Case ${esc(r.case_id)} · ${esc(r.document_title)}</p>
    <div class="who">${head}</div><p>${sub}</p>
    ${(r.warnings || []).map((w) => `<p class="warnline">${esc(w)}</p>`).join("")}
    <div class="grid"><div>
      <h3>Fingerprint score by recipient</h3>
      <div class="scorebars">${bars}</div>
      <p class="hint">Dashed line: the score an innocent recipient reaches with probability below one in a million (Chernoff bound over the ${fp.symbols.positions_read} symbols read).
        Read from the ${ex.method === "vector" ? "PDF text geometry" : "image"}: ${ex.measured} of ${ex.slots} words measured.</p>
      ${checks}
      <p style="margin-top:14px"><a class="btn" href="/api/case/${encodeURIComponent(r.case_id)}/evidence_bundle.json">Download evidence bundle</a>
      <a class="btn ghost" href="/api/case/${encodeURIComponent(r.case_id)}/report.json">Report (JSON)</a>
      ${F.length ? `<button class="primary" id="btn-verify">Verify independently</button>` : ""}</p>
      <pre id="verify-out" hidden></pre>
    </div><div>
      ${r.preview ? `<h3>Evidence</h3><img class="preview" src="${r.preview}" alt="The leaked file">` : ""}
      <p class="hint">${esc(r.evidence.filename)} · SHA3-256 <span class="mono">${short(r.evidence.sha3_256, 16)}…</span><br>
      Investigation by ${esc(r.investigation.officer)}, logged at block ${r.investigation.forensic_access_block};
      finding committed at block ${r.investigation.finding_block}.</p>
    </div></div></div>`;
  const vb = $("#btn-verify");
  if (vb) vb.onclick = () => busy(vb, "Verifying…", async () => {
    const v = await api(`/api/case/${encodeURIComponent(r.case_id)}/verify`, {method: "POST"});
    const o = $("#verify-out"); o.hidden = false; o.textContent = v.output;
  });
}

/* ------------------------------------------------------------------ audit */
function renderCheckpoints() {
  $("#cp-list").innerHTML = S.checkpoints.length ? S.checkpoints.map((c) => `<li class="mono">${esc(c)}</li>`).join("") : `<li class="mut">None exported yet.</li>`;
}
$("#btn-cp").onclick = (e) => busy(e.target, "Exporting…", async () => {
  const r = await api("/api/checkpoint", {method: "POST"});
  toast(`Checkpoint at block ${r.height} saved with ${r.signatures} node signatures`);
  await loadState();
});
$("#tamper-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const fd = new FormData(e.target);
  busy(e.target.querySelector("button"), "Tampering…", async () => {
    const r = await api("/api/tamper", {json: {node: fd.get("node"), kind: fd.get("kind")}});
    toast("Done: " + r.change + ". Now run an audit.");
  });
});
$("#btn-audit").onclick = (e) => busy(e.target, "Auditing…", async () => {
  const a = await api("/api/audit", {method: "POST"});
  const nodes = Object.values(a.nodes).map((n) => {
    const bad = n.ok === false || n.diverged;
    const what = n.ok === null ? `<span class="pill mut">unreachable</span>` : n.ok === false ? `<span class="pill bad">failed at block ${n.corrupted.height}</span>` : n.diverged ? `<span class="pill bad">diverged from quorum</span>` : `<span class="pill ok">verified</span>`;
    return `<div class="anode ${bad ? "bad" : ""}"><h4>${n.node_id}</h4>${what}
      <p class="hint">${n.ok === false ? esc(n.corrupted.reason) : n.ok ? `Blocks 0 to ${n.verified_height} verified from genesis` : esc(n.error || "")}</p>
      ${bad ? `<button class="small" data-heal="${n.node_id}">Heal from quorum</button>` : ""}</div>`;
  }).join("");
  const cps = a.checkpoints.map((c) => `<li>${c.ok ? `<span class="pill ok">holds</span>` : `<span class="pill bad">violated</span>`} checkpoint at block ${c.height}, exported ${fmtTime(c.exported_at)}
     ${c.ok ? "" : `<br><span class="mut">${Object.entries(c.nodes).filter(([, v]) => v !== "match").map(([k, v]) => `${k} ${v === "MISMATCH" ? "holds a different block at this height: history was rewritten after the checkpoint" : v === "MISSING" ? "no longer holds this block" : v}`).join("; ")}.</span>`}</li>`).join("");
  $("#audit-out").innerHTML = `<p><b>${a.ok ? "Ledger intact." : "Tampering detected."}</b> ${a.healthy} of ${a.total} nodes verified their full chain.</p>
    <div class="auditnodes">${nodes}</div>
    <h3 style="margin-top:16px">Offline checkpoints</h3><ul class="plain">${cps || `<li class="mut">No checkpoints to compare. Export one before tampering to catch history rewrites.</li>`}</ul>`;
  loadLanes();
});
$("#audit-out").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-heal]"); if (!b) return;
  busy(b, "Healing…", async () => { const r = await api(`/api/heal/${b.dataset.heal}`, {method: "POST"}); toast(`${b.dataset.heal}: ${r.refetched} blocks re-fetched and verified`); $("#btn-audit").click(); });
});

/* ------------------------------------------------------------------ people */
function renderPeople() {
  const rows = Object.entries(S.certs).map(([serial, c]) => {
    const st = c.status === "active" ? `<span class="pill ok">active</span>` : c.status === "revoked" ? `<span class="pill bad">revoked at block ${c.revoked_at}</span>` : `<span class="pill mut">rotated at block ${c.superseded_at}</span>`;
    const act = c.status === "active" && c.role !== "forensic" ? `<button class="small" data-rot="${esc(c.subject_id)}">Rotate key</button> <button class="small danger" data-rev="${esc(c.subject_id)}">Revoke</button>` : "";
    return `<tr><td><b>${esc(c.display_name)}</b><br><span class="mut">${esc(c.subject_id)}</span></td><td>${esc(c.role)}</td><td>${st}</td><td class="mono">${short(c.fingerprint, 16)}…</td><td>${c.enrolled_at}</td><td>${act}</td></tr>`;
  }).join("");
  $("#people").innerHTML = `<tr><th>Person</th><th>Role</th><th>Certificate</th><th>ML-DSA key fingerprint</th><th>Enrolled at block</th><th></th></tr>` + rows;
}
$("#people").addEventListener("click", (e) => {
  const b = e.target.closest("button"); if (!b) return;
  const sid = b.dataset.rev || b.dataset.rot;
  if (b.dataset.rev && !confirm(`Revoke ${sid}'s certificate? They will no longer be able to open documents.`)) return;
  busy(b, "…", async () => {
    const r = await api(`/api/identity/${sid}/${b.dataset.rev ? "revoke" : "rotate"}`, {method: "POST", json: {}});
    toast(`${b.dataset.rev ? "Revoked" : "Rotated"} at block ${r.block}`); await loadState(); loadLanes();
  });
});
$("#enroll-form").addEventListener("submit", (e) => {
  e.preventDefault();
  const fd = Object.fromEntries(new FormData(e.target));
  busy(e.target.querySelector("button"), "Issuing…", async () => {
    const r = await api("/api/identity", {json: fd});
    toast(`Certificate issued and enrolled at block ${r.block}`); e.target.reset(); await loadState(); loadLanes();
  });
});

/* ------------------------------------------------------------------ attack lab */
let labTimer = null;
async function labStatus() {
  const s = await api("/api/attacklab").catch(() => null);
  if (!s) return;
  const log = $("#lab-log");
  if (s.log.length) { log.hidden = false; log.textContent = s.log.join("\n"); log.scrollTop = log.scrollHeight; }
  $("#btn-lab").disabled = s.running;
  $("#lab-status").textContent = s.running ? "Running…" : s.error ? "Failed: " + s.error : s.report ? `Last run: ${s.report.document}, ${s.report.slots} watermark words.` : "No results yet.";
  $("#lab-link").hidden = !s.report;
  if (s.report) {
    $("#lab-out").innerHTML = s.report.deltas.map((d) => `<h3 style="margin-top:14px">Shift ±${d.delta_pt} pt · PSNR ${d.visual.psnr_db_min} dB · SSIM ${d.visual.ssim_min}</h3>
      <div class="scroll"><table class="tbl"><tr><th>Leak route</th><th>Result</th><th>Score ÷ threshold</th><th>Symbols read</th></tr>${d.attacks.map((a) =>
      `<tr><td>${esc(a.attack)}</td><td><span class="pill ${a.ok ? "ok" : a.verdict.includes("FALSE") ? "bad" : "mut"}">${esc(a.verdict)}</span></td><td>${a.ratio}</td><td>${a.positions_read} of ${a.code_length}</td></tr>`).join("")}</table></div>`).join("");
  }
  if (s.running && !labTimer) labTimer = setInterval(labStatus, 2000);
  if (!s.running && labTimer) { clearInterval(labTimer); labTimer = null; }
}
$("#btn-lab").onclick = async () => { try { await api("/api/attacklab", {json: {quick: true}}); labStatus(); } catch (e) { toast(e.message, true); } };

/* ------------------------------------------------------------------ boot */
$("#btn-init").onclick = (e) => busy(e.target, "Creating keys and genesis…", async () => { await api("/api/init", {method: "POST"}); await loadState(); location.hash = "#ledger"; route(); loadLanes(); });
(async () => {
  try { await loadState(); } catch (e) { toast(e.message, true); }
  route(); loadLanes();
  setInterval(loadLanes, 3000);
})();
