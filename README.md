# Nishaan: post-quantum decryption provenance and leak attribution

MVP for **SIH Problem Statement 26237** (Ministry of Defence, Indian Navy / WESEE):
*Cryptographic Attribution and Immutable Decryption Provenance for Multi-Recipient Encrypted Document Distribution.*

A document is encrypted once and sent to many officers. Every decryption produces a copy that
looks identical but carries an invisible fingerprint unique to that recipient and session. Each
decryption is signed with the recipient's own ML-DSA key and committed to an offline,
Byzantine-fault-tolerant ledger *before* the key is released. Given a leaked PDF, screenshot,
photo or scan, the forensic tool names the recipient(s) responsible and produces an evidence
bundle signed by the investigating officer that an independent verifier can check. Everything runs air-gapped: no cloud KMS, no public
blockchain, no internet.

```
unique per-session watermark  +  recipient's PQC signature  +  immutable offline ledger  =  attribution
```

## Quick start

Python 3.10+.

```bash
pip install -r requirements.txt        # pure-Python PQC; add liboqs for speed, see "Crypto backends"
python -m nishaan demo                 # full scripted demo, about 25 s
python -m nishaan ui                   # local console on http://127.0.0.1:8080
```

The demo follows section 14 of the brief: setup, distribution, two recipients decrypt, the copies
look identical but carry different fingerprints, the ledger entries, a phone photo of Bob's screen
is traced to Bob, the evidence bundle is verified independently, two colluders average their
copies, and an administrator's tampering is detected. It writes `demo_output/` and `nishaan-data/`.

The console walks through the same story by hand: **Send, Open, Compare (with a blink comparator),
Trace a leak, Audit**. It also has controls to take nodes offline, make a node malicious, tamper as
an administrator, and run the attack lab.

Step-by-step CLI:

```bash
python -m nishaan init                                   # offline CA, 4 ledger nodes, genesis, demo identities
python -m nishaan send brief.pdf --title "Brief" --to alice,bob,carol
python -m nishaan open <doc_id> --as bob --out bob.pdf   # commit-before-decrypt
python -m nishaan investigate leaked.jpg                 # report + evidence bundle in nishaan-data/cases/
python -m nishaan verify-bundle nishaan-data/cases/<case>/evidence_bundle.json --trust-anchor <fp>
python -m nishaan cluster up                             # run the 4 nodes as separate processes (HTTP)
python -m nishaan checkpoint export --out /media/usb     # signed checkpoint for an offline witness
python -m nishaan attack-lab                             # robustness + visual identity report (~4 min)
```

## How it works

```
 Sender ──encrypt once (AES-256-GCM)──► package: ciphertext + ML-KEM wrap of K_r[i] per recipient i
   │                                        K = K_r[i] xor K_c[i], each K_c[i] Shamir-split 2-of-4 across nodes
   └─ DISTRIBUTE manifest (ML-DSA signed) ─────────────────────────────┐
                                                                       ▼
 Recipient client                                  ┌──────── offline permissioned ledger ────────┐
  1 sign decryption record (ML-DSA-65)  ─────────► │ node-1  node-2  node-3  node-4 (own keys/DBs)│
  2 committed by PBFT-style consensus     ◄─────── │ PREPARE / COMMIT, 3-of-4 ML-DSA certificates │
  3 nodes release K_c[i] shares (ML-KEM)  ◄─────── │ "no log, no key": only for committed records │
  4 decrypt, verify hash                           └──────────────────────────────────────────────┘
  5 embed session fingerprint (word shifts)                    ▲            │ signed checkpoints
  6 commit delivery receipt (hash of exact copy) ──────────────┘            ▼ to removable media
                                                                       offline witnesses
 Forensic tool: leaked file ─► exact hash? ─► which document? ─► FORENSIC_ACCESS committed
   ─► original decrypted via committee ─► measure word shifts ─► Tardos scores for every session
   ─► verify signature, cert history, Merkle proof, quorum certificate, blind index
   ─► commit FORENSIC_FINDING (symbols hash, error bound, accused) ─► officer-signed report + bundle
```

### Cryptography (NIST PQC only)

| Purpose | Algorithm |
|---|---|
| Key encapsulation (recipient wraps, node shares, escrow) | ML-KEM-768 (FIPS 203) |
| Signatures (records, transactions, votes, certificates) | ML-DSA-65 (FIPS 204) |
| CA root (long-lived, conservative) | SLH-DSA-SHA2-128f (FIPS 205); ML-DSA-87 if liboqs is absent |
| Document encryption | AES-256-GCM |
| Hashing, Merkle trees, blind index, PRFs | SHA3-256 / SHAKE256 |

RSA, ECDH, ECDSA and EdDSA are rejected by the crypto layer (`nishaan/crypto/pqc.py`), and no
classical public-key algorithm appears anywhere. Every signature is domain-separated with a
context string.

**Crypto backends.** `liboqs-python` (fast, C) is used when installed: build liboqs once with
`cmake -GNinja -B build -DBUILD_SHARED_LIBS=ON && ninja -C build install`, then
`pip install liboqs-python`. Otherwise the pure-Python
`kyber-py` / `dilithium-py` implementations are used, which install anywhere with no C toolchain.
Both produce identical FIPS encodings; `tests/test_crypto.py` checks they interoperate. Select one
explicitly with `NISHAAN_PQC_BACKEND=oqs|pure`. SLH-DSA needs liboqs, so a workspace created without
it uses an ML-DSA-87 root.

### Watermark: word-shift fingerprinting with Tardos codes

* **Embedding.** The engine rewrites the PDF content stream directly. It decodes every text operator
  through the font's ToUnicode map and segments words, then moves selected words by ±δ points
  (default 0.35 pt ≈ 0.12 mm) by folding the shift into the line's own kerning numbers. Glyphs,
  fonts and every other drawing are untouched, and nothing else on the page moves. It works on PDFs
  from ReportLab, LaTeX, LibreOffice/Word and Chromium; all four are tested. A rewrite with zero
  shifts renders pixel-identical to the original.
* **Fingerprint.** Each session's codeword comes from a symmetric **Tardos** code: per-document
  secret biases, and the session seed. Symbols are interleaved across all words of the document.
  Colluders who mix or average their copies can only blur symbols where their codes differ, and
  correlation scoring still identifies them.
* **Extraction is informed:** the forensic cell holds the original.
  * *Vector* (leaked PDF): align word sequences, fit an affine transform, read each word's offset.
  * *Raster* (screenshot/photo/scan): SIFT + RANSAC homography to the original render, ECC
    refinement, then sub-pixel Lucas-Kanade shift per word. Line-start/end words never move and act
    as calibration anchors.
* **Accusation threshold.** A recipient is named only if their score exceeds a threshold where the
  probability that an innocent recipient reaches it is ≤ 10⁻⁶. This is a rigorous Chernoff bound
  over the exact per-position distributions, not an approximation. The standalone verifier
  recomputes it.

**Attack lab results** at δ = 0.35 pt, on a 3-page brief with 6 recipient sessions
(`python -m nishaan attack-lab`):

| Leak route | Result | Score ÷ threshold |
|---|---|---|
| Forwarded PDF / re-saved & recompressed PDF | attributed | 2.17 |
| Screenshot at 96 DPI (100% zoom) / 150 DPI | attributed | 1.39 / 1.76 |
| JPEG quality 90 / 60 / 40 | attributed | 1.76 / 1.78 / 1.76 |
| Crop to top half of page | attributed | 1.47 |
| Rotate 3° + scale 85% | attributed | 1.73 |
| Print & scan, *simulated* (300 DPI, blur, skew, noise) | attributed | 1.77 |
| Phone photo, *simulated* (perspective, lighting, JPEG) | attributed | 1.93 |
| Collusion: words spliced from 2 copies | both colluders caught | 1.38 |
| Collusion: pages interleaved / screenshots averaged | 1 of 2 caught (the Tardos guarantee) | 2.52 / 1.30 |

There were no false accusations in any run, at any strength.

**Visual identity:** PSNR 19.0 dB, SSIM 0.939 at 150 DPI. For scale, the *same unmodified file*
rendered by two PDF viewers (PDFium vs Poppler) gives 17.8 dB and 0.905, so the watermark changes
the page less than switching viewer does. At δ = 0.2 pt the numbers are 21.0 dB / 0.961, but
96-DPI screenshots sit right at the threshold and averaged collusion is missed. At 0.5 pt everything
is caught at 0.903 SSIM. That is the invisibility ↔ robustness trade-off from §7.4, measured.

### Forensics and the evidence bundle

1. **Exact copy.** The SHA3 of the leaked file matches a delivery receipt signed by the recipient.
2. **Document match.** Perceptual page hashes from the manifest identify the document.
3. **Fingerprint.** Read the word shifts, then score every decryption session of that document.

The investigation is itself a `FORENSIC_ACCESS` record, and the original is only decryptable once
it commits ("no log, no key" applies to investigators too). Before any report is issued, the
conclusion is committed as a `FORENSIC_FINDING`: the hash of the extracted symbols, the error bound,
the threshold and the accused sessions.

The bundle is signed by the officer. `tools/verify_evidence.py` imports none of this code. It checks:
* the CA root against an out-of-band trust anchor;
* every certificate, Merkle proof and quorum certificate;
* the recipients' signatures on their records and receipts;
* the blind index;
* the finding's bindings.

It then **recomputes the score, the threshold and the false-accusation bound itself**, and enforces a
maximum error rate (`--max-eps`). The extracted symbols are the forensic cell's measurement. A
reviewing authority holding the original can re-run the extraction with
`--original doc.pdf --evidence leaked.jpg`, and the verifier checks the result is identical.

### Ledger: 4-node BFT with PQC-signed blocks

* n = 4, f = 1. Leader-driven PBFT-style protocol: PREPARE, a *prepared certificate*, COMMIT, then
  a *commit certificate* of ⌈(n+f+1)/2⌉ = 3 ML-DSA node signatures stored with each block. Raft is
  not used because it only tolerates crashes, not a malicious administrator.
* Safety rules:
  * Each node votes at most once per (height, view, phase), and never in a lower view than one it
    has already voted in.
  * A node commits only a block it prepared in that view, and locks on it.
  * A lock is only overridden by a prepared certificate from a higher view.
  * A crashed or malicious leader is replaced by a view change. The new leader must re-propose any
    prepared block and sign the re-proposal.
  * The votes and locks tables are part of a node's safety state: restoring a node from an old
    backup means re-enrolling it as a new node.
* Each node has its own key, its own SQLite file, and re-validates every transaction (signatures,
  certificate status, policy). On load it re-verifies its whole chain from genesis. A node that
  fails audit refuses to vote until it is healed from the quorum.
* Transactions: `GENESIS`, `ENROLL` (including key rotation), `REVOKE`, `DISTRIBUTE`,
  `DECRYPT_INTENT`, `DELIVERY_RECEIPT`, `FORENSIC_ACCESS`. Reads are trustless: a Merkle inclusion
  proof plus the commit certificate.
* Nodes run in-process (default) or as separate processes over HTTP on the closed LAN
  (`cluster up`).
* **Signed checkpoints** are exported to removable media for offline witnesses (in the style of
  Certificate Transparency). The tamper lab shows they catch even an attacker holding all four
  node keys who rewrites and re-signs history.

## Requirement coverage

| # | Requirement (brief §2.3) | Where |
|---|---|---|
| 1-3 | Unique, invisible watermark generated at decryption, per recipient & session; copies visually identical | `client.py` step 7, `watermark/` |
| 4-5 | Decryption bound to identity, signed with the recipient's own private key | `DECRYPT_INTENT` record, `client.py` |
| 6 | NIST PQC for key exchange and signatures | `crypto/pqc.py` (ML-KEM-768, ML-DSA-65, SLH-DSA) |
| 7-8 | Immutable DLT; no single admin or compromised account can alter records | `ledger/`, `audit.py`, tests in `test_ledger.py` |
| 9-11 | Extract watermark, look up on ledger, return a verifiable record | `forensics.py`, `tools/verify_evidence.py` |
| 12-14 | Fully offline; no cloud KMS; no public blockchain | everything is local; `airgap.py` blocks outbound sockets |

Supplementary innovations (team note):

| # | Idea | Status |
|---|---|---|
| 1 | Collusion-resistant Tardos fingerprinting | **Done** (symmetric Tardos, rigorous Chernoff threshold) |
| 2 | Commit-before-decrypt with threshold shares, committee-enforced policy | **Done** (per-recipient K_c[i], 2-of-4, share commitments; the committee refuses to log or release beyond max openings / after expiry) |
| 3 | Multi-channel watermark with confidence | Geometry channel done (survives PDF, screen, print, photo). Text-layer (copy-paste) and DCT image channels are roadmap |
| 4 | BFT ledger with PQC-signed blocks + offline checkpoints | **Done** |
| 5 | Anti-framing: blind index on ledger, escrowed seed | **Done** (SHAKE256 blind index; seed ML-KEM-escrowed to the forensic cell) |
| 6 | Layered evidence: exact hash → perceptual hash → watermark; standalone verifier | **Done** (finding committed on ledger, officer-signed bundle, verifier recomputes the threshold and can re-extract) |
| 7 | Ledger-native revocation and key history | **Done** (attribution checks the key was valid at the record's height) |
| 8 | Attack lab with SSIM/PSNR | **Done** (`attack-lab`, console tab) |

## Project layout

```
nishaan/
  crypto/      pqc.py (ML-KEM/ML-DSA/SLH-DSA backends), sym.py (AES-GCM, SHA3, HKDF, KEM-DEM), shamir.py
  pki.py       offline CA, certificates, PIN-protected soft token (HSM/TPM stand-in)
  ledger/      tx, state machine, merkle, block/QC, node (PBFT-style), client, transport, HTTP server
  watermark/   pdftext (content-stream interpreter), plan, tardos, extract (vector/raster), engine, render
  sender.py    encrypt once, wraps, committee shares, manifest
  client.py    recipient: commit-before-decrypt, threshold release, watermark, receipt
  forensics.py three-tier attribution, verification checks, evidence bundle
  audit.py     audits, checkpoints, tamper lab
  attacklab.py robustness & visual-identity measurements
  web/         local console (Flask + vanilla JS, bundled Barlow font, no CDNs)
  cli.py, demo.py, airgap.py, workspace.py
tools/verify_evidence.py   standalone verifier (stdlib + a FIPS 204/205 library only)
tools/ui_shots.py          drives the console with Playwright and saves screenshots (demo prep)
docs/attack_lab_report.*   a full attack-lab run at three watermark strengths
demo/make_sample_docs.py   fictional sample brief (+ LaTeX / LibreOffice / Chromium variants)
tests/                     38 tests: crypto, ledger faults, consensus safety & tampering, watermark
                           robustness, key isolation, malicious shares, expiry, end to end
```

Run the tests with `cd tests && python -m unittest` (about 40 s with liboqs, about 75 s pure Python).

An independent security review of the code (consensus safety, key release, framing and verifier
soundness) found three high-severity issues: a stale-view commit, verifier trust in fields supplied
by the forensic cell, and the quorum size for n > 3f+1. It also found key-isolation and validator
gaps. All are fixed, with regression tests in `test_ledger.py` and `test_end_to_end.py`.

## Honest limitations (what a reviewer will ask)

* **A modified client can skip watermarking.** "No log, no key" guarantees the *record* exists before
  decryption, but the embedding runs on the recipient's machine. Production needs an attested client
  or trusted execution (brief §13). The record alone still proves who decrypted, and when. A client
  that escrows an unreadable watermark seed is flagged in every report as a protocol deviation.
* **Re-open limits bind honest clients.** The committee refuses to log, and so to release keys for,
  openings beyond the limit or after expiry. But a recipient who has decrypted once already holds the
  plaintext. Committee layers are per recipient, so one recipient's key material never lets *another*
  person decrypt without a record. Expiry never blocks investigators.
* **Roots of trust.** The offline CA can issue certificates for anyone, including a forensic officer,
  so it should be held under multi-person control. The forensic cell's extraction is trusted unless an
  authority re-runs it with `--original`; its inputs and conclusion are fixed on the ledger first.
* **Plain-text copy/paste is not attributable.** The geometry channel does not survive retyping or
  copying the text. The text-layer channel (supplement 3a) is the next workstream.
* **Text inside Form XObjects and image-only PDFs** are not watermarked. Documents with fewer than
  64 watermarkable words are refused at distribution.
* **Short leaks carry less evidence.** A page holding only a table (15 words in the sample) is
  reported as *inconclusive* rather than guessed. That is the intended behaviour.
* **The soft token is not an HSM.** Private keys are scrypt + AES-GCM encrypted at rest, and the API
  only exposes `sign`/`decaps`, so a PKCS#11 or TPM token is a drop-in replacement.
* **Consensus is PBFT-lite.** Safety relies on 2f+1 quorum certificates with locking, and view change
  re-proposes prepared blocks. It has not been formally verified, and there is no dynamic membership.
* **Print-and-scan and phone photo are simulated** in the attack lab. Validate with a real printer
  and phone before claiming them.
* After a key rotation, documents wrapped for the old key must be re-issued by the sender.
* Demo convenience: every soft token uses one PIN (`NISHAAN_PIN`, default `nishaan-demo-pin`), and the
  node RPC endpoints are unauthenticated on the closed LAN. All consensus messages, records and key
  shares are still signed or encrypted end to end.

## Licences

Code: yours to choose for the submission. Bundled font: Barlow (SIL OFL 1.1,
`nishaan/web/static/fonts/OFL-Barlow.txt`). Sample documents are fictional.
