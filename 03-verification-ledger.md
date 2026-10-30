# Verification ledger — every test, every negative result
Ryan Mwendwa · 2026-10-30

Rule I work to: nothing is submitted until it is verified, and negative results are recorded
rather than hidden. This is the record so nobody repeats the same work.

## Proton (in-scope products, read-only, no account created, no traffic beyond public endpoints)

Differential-authentication testing across four products:

| Product | Endpoints probed | Result |
|---|---|---|
| SimpleLogin | /api/user_info, /api/aliases, /api/mailboxes, /api/custom_domains, /api/settings, /api/auth/login | all correctly 401/405 — enforced |
| Proton Pass | /api/settings | gateway routing error, not a bypass |
| Proton Drive / Docs | /api/, /api/import, /api/uploads | 404 — no pre-auth ingestion |
| Standard Notes | /api/, /importer | 404/301 — no pre-auth ingestion |

CSP analysis — the one real asymmetry found:

| Product | script-src | Assessment |
|---|---|---|
| Proton Pass | `'self' 'wasm-unsafe-eval' blob:` + `sha256-...` | hash-based, hardened |
| Proton Mail | identical | hardened |
| **SimpleLogin** | `'unsafe-inline' 'unsafe-eval'` + 3rd parties | **weak — no nonce/hash** |

Recorded as *targeting intelligence, not a reportable finding*: a weak CSP is defence-in-depth
only, and Proton's own policy excludes best-practice findings with no concrete exploit path.
This is why it is in the ledger and not in a bug report.

DNS / mail posture (passive, DNS-over-HTTPS, two independent resolvers, re-verified):

| Domain | DMARC | Subdomain policy | Finding |
|---|---|---|---|
| proton.me | p=quarantine, no rua | unset (inherits) | quarantines rather than rejects; no monitoring |
| protonvpn.com | p=quarantine | unset | CAA includes an iodef address — done right |
| simplelogin.io | p=reject | **sp=none** | **subdomain spoofing unprotected** |
| standardnotes.com | p=quarantine | unset | **DNSSEC absent** |

Same judgment: posted as a courtesy hardening note at most. Proton's policy would decline
these as non-exploitable, and I would rather they know I understand that distinction than
inflate them.

## GitHub — git-history forensics, full sweep

| Repo | Blobs scanned | PEM/CERT matches | Classification |
|---|---|---|---|
| ProtonMail/go-crypto | 6,382 | 1,211 lines | all test vectors |
| ProtonMail/proton-crypto-rs | 1,576 | PGP constants + assert! strings | all test vectors |
| ProtonMail/gosop | 342 | bare PGP key | test vector |
| ProtonMail/rustls-platform-verifier | 647 | none | clean |

Method: full mirror clone, `git cat-file --batch-all-objects`, then classification of every
PEM block against test-context markers. Result: **no real key material anywhere in Proton's
crypto repositories' history.** The one live private key I have ever found this way was in
deriv-com/traders-hub — and the difference was decisive and checkable: that key was a real
2048-bit RSA key whose modulus matched a real certificate and which carried a real developer
identity. These did not, and so they were not reported.

## What was explicitly NOT done, and why

- No account was created on any target. Every test was unauthenticated against public
  endpoints.
- No pentesting of GitLab.com — their policy requires written permission upfront and I have
  not requested it.
- No dependency-CVE sweep was completed. It is GitLab's dominant bug class (12 of 60
  security issues are gem CVEs) and it is the next thing I would do.
- No Kubernetes/cloud/container exploitation — outside what has been authorised.

## Prior disclosures in flight (so you know I'm not starting from zero)

- deriv-com/traders-hub — a live TLS private key recovered from public git history, verified
  against its matching certificate, disclosed to security@deriv.com and escalated to
  HackerOne support. Currently in coordination.
- butik.atg.se — missing authentication on an endpoint returning suppressed CMS content,
  reproduced and verified against sibling endpoints that correctly return 401. Disclosed
  to vuln@atg.se and awaiting triage.
- Two reports on a public bug bounty platform, both triaged.
