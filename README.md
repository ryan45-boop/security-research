# Security research

Public work by **Ryan Mwendwa** — ryanmwn45@gmail.com · [HackerOne](https://hackerone.com/ryanmwn07) · Nairobi, Kenya.

Security research I've done in the open. Everything here is reproducible from public sources,
and where something is unverified I say so rather than dressing it up.

## What's here

| Document | What it is |
|---|---|
| [`01-gitlab-spp-bypass-analysis.md`](01-gitlab-spp-bypass-analysis.md) | Root-cause analysis of an **open, unfixed** Secret Push Protection bypass in GitLab (issue #632847). Traced to the specific line in their source, with three proposed fixes. |
| [`02-threat-landscape-cisa-kev.md`](02-threat-landscape-cisa-kev.md) | Threat-landscape brief primary-sourced from CISA's Known Exploited Vulnerabilities catalog, including GitLab's own CVE history. |
| [`03-verification-ledger.md`](03-verification-ledger.md) | Every test I ran and every negative result — including a full git-history sweep of four Proton crypto repositories where all 1,211 PEM matches turned out to be test vectors, and were therefore **not** reported. |

## How I work

**Verify before reporting.** I've withheld findings that failed verification and recorded
them as negatives instead. Differential authorisation testing — the same request to sibling
endpoints, showing which enforce a check and which don't — is how I found a missing auth
check that returned suppressed internal content while three neighbouring endpoints correctly
returned 401.

**Check for duplication first.** Before writing anything on #632847 I pulled GitLab's public
security tracker and built a dedupe baseline. I still flagged three things I couldn't verify
in the analysis itself, because the work may already be underway and I'd rather stop than
duplicate.

**Say what I don't have.** I'm 19, self-taught, diploma in progress, no formal
certification, no EU work authorisation. All of that is stated in the documents rather than
left to be discovered.

## Tooling

I use OpenCode, an agentic AI research tool, to drive the mechanical work — enumeration,
git-history forensics, differential endpoint testing, evidence capture — so my own time goes
on the judgement calls. For the GitLab analysis I read and followed their in-repo
`AGENTS.md`, which specifies how AI-authored contributions must be formatted.

## Notes

Every number in these documents traces to a primary source I actually read — GitLab's
repository, CISA's catalog. Where a claim is reasoned rather than confirmed, it says so
in the document itself.
