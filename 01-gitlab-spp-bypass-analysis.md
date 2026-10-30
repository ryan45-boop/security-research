# Root-cause analysis — GitLab issue #632847: SPP bypass via merging a remote tracking branch

**Researcher:** Ryan Mwendwa · ryanmwn45@gmail.com · HackerOne: ryanmwn07
**Date:** 2026-10-30 · **Target:** `gitlab-org/gitlab` (public repo, `master`)
**Status:** Issue is `opened`, unfixed, severity::2, and explicitly marked *"Everyone can
contribute… earning points, leveling up and collecting rewards."*

> **Verification status of this document.** The bug reproduction and console output are
> quoted from GitLab's own issue (reproduced on GitLab.com by their staff). The code
> quotations are taken from `master` at the time of writing. The root cause is a
> **code-grounded hypothesis**, clearly separated from confirmed fact. GitLab linked
> work_item `603568` as "possibly related" — that item returns **404**, so I could not
> check for overlap, and I could not read the issue's 9 notes (401 on the notes API;
> GitLab keeps security discussion private). Those are the two things to check before
> filing, so as not to duplicate work already done.

---

## 1. The bug

Local branch `bypass-SPP` exists remotely at `cf9dc8a`. Locally:

```
cf9dc8a ── 9250d6e2 ── 2f958a6   (bypass-SPP)
             (secret commit)      (merge of origin/main)
```

- Push `9250d6e2` → SPP **blocks**: *"Secret push protection found the following secrets
  in commit: 9250d6e2… secret.txt:1 | GitLab personal access token"*
- `git merge --no-ff --no-edit origin/main` → merge commit `2f958a6`
- Push `cf9dc8a..2f958a6` → **SPP does not flag it. The secret commit lands in the repo.**

Net effect: Secret Push Protection, whose entire job is to stop a secret entering the
repository, can be walked around by wrapping the secret commit as the first parent of a
merge commit.

---

## 2. The code path

`ee/lib/gitlab/checks/secret_push_protection/payload_processor.rb`

**Step 1 — scope is taken from the new ref tips only.** This is the load-bearing line:

```ruby
def revisions
  @revisions ||= changes_access
    .changes
    .pluck(:newrev)        # <── NEW REV ONLY. `oldrev` is never read.
    .reject { |r| ::Gitlab::Git.blank_ref?(r) }
    .compact
end
```

`changes_access.changes` is the set of ref updates from the push. Taking `:newrev` alone
means the scan has **no concept of a range**. `oldrev..newrev` is never constructed
anywhere in this file.

**Step 2 — the commit set is then narrowed again:**

```ruby
commits = project.repository.new_commits(revisions)
```

**Step 3 — changed paths are derived from that commit set:**

```ruby
paths = project.repository.find_changed_paths(
  commits,
  merge_commit_diff_mode: :all_parents,
  find_renames: true,
  diff_filters: diff_filters
)
```

**Step 4 — the diff pairs are built only from those paths** (`diff_blobs` /
`diff_blobs_with_raw_info`), and only lines beginning with `+` are extracted for scanning
(`DIFF_ADDED_LINE`).

So the entire scan surface is: *ref tips → commits → changed paths → added lines.*
Every one of those four steps narrows. If a secret-bearing commit is absent at step 2,
it is invisible for the rest of the pipeline.

---

## 3. Root cause (hypothesis, argued from the code)

**The enforcement boundary and the data boundary are different things, and SPP only
guards the first.**

- SPP guards **ref updates**. Its abort message is a pre-receive hook rejection, and the
  blocked push proves the ref update can be stopped.
- The secret content travels as **git objects**. Blocking a ref update does not, by
  itself, make the objects unavailable.

The reported bypass puts the same secret-bearing objects into the repository attached to
a *different* ref update — one whose tip is a merge commit — and the pipeline above never
materially examines the secret. The reasons it can fail to, read straight off the code:

1. **`revisions` uses `newrev` only.** The scan is defined by "what does the new tip
   reach", not "what does this ref update introduce." A push whose ref update spans
   several commits has no bounded range.

2. **The merge commit is scanned via `merge_commit_diff_mode: :all_parents`, but its
   parent is not.** For the merge commit `2f958a6`, the diff against its first parent
   (`9250d6e2`, the secret branch) yields exactly what the console output shows —
   `README.md | 2 ++`, i.e. the changes that came from `origin/main`. The diff is
   correct. It just does not contain the secret, because **relative to `9250d6e2` the
   secret is not new; it was already there in parent 1.** The secret lives in the diff
   against the *other* parent or in parent 1's own diff, and neither is part of the
   scanned commit set once step 2 has narrowed it.

3. **Consequently `diff_blobs` never sees a blob pair whose added lines contain the
   token.** `diff_blobs` skips any path where `path.old_blob_id == path.new_blob_id`
   (unchanged content is not a diff), and only `+` lines are extracted. A secret that is
   already present in the first-parent side of a merge is therefore "unchanged" from the
   perspective the scan actually takes.

**One sentence:** SPP authorizes ref updates, but admits secret content through git
objects; a merge commit lets an attacker attach an already-uploaded, secret-bearing
commit as a parent while the scan examines only the merge's own diff — which, against
that parent, correctly shows no secret.

---

## 4. What to verify before this is asserted (must-do, to avoid duplicating)

1. **Read the 9 notes on the issue.** I could not (401). The notes API is closed; view
   them signed in. Someone may already have proposed exactly this.
2. **Resolve work_item `603568`** (GitLab: "possibly related"). It 404s for me, so it is
   private or deleted. Someone with access must check.
3. **Confirm what `repository.new_commits(revisions)` actually returns.** Whether it is
   object-presence-filtered or ref-reachability-filtered decides whether the secret
   commit is excluded at step 2 or merely mis-diffed at step 3. This single fact
   distinguishes two different fixes, and I could not verify it without reading
   `Gitlab::Git::Repository#new_commits` and the Gitaly call it makes.
4. **Reproduce locally** with a scratch project to confirm the merge's changed-path set
   really omits `secret.txt`.

---

## 5. Proposed fix directions (both are consistent with the code)

**Fix A — scan the ref-update range, not the tips.**
Build `oldrev..newrev` from `changes_access.changes` and scan every commit in that range.
This makes the scanned set equal to what the push introduces, which is what SPP is
supposed to guard, and it is immune to how objects happened to arrive.

**Fix B — make merge commits self-contained for scanning.**
When `find_changed_paths` is called with `merge_commit_diff_mode: :all_parents`, ensure
the commit set includes **all parents** of any merge commit encountered — not just the
commits deemed new — so the first-parent history is genuinely diffed.

**Fix C (defence in depth, and the one I'd argue for) — verify objects, not just refs.**
SPP's guarantee is about content entering the repository. The durable fix is to make the
hook's blocking condition depend on object presence/absence independently of the ref
update that carries them, so that a secret commit which was ever rejected cannot be
admitted later by another route.

**Do not** rely on `MAX_LINES_PER_REQUEST` / `MAX_CHANGED_PATHS` limits — they are
timeout guards, not security controls, and both are large enough that a single secret
sails under them.

---

## 6. What I'd file on the issue

A comment that leads with the reproduction already in the issue, then the three-line
root cause (tips → commits → paths; `newrev` only; merge diff against parent 1 shows no
secret), then Fix A/B/C, then the four verification items from §4. No claim of
confirmation until §4 items 3 and 4 are done.

**Deliberately not claimed:** that I found this bug (GitLab's staff reproduced it), that
my root cause is confirmed rather than reasoned, or that any fix is validated. All
three would be false.

---

## 7. Note on how this was researched

- Bug and repro: GitLab issue #632847 (theirs).
- Code: `payload_processor.rb` from `master`, fetched read-only. No local clone of the
  GitLab monorepo, no GDK setup, no traffic to GitLab.com beyond fetching public
  repository files.
- Dedupe performed before writing: GitLab's public security-labelled issue tracker
  (60 issues, taxonomy extracted), the two currently-open security issues, and the
  "possibly related" work_item.
- Explicitly out of scope and not done: pentesting GitLab.com (requires written
  permission per their policy), MITM/the-payload_processor's gRPC service, and any test
  against the SDS gem.
