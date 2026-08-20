# Project conventions

## File naming

- **Markdown filenames are UPPERCASE and use underscores (`_`), not hyphens (`-`).**
  Examples: `PLATFORM_OVERVIEW.md`, `README.md`, `GETTING_STARTED.md`.
  (Conventional names like `README.md` already comply.)

 - Renaming an existing doc means updating every reference to it — the `CLAUDE.md` index row, other docs, ADRs, and the source comments that cite it (there were 40 files for the two renamed above).

## Diagrams

- **Use [Mermaid](https://mermaid.js.org/) fenced code blocks** for diagrams in markdown — architecture, flows, sequences, ER — not ASCII art.
- Plain directory/file listings may stay as fenced code blocks (they are listings, not diagrams).

## Per-area conventions load with the area

Rules that only bind one to one folder live in to it, so they cost nothing when you're working elsewhere

## Linting & formatting (Biome)

Every applicable file will be linted, formatted and corrected before committing, e.g. markdown, typescript and go sources.

## Testing

- **Every new functionality will be accompanied by one or more tests**, testing the new functionality. Either through unit or integration tests.
- **When you fix a bug, add a regression test for it.** Every found-and-fixed issue gets a test that fails on the bug and passes with the fix — a unit test next to the code asserting the specific behavior that was broken. This locks the fix in so the regression can't silently return, and doubles as documentation of the edge case. (See also `docs/project_notes/bugs.md`.)

## Not in production — skip back-compat / deprecation churn

If a project is not yet in production, you generally don't need to preserve backward compatibility or add deprecation shims unless stated otherwise. **When you rename, change, or remove** something, do it **outright**: update every call site, drop the old field/column/endpoint/flag/setting, and delete the dead code — rather than keeping a `@deprecated` alias, a compatibility wrapper, a "legacy" fallback branch, or a migration path for clients/data that don't exist yet. There are no external consumers to break and no historical rows to preserve, so a clean break is simpler and leaves no rot to clean up later.

**Exceptions** are narrow: an in-flight migration you are *deliberately* rolling out in stages, or a genuinely external contract (a third-party webhook/PSP payload shape). Those are rare here — when in doubt, prefer the clean break and say so in the PR.


## Document index

The project specific CLAUDE.md will carry an index of the repository's docs at a glance. Each design doc carries its own **Status** and detail in its header — this is the map, not the territory. Keep it in sync: when you add a doc under `docs/`, add a row here (filenames follow the UPPERCASE + underscores rule above).

**A row is one line.** Name the subsystem, the ADR, a short description, and the build state — nothing else. 
**Rationale, measurements, phase-by-phase history and design arguments belong in the doc**, where someone reading them has the context to use them. If a fact is load-bearing enough to be read by an agent who will *never open the doc*, it is not an index row — it is a section of its own.

### Status is part of the change, not a follow-up

**A PR that changes build state must update the affected doc's `Status:` line and its row in this index, in the same PR.** Shipping a phase and leaving the header saying "Proposed" is not a
tidy-up task for later — it is the change being half-done.

This is the single most common form of rot in the repo.

A failure mode worth naming, because neither is caught by reviewing your own diff:

- **Work that lands under another doc's banner.** **If your PR makes another doc's status wrong, that doc is part of your PR.**

The direction that matters most is **"says built but is not built"** — it makes people rely on something absent. 

When editing docs programmatically, **assert the match before replacing**. 

## Project Memory System

This project maintains institutional knowledge in `docs/project_notes/` for consistency across sessions.

### Memory Files

- **BUGS.md** — Bug log with dates, solutions, and prevention notes
- **DECISIONS.md** — Architectural Decision Records (ADRs) with context and trade-offs
- **KEY_FACTS.md** — Project configuration, document inventory, important references (never secrets)
- **WORK_LOG.md** — Work log with ticket IDs, descriptions, and URLs

### Memory-Aware Protocols

**Before proposing architectural changes:**

- Check `docs/project_notes/decisions.md` for existing decisions
- If the proposed approach conflicts with a past choice, acknowledge it and explain why revisiting makes sense

**When encountering errors or bugs:**

- Search `docs/project_notes/bugs.md` for similar issues
- Apply known solutions if found; document new bugs and solutions when resolved

**When looking up project configuration:**

- Check `docs/project_notes/key_facts.md` for document names, tool names, environment info
- Prefer documented facts to assumptions

**When completing work:**

- Log completed work in `docs/project_notes/work_log.md`
- Include ticket ID (if any), date, brief description

**When user requests memory updates:**

- Update the appropriate file following its established format

---

## Shared working tree — git discipline

**Multiple Claude sessions often run against this repo at the same time.** Unless you were launched in your own `git
worktree`, you share one working directory, one `HEAD`, and one index with the other sessions — so any branch switch or
history rewrite you perform yanks the tree out from under them mid-task.

**Because of this, every session MUST work in its own `git worktree`** — including editing, not just the final
commit. Editing in the shared primary tree is what causes the collisions (files changed under you mid-edit, merge
conflicts on shared docs). Do **all** of your
work — edit, verification, ship — inside the worktree.

**This is now enforced**, so there's no setup friction and no accidental shared-tree commits:

- **Worktrees live INSIDE the repo root**, under the gitignored **`.claude/worktrees/<topic>`** — the same place
  the harness's own worktrees live. **Never create a worktree outside the project root** (no `../of1-*` siblings):
  they clutter the parent directory, and a compose stack recreated from such a path pins its bind mounts to the
  soon-to-be-deleted sibling. `.claude/worktrees/` is already in `.gitignore`, so nothing there is ever committed.
- **`npm run worktree <topic>`** (`scripts/worktree.sh`) creates `.claude/worktrees/<topic>` on a new branch off
  `origin/main` **and** installs its deps + builds `@of1/shared` + generates the Prisma client, so `npm run verify`
  runs immediately. `cd` into it and stay there. (Equivalent to the `EnterWorktree` tool — which also uses
  `.claude/worktrees/` — or an `Agent` with `isolation: "worktree"`; those are fine too.)
- A **pre-commit hook** (lefthook, `scripts/guard-shared-tree.sh`) **refuses commits on the primary tree's `main`**
  — so shared-tree work can't be committed; you land everything from a worktree branch. It's a no-op inside a
  linked worktree.

Only stay on the primary tree for quick, read-only work, and even then assume another Claude may change files under
you at any moment — re-check on-disk state right before editing, and never trust that `git status` reflects only your
own changes.

**Never run these on a shared tree** (they mutate the shared `HEAD`/index/files):

- `git checkout <branch>` / `git switch` to a *different* branch, `git reset --hard`, `git stash`, `git rebase`,
  `git clean`. This includes the "reconcile local `main`" step some skills end with (`git checkout main &&
  git reset --hard origin/main`) — skip or defer it when sharing a tree.

**Do instead:**

- Keep all work on the branch you were started on; commit there and push. Integrate via PR merges on the remote, which
  never touch your local `HEAD`.
- Need `main` up to date for a diff/base? Use `git fetch origin` and compare against `origin/main` — don't check out or
  reset local `main`.
- Stage explicitly by path (`git add <path>`), never `git add -A`; the tree may hold another session's files or
  script side-effects (e.g. a bumped `*.cert.srl`).
- Verify a file's current on-disk state right before editing — an earlier snapshot may be stale if another session
  touched it.

**To actually work in parallel safely,** each session should be launched in its own worktree (`git worktree add
.claude/worktrees/<topic> -b <topic>`, then start Claude there) — or a session can call the `EnterWorktree` tool /
delegate via an `Agent` with `isolation: "worktree"`. Worktrees share the `.git` object store (no re-clone) but have
independent `HEAD`s, so branch switches and resets are isolated. Keep the path inside the repo root
(`.claude/worktrees/`), never a `../of1-*` sibling.

## Beads — repo notes (hand-owned)

**This section is hand-written and authoritative, and it deliberately sits OUTSIDE the generated
beads block below** — the region fenced by the `bv` agent-instruction HTML comment markers. Everything
inside that region is generated: **do not run `br agents --add` / `--update`** — they rewrite the whole
region, and anything left inside it is lost without a trace. These rules live out here because they
are repo-specific and are *not* in `br --help` / `bv --help`, so nothing else records them. If the
generated block ever swallows them again, restore them here.

- **A bead id is always `<prefix>-<XXX>`** — the workspace prefix defined in `.beads/config.yaml`
  (the `issue_prefix` key; `whois` in this repo) plus the three+ character token `br` mints, and nothing
  else: `whois-gq5`, `whois-m45`, `whois-q1rfj`. **Let `br create` assign it; never pass `--id` to
  hand-build a descriptive one.** A slug in the id is a second, worse copy of the title — it goes stale
  when the title is corrected, it is long enough that citing it in a commit or PR body invites a typo,
  and it buys nothing `br search` doesn't already give you.
- **If a slug id ever appears, renaming it is create-then-delete** — `br` has no rename. Copy the
  description byte-for-byte from the record, carry `--notes` and re-add every `br dep` edge (re-pointed
  at the new id on *both* ends), then `br delete --reason "renamed to <new-id>"`. The tombstone that
  leaves is the point: it answers the old id with the new one, so a reference in an old commit message
  resolves to a pointer rather than to nothing. Order matters — a delete is refused while a live record
  still depends on the target.
- **`br search "<keyword>"`** — full-text search across issues. Reach for it before guessing at an id.
- **This repo's git discipline overrides any beads workflow advice**, including the generated block's
  own Git Policy below. Commits are landed **from a worktree branch**, never on the shared tree's
  `main`, and git actions happen when asked rather than on a schedule.
- **The JSONL is a whole-file export, so a stale flush silently clobbers other sessions.**
  `.beads/issues.jsonl` is a whole-file export of `.beads/beads.db` — SQLite, and gitignored, so there
  is **one DB per checkout** and each worktree carries its own. A flush from a DB that predates someone
  else's changes rewrites the entire file and drops them, and because git sees a rewrite rather than
  overlapping hunks there is **no conflict and no error** — last flush wins, silently.
- **Sync immediately before any `br` mutation, and re-check after it merges.** Before `br create` /
  `update` / `close`: `git fetch origin` and make sure your worktree is on current `origin/main`. A
  fresh worktree has no `beads.db`, so `br` rebuilds it from the committed JSONL — which is what you
  want; an old worktree's stale DB is the hazard. (With no remote configured the fetch is a no-op, but
  the hazard is still live between worktree branches, which each carry their own DB.)
  - After: the `.beads/issues.jsonl` diff must be **a few lines, not a file rewrite**. A rewrite means
    you are about to clobber someone. Land it promptly — the window is the exposure.
    (This holds for `br` in a checkout, **with** its database, which appends. `br --no-db` legitimately
    *reorders* the whole file — one added record can show as ~27 added / ~26 removed lines with every
    record still byte-identical — so in that mode compare record **sets**, not line counts.)
- **`br sync --flush-only` printing `Nothing to export (no dirty issues)` is normal** — `br` writes the
  JSONL eagerly, so the flush is usually a no-op. It is **not** evidence your change was lost, and not a
  reason to retry it or re-create the issue.
- **Ids do not survive a clobber** — a re-created issue gets a new id, so anything citing the old one (a
  PR body, a commit message) silently points at nothing. Reference beads by title in prose that outlives
  them.

<!-- bv-agent-instructions-v3 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`) for issue tracking and [beads_viewer](https://github.com/Dicklesworthstone/beads_viewer) (`bv`) for graph-aware triage. Issues are stored in `.beads/` and tracked in git. Current `br` workspaces normally export `.beads/issues.jsonl`; older `bd`/legacy workspaces may use `.beads/beads.jsonl`. `bv` auto-discovers the supported JSONL files, so agents should use `br`/`bv` commands instead of hard-coding a single filename.

### Using bv as an AI sidecar

bv is a graph-aware triage engine for Beads projects. Instead of parsing .beads/issues.jsonl / .beads/beads.jsonl directly or hallucinating graph traversal, use robot flags for deterministic, dependency-aware outputs with precomputed metrics (PageRank, betweenness, critical path, cycles, HITS, eigenvector, k-core).

**Scope boundary:** bv handles *what to work on* (triage, priority, planning). `br` handles creating, modifying, and closing beads.

**CRITICAL: Use ONLY --robot-* flags. Bare bv launches an interactive TUI that blocks your session.**

#### The Workflow: Start With Triage

**`bv --robot-triage` is your single entry point.** It returns everything you need in one call:
- `quick_ref`: at-a-glance counts + top 3 picks
- `recommendations`: ranked actionable items with scores, reasons, unblock info
- `quick_wins`: low-effort high-impact items
- `blockers_to_clear`: items that unblock the most downstream work
- `project_health`: status/type/priority distributions, graph metrics
- `commands`: copy-paste shell commands for next steps

```bash
bv --robot-triage        # THE MEGA-COMMAND: start here
bv --robot-next          # Minimal: just the single top pick + claim command

# Token-optimized output (TOON) for lower LLM context usage:
bv --robot-triage --format toon
```

Before claiming, verify current state with `br show <id> --json` or `br ready --json`. `recommendations` can include graph-important blocked or assigned work; only `quick_ref.top_picks` and non-empty `claim_command` fields represent claimable work.

#### Other bv Commands

| Command | Returns |
|---------|---------|
| `--robot-plan` | Parallel execution tracks with unblocks lists |
| `--robot-priority` | Priority misalignment detection with confidence |
| `--robot-insights` | Full metrics: PageRank, betweenness, HITS, eigenvector, critical path, cycles, k-core |
| `--robot-alerts` | Stale issues, blocking cascades, priority mismatches |
| `--robot-suggest` | Hygiene: duplicates, missing deps, label suggestions, cycle breaks |
| `--robot-diff --diff-since <ref>` | Changes since ref: new/closed/modified issues |
| `--robot-graph [--graph-format=json\|dot\|mermaid]` | Dependency graph export |

#### Scoping & Filtering

```bash
bv --robot-plan --label backend              # Scope to label's subgraph
bv --robot-insights --as-of HEAD~30          # Historical point-in-time
bv --recipe actionable --robot-plan          # Pre-filter: ready to work (no blockers)
bv --recipe high-impact --robot-triage       # Pre-filter: top PageRank scores
```

### br Commands for Issue Management

```bash
br ready --json                       # Show issues ready to work (no blockers)
br list --status=open --json          # All open issues
br show <id> --json                   # Full issue details with dependencies
br create --title="..." --type=task --priority=2 --json
br update <id> --status=in_progress --json
br close <id> --reason="Completed" --json
br close <id1> <id2> --reason="Completed" --json
br sync --flush-only                  # Export DB to JSONL after Beads mutations
```

### Workflow Pattern

1. **Triage**: Run `bv --robot-triage` to find the highest-impact actionable work
2. **Claim**: Use `br update <id> --status=in_progress --json`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id> --reason="Completed" --json`
5. **Sync**: Run `br sync --flush-only` after Beads mutations so the JSONL export is current

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready --json` shows only unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers 0-4, not words)
- **Types**: task, bug, feature, epic, chore, docs, question
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Git Policy

`br` never commits or pushes. Follow this repository's own git instructions before staging, committing, or pushing. If the repository says "commit only when asked," that rule overrides any generic workflow advice.

<!-- end-bv-agent-instructions -->
