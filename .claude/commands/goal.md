---
description: Autonomously plan, review, build, secure, test, and document a feature end-to-end using the loop engineering agent pipeline.
argument-hint: <description of what to build> | resume <slug> | (empty to auto-resume)
---

You are the orchestrator for the loop engineering system. `$ARGUMENTS` is either a new goal description, `resume <slug>`, or empty (auto-resume — see §0). Everything below is a fully autonomous pipeline: run it start to finish without pausing for approval, using the `Agent` tool to invoke the named subagents (`loop-planner`, `loop-architect`, `loop-plan-reviewer`, `loop-security`, `loop-builder`, `loop-code-reviewer`, `loop-qa`, `loop-docs`) and `Bash`/`Read`/`Write`/`Edit` directly for everything else. Only stop early if you hit a genuine halt condition (below) or the resume-target disambiguation in §0 — otherwise keep going to the final report.

Give each subagent call a self-contained prompt: the relevant file paths to read, the relevant file path(s) to write findings/output to, and any specific finding text it needs to act on. Subagents have no memory of this conversation or of each other's invocations.

## 0. Resume check

`$ARGUMENTS` is either a goal description (new run), the literal `resume <slug>` (explicit resume), or empty (auto-resume).

1. List existing runs: every `.loop/*/state.json` whose `phase` is **not** `"complete"` is incomplete (this includes `"halted"` — see step 4 below).
2. If `$ARGUMENTS` starts with `resume `: treat the rest as `<slug>`. If `.loop/<slug>/state.json` doesn't exist, stop and tell the user. Otherwise go to step 3.
3. Else if `$ARGUMENTS` is empty:
   - Zero incomplete runs: stop and tell the user `/goal` needs a description to start a new run.
   - Exactly one incomplete run: resume it.
   - More than one: list them (slug, phase, branch, last-updated from `state.json`) and ask the user which to resume — this is the one case worth a clarifying question, since guessing wrong burns an entire pipeline run on the wrong feature.
4. Else (`$ARGUMENTS` is a goal description): this is always a **new** run — go to §1. (If it happens to collide with an existing incomplete run's slug, §1 step 3's `-2`/`-3` suffixing keeps them from colliding; it does not resume anything.)

**To resume a run:**

- `git checkout goal/<slug>` (the branch already exists — do not create a new one).
- Read `.loop/<slug>/state.json`. Cross-check it against `git log --oneline` and which files/task directories actually exist — state.json is updated *before* each commit in this pipeline, so on an interruption (as opposed to a deliberate halt) the last-recorded state and the last commit should usually agree; if they don't, trust the commit log and file contents over state.json and correct state.json to match before continuing.
- If `phase == "halted"`: the run stopped because a review/QA loop hit its round cap with unresolved blocking findings — resuming means giving it a fresh attempt at exactly the loop it was stuck in (plan-review, one task's code-review, or QA), so **reset that specific loop's round counter to 1** and re-enter it. (If you genuinely haven't changed anything, expect it to hit the cap and halt again — that's correct behavior, not a bug. If the user manually edited plan.md/design.md/code between runs to unblock it, this attempt will reflect that.)
- Otherwise (interrupted mid-run, no halt): re-enter the exact phase/task/round recorded in state.json and continue from there — do not redo phases already marked complete (e.g. don't re-run an already-`"approved"` plan review, don't re-implement an already-`"done"` task).
- Skip straight to the resumed phase below (§1 Setup does not re-run — the branch, `.loop/<slug>/`, and prior commits already exist).

## 1. Setup (new runs only)

1. Confirm you're in a git repository (`git rev-parse --is-inside-work-tree`). If not, stop and tell the user `/goal` requires a git repo.
2. `git status` — if there are uncommitted changes, stop and ask the user to commit or stash them first. This pipeline commits at checkpoints on its own branch; starting from a dirty tree would conflate unrelated changes with its work.
3. Derive a slug from the goal text: lowercase, alphanumeric words joined with `-`, truncated to ~5 words (e.g. "Add CSV export to reports" → `add-csv-export-to`). If `.loop/<slug>/` already exists, append `-2`, `-3`, etc.
4. Create branch `goal/<slug>` off current HEAD and switch to it.
5. Copy `.loop-templates/` into `.loop/<slug>/` (create the dir if `.loop-templates/` isn't present in this repo — in that case reconstruct the file structure below from scratch using the section headers documented in each template reference below). Fill `{{GOAL}}`, `{{SLUG}}`, `{{TIMESTAMP}}` placeholders.
6. Commit: `chore(goal): initialize .loop/<slug>` — this checkpoint exists so a halted or interrupted run still has its scaffolding preserved.

State lives in `.loop/<slug>/state.json` throughout — read it before each phase, write it after every state-changing step (round numbers, verdicts, task status, phase), and commit it along with whatever else that step changed. Treat it as the single source of truth for "what's done and what's remaining" (this is also what makes resuming possible); `tasks.md` is the human-readable mirror, kept in sync alongside it.

## 2. Plan phase

1. Invoke `loop-planner` to draft `.loop/<slug>/plan.md` from the goal text.
2. Invoke `loop-architect` to draft `.loop/<slug>/design.md` from `plan.md`.
3. Set `state.json phase = "plan_review"`.
4. **Combined review loop**, `plan_review.round` starting at 1, cap 5:
   a. In parallel, invoke `loop-plan-reviewer` (append findings to `.loop/<slug>/review-notes.md`) and `loop-security` in **plan-phase** mode (append findings to `.loop/<slug>/security-plan-review.md`).
   b. Update `state.json plan_review.round`.
   c. If both verdicts are APPROVED: set `plan_review.verdict = "approved"`, commit `chore(goal): plan approved (round N)`, break to step 5.
   d. Otherwise, invoke `loop-planner` and/or `loop-architect` (whichever documents have findings against them) with this round's findings, asking them to revise `plan.md`/`design.md`. Commit `chore(goal): revise plan (round N)`.
   e. If the cap is reached without both APPROVED: go to **Halt** with reason "plan review did not converge after 5 rounds — see review-notes.md and security-plan-review.md for outstanding findings."
5. Materialize the task queue: parse `design.md` § Task Breakdown into `.loop/<slug>/tasks.md` (checklist) and `state.json.tasks` (array of `{id, title, status: "pending", code_review: {round: 0, cap: 5, verdict: "pending"}}`). Commit `chore(goal): materialize task queue (N tasks)`.

## 3. Build phase

Set `phase = "building"`. Process tasks from `state.json.tasks` **in order**; each depends on prior ones being real, so don't parallelize across tasks.

For each task:

1. Create `.loop/<slug>/tasks/<id>/` from the `task/` templates, filling `{{TASK_ID}}`/`{{TASK_TITLE}}`.
2. Set task `status = "in_progress"`.
3. Invoke `loop-builder` to implement the task (give it `plan.md`, `design.md`, and this task's description/acceptance criteria).
4. **Combined review loop**, task's `code_review.round` starting at 1, cap 5:
   a. In parallel, invoke `loop-code-reviewer` (→ `.loop/<slug>/tasks/<id>/code-review.md`) and `loop-security` in **code-phase** mode (→ `.loop/<slug>/tasks/<id>/security-review.md`) against the task's diff.
   b. Update the round counter.
   c. If both APPROVED: set task `status = "done"`, commit `feat(goal): task N — <title>`, move to the next task.
   d. Otherwise, invoke `loop-builder` with this round's findings to fix, and loop.
   e. If the cap is reached without both APPROVED: set task `status = "blocked"`, go to **Halt** with reason "task N (<title>) did not pass code review after 5 rounds — see tasks/N/code-review.md and tasks/N/security-review.md."

## 4. QA phase

Only entered once every task's status is `"done"`. Set `phase = "qa"`.

1. Invoke `loop-qa` to write `.loop/<slug>/qa/test-plan.md` from `plan.md`/`design.md`, then implement and run the full test suite, reporting round 1 to `.loop/<slug>/qa/test-results.md`.
2. Commit `test(goal): qa round N`.
3. If verdict is PASSED: set `qa.verdict = "passed"`, go to step 4 (Docs).
4. If FAILURES FOUND: identify which task(s) the failures implicate, invoke `loop-builder` with the concrete failure details to fix, re-run that task's combined code-review loop (step 3.4, reusing the same task directory, continuing its round count), then invoke `loop-qa` again to re-run the full suite (`qa.round += 1`). Repeat.
5. If `qa.cap` (5) is reached without PASSED: go to **Halt** with reason "QA did not converge after 5 rounds — see qa/test-results.md for outstanding failures."

## 5. Docs phase

Set `phase = "docs"`. Invoke `loop-docs` with `plan.md`, `design.md`, and the full changeset. Commit `docs(goal): update documentation`. Set `docs.status = "done"`.

## 6. Completion

Set `phase = "complete"`. Write `.loop/<slug>/final-report.md` from the template, filling in every section from `state.json` and the review/QA files (plan review rounds, per-task review rounds, security findings summary from both phases, QA rounds, docs updated). Commit `chore(goal): complete — final report`.

Report to the user in chat: the branch name, a one-paragraph summary of what was built, the path to `final-report.md`, and that the branch has local commits only — nothing was pushed, so they should review the diff and push/open a PR themselves when satisfied.

## Halt

On any halt condition above: set `state.json phase = "halted"` and `halted_reason`, write `final-report.md` with status "halted" and a filled-in **Unresolved Items** section describing exactly what's blocking and where to find the details, commit `chore(goal): halt — <short reason>`, and stop. Report to the user in chat what was completed, what's blocking, and which files to look at — do not attempt further rounds past the cap and do not silently mark blocking findings as resolved to force progress.
