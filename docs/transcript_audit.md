# Transcript audit — `log.txt` against the authentic session records

Audit performed 2026-10-24 (recovery time of each correction is recorded in `log.txt`). Reproduce the
counts with:

```text
python3 scripts/transcript_audit.py --log log.txt --zip <agent-trace.zip> <session>.jsonl
```

The script prints only counts, timestamps and redacted first lines; raw traces are never committed.

## 1. Sources and what each covers

| Source | Covers (UTC) | Authenticity |
|---|---|---|
| `log.txt` (repository root) | 13:09:48 → this turn, 13 entries before this audit's corrections | written by the agent during the session; append-only |
| `agent-trace.zip` → `claude-code/9b2789ab-….jsonl` (2,321 records) | 17:35:19 → 22:38:38 | harness session export, copied out of `~/.claude/projects/` before the latest compaction |
| live `~/.claude/projects/-home-claude/9b2789ab-….jsonl` | 22:43:03 → now | the harness rewrites this file at compaction; it no longer holds anything earlier |
| `/mnt/user-data/attachments/9b2789ab-…/*-attachment.txt` (8 files) | file mtimes 13:09, 13:19, 17:35, 19:41, 20:22, 20:37, 21:43, 22:43 | the prompts the person attached, byte for byte |

**No raw session record survives for 13:09:48 → 17:35:19 (4 h 25 min).** For that window `log.txt`
and two attachment files are the only evidence. The agent cannot recover it. An account-level export might (§5); that is unverified.

## 2. Record classes (agent-trace.zip, 2,321 records)

| Class | Records | Counted as a human turn? |
|---|---:|---|
| assistant (model output, text and tool calls) | 761 | no |
| tool-result (type=user records carrying `tool_result`) | 359 | **no** |
| task-notification (background-task notices delivered as user-role records) | 13 | no (automated) |
| interrupt (`[Request interrupted by user…]`) | 4 | person action, no text |
| human (typed text, or a `queued_command` typed while the agent was busy) | 9 | **yes** |
| compaction summary | 1 | no |
| meta | 3 | no |
| other harness records (attachments, mode, cost-state, pr-link, queue operations, last-prompt) | 1,171 | no |

Stop-hook feedback appears in `log.txt` entries at 14:03:00 and 17:24:55 (recorded late); both are labelled
there as hook text (`[stop-hook]`, `Stop hook feedback:`) and are automated, not human turns.

## 3. Harness and model identifiers (from original metadata)

* Every assistant record in both JSONL sources has `message.model = "claude-opus-5-5"` (761 + all records
  of the live file). This matches `model=claude-opus-5-5` in every `log.txt` entry.
* Every record carrying harness metadata has `entrypoint = "remote_cowork"`, `version = "2.1.310"` and
  `sessionId = 9b2789ab-1b74-50b7-9857-9b193fbc75ff`: the Claude Code agent runtime (2.1.310) running as
  the agent workspace of the claude.ai app. `log.txt` records this as
  `tool=Claude (claude.ai app agent workspace)`, the name the person sees; the metadata is consistent with it.

## 4. Reconciliation: every human message, its source, and its log entry

| # | Time (UTC) | Message | Raw source | `log.txt` |
|---|---|---|---|---|
| 1 | 13:09 | build brief (attachment 60011b84, plus "Hack Rank OCT :") | attachment file | entry 13:50:36 "Build, evaluate…" (verbatim) |
| 2 | 13:19 | QA-hardening brief (attachment c6da19e6) | attachment file | entry 13:50:36 "QA hardening…" (verbatim) |
| 3 | ≈14:03 | owner / identity / no-AI-branding instructions | none surviving | entry 14:03:00 (verbatim, with the hook text) |
| 4 | ≈17:13 | Git e-mail | none surviving | entry 17:13:35 (e-mail redacted) |
| 5 | ≈17:24 | read-only senior review request | none surviving | entry 17:24:55 (verbatim) |
| 6 | 17:35 | correctness-repair brief (attachment d56915b8) | attachment file | entry 20:06:17 says "verbatim text not available" — **correction C1** |
| 7 | 17:56:14 | challenge URL (queued) | agent-trace.zip | **not logged — correction C2** |
| 8 | 19:41:29 | challenge URL, interrupted 0.2 s later | agent-trace.zip | **not logged — correction C2** |
| 9 | 19:41:53 | attachment 6d127010, interrupted at 19:41:56 | agent-trace.zip + file | covered by entry 20:06:17 "Complete and validate…" (same text as #10) |
| 10 | 19:42:09 | the same brief typed in full | agent-trace.zip | entry 20:06:17 "Complete and validate…" (verbatim) |
| 11 | 19:49:03 | "mandatory engineering safeguards and release gates" (queued) | agent-trace.zip | **not logged — correction C3** |
| 12 | 19:51:07 | complete, test, deliver; push authorised | agent-trace.zip | entry 20:06:17 "Repair, test, package, commit and push…" (verbatim) |
| 13 | 20:22:18 | attachment e9ab1a4c (review of 3be6cb1) | agent-trace.zip + file | entry 21:02:18 (verbatim) |
| 14 | 20:37:04 | attachment bfcaec9d (queued "Continue on feature/correctness-repair…") | agent-trace.zip + file | noted inside entry 21:02:18; its text is logged there |
| 15 | 21:43:43 | attachment 7bee58a4 (review of 62eb25d) | agent-trace.zip + file | entry 22:24:26 (verbatim) |
| 16 | 22:43:03 | attachment a956f16b (this pass) | attachment file; live JSONL keeps only `last-prompt` and the re-attached file after compaction | this turn's entry |
| 17–20 | 22:46:37 | four answers to the in-app review-packet question | live JSONL, as one tool-result record | this turn's entry, and `docs/review_packets.md` |

Interrupts (person actions without text): 18:02:12 (a tool use rejected), 19:41:29, 19:41:56, 19:51:05.

**Defensible denominators.**
* Human messages identifiable from any authentic source: **16** typed or attached messages, plus **4**
  answers given through the in-app question tool.
* Covered by a surviving raw session record: 10 of 16 (#7–#16). For #1, #2 and #6 the attachment file is
  authentic but the surrounding exchange is not recoverable here. #3–#5 rest on `log.txt` alone.
* Logged verbatim before this audit: 11 of the 15 earlier messages (#1–#5, #9, #10, #12–#15; #14 inside
  another entry). #6 was logged only as a summary, and #7, #8 and #11 were missing. #16 is logged in this
  turn's entry. After the corrections: 16 of 16. The corrections are appended now and labelled as such; none is
  backdated.

## 5. The partial trace and the truncated final turn

* The in-session JSONL is rewritten at each compaction, so no copy made from inside the session can be
  complete. The turn now in progress is also cut off in any copy taken before it ends.
* `agent-trace.zip` (kept outside the repository and outside `code.zip`) is rebuilt at the end of this
  turn. It holds the earlier export (17:35 → 22:38) and the live file (22:43 → the time of packaging), with
  the account e-mail redacted. It still lacks 13:09 → 17:35 and the remainder of the final turn.
* **The one action only the person can take:** after this turn finishes, request the claude.ai account
  data export (in claude.ai Settings, under Privacy) and locate session 9b2789ab-1b74-50b7-9857-9b193fbc75ff.
* **Coverage of that export is UNVERIFIED.** Nobody has inspected an actual export. Whether it holds
  13:09 → 17:35 UTC, the in-app answers and the complete final turn is not known. Until an export is inspected
  and reconciled with this table, the gaps above stand. The denominators in §4 stay as stated (10 of 16
  messages raw-backed), and `known_exceptions.json` keeps transcript completeness as an EXCEPTION.
