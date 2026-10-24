# Usage report — final full-dataset run

_Source: `output.manifest.json` written by the run that produced the submitted `output.csv` (git revision at run time `f280a63a7f918032ad9bee4d3759e62abd66b584+local-changes`, code fingerprint `43d8c4c623279f0738df3d52c7be07953fc638cdcf4d612290f92835caaf50e8`, parser `parsers-v13`)._

## Summary

| Item | Value |
|---|---|
| Requests processed | 518 (COMPLETE: 111, INCOMPLETE: 397, NOT_APPLICABLE: 10) |
| Model provider(s) | none |
| Model name(s) | none — no model was called |
| Model calls | 0 (failed attempts: 0, prompt-cache hits: 0) |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0.00 |
| Estimated total cost | $0.000000 |
| Estimated cost per request | $0.00000000 |
| Wall-clock time | 9.94 s total, of which 7.7 s evidence loading |
| Extraction cache | disabled (fresh extraction); hits 0, misses 94 (key = content sha256 + parser version + file id + capture time) |
| Intent decisions (source:label) | rules:ACCESS_OR_EXPORT 4, rules:CORRECTION 3, rules:DELETION 508, rules:MARKETING_OPT_OUT 1, rules:OTHER 2 |
| Requests eligible for the model fallback (rules UNDECIDED) | 0 |

## Per-model totals

| Provider | Model | Calls | Input tokens | Output tokens | Est. cost (USD) |
|---|---|---|---|---|---|
| **overall** | — | 0 | 0 | 0 | 0.000000 |

## Why the model-token count is zero

The pipeline is deterministic: structured evidence is parsed directly, SQL snapshots are executed in isolated in-memory SQLite databases, PDFs go through `pdftotext`, screenshots through local Tesseract OCR, and request intent is decided by a multilingual, negation-aware rule set. The optional model fallback (`code/ghost_audit/llm.py`, prompt in `code/prompts/intent_fallback.md`) is only consulted for a request the rules cannot classify **and** only when `ANTHROPIC_API_KEY` is set. In this run every request was decided by the rules and no key was configured, so no call was made. These figures are counted, not estimated.

**Status of the model path.** The fallback has never been run against a real provider. Its failure handling (timeouts, rate limits, malformed or out-of-schema responses) is exercised with fake responses in the evaluation suite, but the request format, response parsing against the live API and the cost estimate are **untested**. No ceremonial calls were made to produce non-zero numbers.

## Preprocessing attributable to the run (local compute, no tokens)

| Step | Count | Notes |
|---|---|---|
| Evidence files in manifest | 94 | all processed; failures listed below |
| OCR (Tesseract) | 11 screenshots | local CPU; result cached |
| PDF text (`pdftotext`) | 4 documents | local CPU; result cached |
| SQL snapshots | 24 files | each executed in a throw-away in-memory SQLite database |
| Extraction status | facts-only 1, no-direct-facts 3, ok 90 | see failures below |

Extraction failures and partial extractions recorded during the run: none.

If the model fallback is enabled, cost is estimated with the per-million-token prices in `GHOST_AUDIT_PRICE_IN` / `GHOST_AUDIT_PRICE_OUT` (defaults 1.0 / 5.0 USD) applied to the token counts returned by the API.

## Development-time AI usage (not part of the run)

The solution was written with an AI coding agent (harness: Claude in the claude.ai app agent workspace, built on Claude Code; model `claude-opus-5-5`). That session's token usage is not exposed to the agent and is therefore not reported here; the transcript is the root `log.txt`; the raw agent trace is submitted separately as `agent-trace.zip`. It does not contribute to the cost of producing `output.csv`.
