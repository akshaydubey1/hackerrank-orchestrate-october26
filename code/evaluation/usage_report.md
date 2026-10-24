# Usage report — final full-dataset run

_Source: `output.manifest.json` written by the run that produced the submitted `output.csv` (code revision `acb3dfca6e94e4803a26e72c49074a488de93c93+local-changes`, parser `parsers-v10`)._

## Summary

| Item | Value |
|---|---|
| Requests processed | 518 (COMPLETE: 153, INCOMPLETE: 355, NOT_APPLICABLE: 10) |
| Model provider(s) | none |
| Model name(s) | none — no model was called |
| Model calls | 0 (failed attempts: 0, prompt-cache hits: 0) |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0.00 |
| Estimated total cost | $0.000000 |
| Estimated cost per request | $0.00000000 |
| Wall-clock time | 9.22 s total, of which 7.63 s evidence loading |
| Extraction cache | disabled (fresh extraction); hits 0, misses 94 |

## Per-model totals

| Provider | Model | Calls | Input tokens | Output tokens | Est. cost (USD) |
|---|---|---|---|---|---|
| **overall** | — | 0 | 0 | 0 | 0.000000 |

## Why the model-token count is zero

The pipeline is deterministic: structured evidence is parsed directly, SQL snapshots are executed in isolated in-memory SQLite databases, PDFs go through `pdftotext`, screenshots through local Tesseract OCR, and request intent is decided by a multilingual, negation-aware rule set. The optional model fallback (`code/ghost_audit/llm.py`, prompt in `code/prompts/intent_fallback.md`) is only consulted for a request the rules cannot classify **and** only when `ANTHROPIC_API_KEY` is set. In this run every request was decided by the rules and no key was configured, so no call was made. These figures are counted, not estimated.

## Preprocessing attributable to the run (local compute, no tokens)

| Step | Count | Notes |
|---|---|---|
| Evidence files in manifest | 94 | all processed; failures listed below |
| OCR (Tesseract) | screenshots in `evidence/images` | local CPU, cached by content hash + parser version |
| PDF text (`pdftotext`) | documents in `evidence/documents` | local CPU, cached likewise |
| SQL snapshots | executed in throw-away in-memory SQLite | never touches disk or other snapshots |

Files that yielded no direct observations (still used via data-catalog aliases in their text): `evidence_18` (no observations extracted), `evidence_27` (no observations extracted), `evidence_42` (no observations extracted), `evidence_46` (no observations extracted).

If the model fallback is enabled, cost is estimated with the per-million-token prices in `GHOST_AUDIT_PRICE_IN` / `GHOST_AUDIT_PRICE_OUT` (defaults 1.0 / 5.0 USD) applied to the token counts returned by the API.

## Development-time AI usage (not part of the run)

The solution was written with an AI coding agent (Claude, model `claude-opus-5-5`, in the Claude app). That session's token usage is not exposed to the agent and is therefore not reported here; the transcript is in the root `log.txt`. It does not contribute to the cost of producing `output.csv`.
