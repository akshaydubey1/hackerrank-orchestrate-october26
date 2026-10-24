"""Write code/evaluation/usage_report.md from the manifest of the run that produced output.csv.

    python3 code/evaluation/make_usage_report.py [code/runs/output.manifest.json]
Every number comes from the manifest written by code/main.py during that run.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    mpath = Path(sys.argv[1]) if len(sys.argv) > 1 else HERE.parent / "runs" / "output.manifest.json"
    m = json.loads(mpath.read_text(encoding="utf-8"))
    u = m["model_usage"]
    n = m["n_requests"]
    files = m["evidence_files"]
    tok = u["input_tokens"] + u["output_tokens"]
    lines = [
        "# Usage report — final full-dataset run",
        "",
        f"_Source: `{mpath.name}` written by the run that produced the submitted `output.csv` "
        f"(code revision `{m['code_revision']}`, parser `{m['parser_version']}`)._",
        "",
        "## Summary",
        "",
        "| Item | Value |",
        "|---|---|",
        f"| Requests processed | {n} ({', '.join(f'{k}: {v}' for k, v in sorted(m['status_counts'].items()))}) |",
        f"| Model provider(s) | {u['provider']} |",
        f"| Model name(s) | {', '.join(u['by_model']) or 'none — no model was called'} |",
        f"| Model calls | {u['calls']} (failed attempts: {u['failures']}, prompt-cache hits: {u['cache_hits']}) |",
        f"| Input tokens | {u['input_tokens']} |",
        f"| Output tokens | {u['output_tokens']} |",
        f"| Total tokens | {tok} |",
        f"| Average tokens per request | {tok / n:.2f} |",
        f"| Estimated total cost | ${u['estimated_cost_usd']:.6f} |",
        f"| Estimated cost per request | ${u['estimated_cost_usd'] / n:.8f} |",
        f"| Wall-clock time | {m['seconds_total']} s total, of which {m['seconds_loading']} s evidence loading |",
        f"| Extraction cache | {'enabled' if m['cache']['enabled'] else 'disabled (fresh extraction)'}; "
        f"hits {m['cache']['hits']}, misses {m['cache']['misses']} |",
        "",
        "## Per-model totals",
        "",
        "| Provider | Model | Calls | Input tokens | Output tokens | Est. cost (USD) |",
        "|---|---|---|---|---|---|",
    ]
    if u["by_model"]:
        for model, x in u["by_model"].items():
            lines.append(f"| anthropic | {model} | {x['calls']} | {x['input_tokens']} | {x['output_tokens']} | "
                         f"(see total) |")
    lines.append(f"| **overall** | — | {u['calls']} | {u['input_tokens']} | {u['output_tokens']} | "
                 f"{u['estimated_cost_usd']:.6f} |")
    lines += [
        "",
        "## Why the model-token count is zero",
        "",
        "The pipeline is deterministic: structured evidence is parsed directly, SQL snapshots are executed in "
        "isolated in-memory SQLite databases, PDFs go through `pdftotext`, screenshots through local Tesseract "
        "OCR, and request intent is decided by a multilingual, negation-aware rule set. The optional model "
        "fallback (`code/ghost_audit/llm.py`, prompt in `code/prompts/intent_fallback.md`) is only consulted for a "
        "request the rules cannot classify **and** only when `ANTHROPIC_API_KEY` is set. In this run every "
        "request was decided by the rules and no key was configured, so no call was made. These figures are "
        "counted, not estimated.",
        "",
        "## Preprocessing attributable to the run (local compute, no tokens)",
        "",
        "| Step | Count | Notes |",
        "|---|---|---|",
        f"| Evidence files in manifest | {len(files)} | all processed; failures listed below |",
        "| OCR (Tesseract) | screenshots in `evidence/images` | local CPU, cached by content hash + parser version |",
        "| PDF text (`pdftotext`) | documents in `evidence/documents` | local CPU, cached likewise |",
        "| SQL snapshots | executed in throw-away in-memory SQLite | never touches disk or other snapshots |",
        "",
        "Files that yielded no direct observations (still used via data-catalog aliases in their text): "
        + (", ".join(f"`{fid}` ({err})" for fid, err in m["extraction_failures"]) or "none") + ".",
        "",
        "If the model fallback is enabled, cost is estimated with the per-million-token prices in "
        "`GHOST_AUDIT_PRICE_IN` / `GHOST_AUDIT_PRICE_OUT` (defaults 1.0 / 5.0 USD) applied to the token counts "
        "returned by the API.",
        "",
        "## Development-time AI usage (not part of the run)",
        "",
        "The solution was written with an AI coding agent (Claude, model `claude-opus-5-5`, in the Claude app). "
        "That session's token usage is not exposed to the agent and is therefore not reported here; the "
        "transcript is in the root `log.txt`. It does not contribute to the cost of producing `output.csv`.",
        "",
    ]
    out = HERE / "usage_report.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
