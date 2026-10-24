"""Classify the records of Claude Code session exports (JSONL) and reconcile them with log.txt.

    python3 scripts/transcript_audit.py --log log.txt TRACE.jsonl [TRACE2.jsonl ...] [--zip agent-trace.zip]

Raw traces are never written into the repository; only counts, timestamps and short labels are printed.
Record classes:
  human            a message the person typed (type=user, string or text content, not meta / summary / hook),
                   or a queued_command attachment (typed while the agent was busy)
  interrupt        "[Request interrupted by user...]" markers (a person action, no text)
  tool-result      type=user records carrying tool_result blocks (NOT human turns)
  task-notification background-task completion notices delivered as user-role records (automated)
  hook             stop-hook / system feedback delivered as user-role records (automated)
  compaction       the summary inserted when context is compacted (isCompactSummary)
  meta             isMeta records (harness bookkeeping)
  assistant        model output (text and tool calls); its message.model is the serving model
  other            attachments, mode, cost-state, pr-link, queue operations and similar harness records
"""
from __future__ import annotations

import argparse
import json
import re
import zipfile
from collections import Counter
from pathlib import Path

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def text_of(content) -> str:
    if isinstance(content, str):
        return content
    return " ".join(x.get("text", "") for x in content if isinstance(x, dict) and x.get("type") == "text")


def classify(r: dict) -> str:
    t = r.get("type")
    if t == "assistant":
        return "assistant"
    queued = t == "attachment" and (r.get("attachment") or {}).get("type") == "queued_command"
    if t != "user" and not queued:  # a queued_command was typed while the agent was busy
        return "other"
    if r.get("isCompactSummary"):
        return "compaction"
    if r.get("isMeta"):
        return "meta"
    c = (r.get("message") or {}).get("content") if not queued else (r["attachment"].get("prompt") or "")
    if isinstance(c, list) and any(isinstance(x, dict) and x.get("type") == "tool_result" for x in c):
        return "tool-result"
    s = text_of(c).strip()
    if s.startswith("[Request interrupted by user"):
        return "interrupt"
    if s.startswith("<task-notification>"):
        return "task-notification"
    if "Stop hook feedback" in s[:200] or s.startswith("<local-command") or s.startswith("<command-"):
        return "hook"
    return "human"


def label(r: dict) -> str:
    att = r.get("attachment") or {}
    s = text_of((r.get("message") or {}).get("content") if r.get("type") == "user" else (att.get("prompt") or ""))
    s = re.sub(r"<system-reminder>.*?</system-reminder>", "", s, flags=re.S).strip()
    s = EMAIL.sub("[email]", s)
    return (s.splitlines() or [""])[0][:90]


def records(paths, zpath):
    for p in paths:
        yield str(p), [json.loads(l) for l in Path(p).read_text(encoding="utf-8").splitlines() if l.strip()]
    if zpath:
        with zipfile.ZipFile(zpath) as z:
            for n in z.namelist():
                if n.endswith(".jsonl"):
                    yield f"{zpath}:{n}", [json.loads(l) for l in z.read(n).decode().splitlines() if l.strip()]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("traces", nargs="*")
    ap.add_argument("--zip", default=None)
    ap.add_argument("--log", default=None)
    ap.add_argument("--json", default=None)
    a = ap.parse_args(argv)
    out = {"sources": [], "human": {}}
    for src, rows in records(a.traces, a.zip):
        c = Counter(classify(r) for r in rows)
        ts = [r["timestamp"] for r in rows if r.get("timestamp")]
        models = Counter((r.get("message") or {}).get("model") for r in rows if r.get("type") == "assistant")
        meta = {"version": sorted({r["version"] for r in rows if r.get("version")}),
                "entrypoint": sorted({r["entrypoint"] for r in rows if r.get("entrypoint")}),
                "sessionId": sorted({r["sessionId"] for r in rows if r.get("sessionId")})}
        out["sources"].append({"source": src, "records": len(rows), "classes": dict(c), "first": min(ts, default=None),
                               "last": max(ts, default=None), "assistant_models": dict(models), **meta})
        for r in rows:
            if classify(r) == "human":  # same uuid in two exports counts once
                out["human"][r.get("uuid") or r.get("timestamp")] = (r.get("timestamp"), label(r))
    log_entries = []
    if a.log:
        for m in re.finditer(r"(?m)^## \[([^\]]+)\] (.*)$", Path(a.log).read_text(encoding="utf-8")):
            log_entries.append((m.group(1), m.group(2)))
    out["log_entries"] = log_entries
    for s in out["sources"]:
        print(json.dumps(s))
    hum = sorted(out["human"].values())
    print(f"distinct human messages across sources: {len(hum)}")
    for t, l in hum:
        print("  human", t, "|", l)
    print(f"log.txt entries: {len(log_entries)}")
    for t, l in log_entries:
        print("  log  ", t, "|", l)
    if a.json:
        Path(a.json).write_text(json.dumps(out, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
