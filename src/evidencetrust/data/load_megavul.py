"""
Label rules:
  label = 1 -> vulnerable pre-fix function (code = func_before)
  label = 0 -> non-vulnerable function (code = func_before if present, else func)
  Patched 'after' versions are NOT used as negatives (near-duplicates -> label noise);
  they are kept in `code_after` for later paired analysis.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pandas as pd

ALIASES = {
    "is_vul": ["is_vul", "vul", "target", "label"],
    "func_before": ["func_before", "vul_func", "func_vul"],
    "func": ["func", "func_after", "fixed_func"],
    "cve_id": ["cve_id", "cve"],
    "cwe_ids": ["cwe_ids", "cwe_id", "cwe"],
    "git_url": ["git_url", "commit_url", "url"],
    "repo": ["repo_name", "repo", "project"],
    "commit": ["commit_hash", "commit_id", "hash"],
    "file_path": ["file_path", "file_name", "filename"],
    "func_name": ["func_name", "name", "method_name"],
    "graph_path": ["func_graph_path_before", "func_graph_path", "graph_path"],
}


def _get(rec: dict, key: str):
    for k in ALIASES[key]:
        if k in rec and rec[k] not in (None, ""):
            return rec[k]
    return None


def _flatten(data) -> list[dict]:
    if isinstance(data, list) and data and isinstance(data[0], dict) and _get(data[0], "is_vul") is not None:
        return data
    out = []

    def walk(x, ctx):
        if isinstance(x, dict):
            ctx = {**ctx, **{k: v for k, v in x.items() if not isinstance(v, (list, dict))}}
            if _get(x, "is_vul") is not None and (_get(x, "func_before") or _get(x, "func")):
                out.append({**ctx, **x})
                return
            for v in x.values():
                walk(v, ctx)
        elif isinstance(x, list):
            for v in x:
                walk(v, ctx)

    walk(data, {})
    return out


def _parse_git_url(url):
    if not url:
        return None, None
    m = re.search(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?/commit/([0-9a-f]{7,40})", url)
    if m:
        return f"{m.group(1)}/{m.group(2)}".lower(), m.group(3)
    m = re.search(r"github\.com/([^/]+)/([^/#?]+)", url)
    return (f"{m.group(1)}/{m.group(2)}".lower(), None) if m else (None, None)


def _to_bool(v) -> int:
    if isinstance(v, str):
        return int(v.strip().lower() in ("1", "true", "yes"))
    return int(bool(v))


def load_records(path) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict):
        lists = [v for v in data.values() if isinstance(v, list)]
        data = lists[0] if len(lists) == 1 else data
    return _flatten(data)


def to_frame(records: list[dict]) -> pd.DataFrame:
    rows = []
    for i, r in enumerate(records):
        label = _to_bool(_get(r, "is_vul"))
        before, after = _get(r, "func_before"), _get(r, "func")
        code = before if (label == 1 or before) else after
        if not code:
            continue
        repo_url, commit_url = _parse_git_url(_get(r, "git_url"))
        cwe = _get(r, "cwe_ids") or []
        if isinstance(cwe, str):
            cwe = [c.strip() for c in re.split(r"[,;| ]+", cwe) if c.strip()]
        rows.append({
            "src_index": i, "code": code, "code_after": after if label == 1 else None,
            "label": label, "cve_id": _get(r, "cve_id"), "cwe_ids": list(cwe),
            "repo": _get(r, "repo") or repo_url, "commit": _get(r, "commit") or commit_url,
            "file_path": _get(r, "file_path"), "func_name": _get(r, "func_name"),
            "graph_path": _get(r, "graph_path"),
        })
    df = pd.DataFrame(rows)
    df["n_lines"] = df["code"].str.count("\n") + 1
    df["uid"] = [
        hashlib.sha1(f"{c}|{cv}|{fp}|{fn}|{idx}".encode()).hexdigest()[:16]
        for c, cv, fp, fn, idx in zip(df["code"], df["cve_id"], df["file_path"], df["func_name"], df["src_index"])
    ]
    cols = ["uid", "code", "label", "cve_id", "cwe_ids", "repo", "commit", "file_path",
            "func_name", "graph_path", "n_lines", "code_after", "src_index"]
    return df[cols]


def summarise(df: pd.DataFrame, expected: dict | None = None) -> dict:
    s = {
        "total": int(len(df)), "vul": int(df["label"].sum()), "non_vul": int((df["label"] == 0).sum()),
        "repos": int(df["repo"].nunique()), "cves": int(df["cve_id"].nunique()),
        "cwes": int(len({c for cs in df["cwe_ids"] for c in cs})),
        "commits": int(df["commit"].nunique()), "with_graph_path": int(df["graph_path"].notna().sum()),
    }
    if expected:
        s["check"] = {k: ("OK" if s[k] == v else f"MISMATCH (expected {v})") for k, v in expected.items() if k in s}
    return s