"""Deduplicate by normalised code hash.
  same code ,same label     
  same code ,different label , drop all copies 
"""
from __future__ import annotations

import hashlib
import re

import pandas as pd

_BLOCK = re.compile(r"/\*.*?\*/", re.S)
_LINE = re.compile(r"//[^\n]*")
_STR = re.compile(r'"(?:\\.|[^"\\])*"')
_WS = re.compile(r"\s+")


def normalise(code: str) -> str:
    strings: list[str] = []

    def keep(m):
        strings.append(m.group(0))
        return f"__STR{len(strings) - 1}__"

    c = _STR.sub(keep, code)          # protect "http://..." inside strings
    c = _BLOCK.sub(" ", c)
    c = _LINE.sub(" ", c)
    for i, s in enumerate(strings):
        c = c.replace(f"__STR{i}__", s)
    return _WS.sub(" ", c).strip()


def code_hash(code: str) -> str:
    return hashlib.sha1(normalise(code).encode()).hexdigest()


def deduplicate(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    df = df.copy()
    df["norm_hash"] = df["code"].map(code_hash)
    n_labels = df.groupby("norm_hash")["label"].nunique()
    conflict = set(n_labels[n_labels > 1].index)

    conflicts = df[df["norm_hash"].isin(conflict)]
    kept = df[~df["norm_hash"].isin(conflict)]
    dup_mask = kept.duplicated("norm_hash", keep="first")
    dups = kept[dup_mask]
    out = kept[~dup_mask].reset_index(drop=True)

    report = {
        "input": int(len(df)), "output": int(len(out)),
        "removed_exact_duplicates": int(len(dups)), "removed_duplicates_vul": int(dups["label"].sum()),
        "removed_label_conflicts": int(len(conflicts)), "conflict_groups": int(len(conflict)),
        "output_vul": int(out["label"].sum()), "output_non_vul": int((out["label"] == 0).sum()),
        "output_vul_ratio": round(float(out["label"].mean()), 4) if len(out) else 0.0,
    }
    return out, report