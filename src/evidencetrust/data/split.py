"""CVE-grouped, label-stratified"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold


def make_groups(df: pd.DataFrame, group_by: str = "cve_id") -> pd.Series:
    g = df[group_by].astype("object")
    for fb in ("commit", "repo", "uid"):          # fallback if CVE missing
        if fb in df:
            g = g.where(g.notna(), "fb_" + df[fb].astype(str))
    return g.astype(str)


def assign_splits(df, seed=42, n_folds=20, train_folds=14, val_folds=3, group_by="cve_id") -> pd.Series:
    groups = make_groups(df, group_by)
    n_folds = min(n_folds, groups.nunique())
    sgkf = StratifiedGroupKFold(n_splits=n_folds, shuffle=True, random_state=seed)
    fold = np.empty(len(df), dtype=int)
    for k, (_, idx) in enumerate(sgkf.split(df, df["label"], groups)):
        fold[idx] = k
    order = np.random.default_rng(seed).permutation(n_folds)
    tr, va = order[:train_folds], order[train_folds:train_folds + val_folds]
    return pd.Series(np.where(np.isin(fold, tr), "train", np.where(np.isin(fold, va), "val", "test")),
                     index=df.index, name="split")


def summary(df, split, group_by="cve_id") -> dict:
    groups = make_groups(df, group_by)
    out = {}
    for s in ("train", "val", "test"):
        m = split == s
        out[s] = {"n": int(m.sum()), "vul": int(df.loc[m, "label"].sum()),
                  "vul_ratio": round(float(df.loc[m, "label"].mean()), 4) if m.any() else 0.0,
                  "share": round(float(m.mean()), 4), "groups": int(groups[m].nunique())}
    sets = {s: set(groups[split == s]) for s in ("train", "val", "test")}
    out["group_overlap"] = {"train_val": len(sets["train"] & sets["val"]),
                            "train_test": len(sets["train"] & sets["test"]),
                            "val_test": len(sets["val"] & sets["test"])}
    return out


def save_splits(df, split, out_dir, info) -> None:
    out_dir = Path(out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    for s in ("train", "val", "test"):
        df.loc[split == s, ["uid", "label"]].to_csv(out_dir / f"{s}_ids.csv", index=False)
    (out_dir / "split_summary.json").write_text(json.dumps(info, indent=2))