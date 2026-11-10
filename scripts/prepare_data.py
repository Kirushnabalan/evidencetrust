"""megavul.json  clean.parquet dedup frozen CVE-grouped split.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evidencetrust.data.dedup import deduplicate
from evidencetrust.data.load_megavul import load_records, summarise, to_frame
from evidencetrust.data.split import assign_splits, save_splits, summary
from evidencetrust.utils.config import load_config, set_seed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/data.yaml")
    ap.add_argument("--drive-root", default=None)
    ap.add_argument("--force", action="store_true", help="overwrite an existing frozen split")
    a = ap.parse_args()

    cfg = load_config(a.config, a.drive_root); P = cfg["abs"]; sp = cfg["split"]
    set_seed(sp["seed"])
    if (Path(P["splits_dir"]) / "test_ids.csv").exists() and not a.force:
        sys.exit("Split already frozen. Use --force only if you really mean to re-split (test set!).")

    print("1/4 loading", P["raw_json"])
    raw = to_frame(load_records(P["raw_json"]))
    raw_stats = summarise(raw, cfg["expected"]); print(json.dumps(raw_stats, indent=2))

    print("2/4 deduplicating")
    clean, dedup_report = deduplicate(raw); print(json.dumps(dedup_report, indent=2))

    print("3/4 splitting (grouped by", sp["group_by"], ")")
    split = assign_splits(clean, sp["seed"], sp["n_folds"], sp["train_folds"], sp["val_folds"], sp["group_by"])
    clean["split"] = split.values
    info = summary(clean, split, sp["group_by"]); print(json.dumps(info, indent=2))
    assert sum(info["group_overlap"].values()) == 0, "group leakage between splits!"

    print("4/4 saving")
    Path(P["clean"]).parent.mkdir(parents=True, exist_ok=True)
    clean.to_parquet(P["clean"], index=False)
    Path(P["dedup_report"]).write_text(json.dumps({"raw": raw_stats, "dedup": dedup_report}, indent=2))
    save_splits(clean, split, P["splits_dir"], {"config": sp, **info})
    print("done ->", P["clean"], "and", P["splits_dir"])


if __name__ == "__main__":
    main()