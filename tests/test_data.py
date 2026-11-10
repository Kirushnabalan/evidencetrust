import json
import random

import pandas as pd
import pytest

from evidencetrust.data.dedup import deduplicate, normalise
from evidencetrust.data.load_megavul import load_records, summarise, to_frame
from evidencetrust.data.split import assign_splits, make_groups, summary


def _fake_megavul(n_cves=200, seed=0):
    rnd = random.Random(seed); recs = []
    for c in range(n_cves):
        url = f"https://github.com/org{c % 40}/repo{c % 40}/commit/{c:040x}"
        for f in range(rnd.randint(5, 30)):
            vul = f == 0 or (f == 1 and rnd.random() < 0.3)
            body = f"public int m{c}_{f}(int x) {{ return x + {f}; }}"
            recs.append({"cve_id": f"CVE-2020-{c:05d}", "cwe_ids": ["CWE-79"], "git_url": url, "is_vul": vul,
                         "func_before": body, "func": body.replace("+", "-") if vul else body,
                         "file_path": f"src/A{c}.java", "func_name": f"m{c}_{f}",
                         "func_graph_path_before": f"g/{c}_{f}.json"})
    return recs


@pytest.fixture
def df(tmp_path):
    p = tmp_path / "megavul.json"; p.write_text(json.dumps(_fake_megavul()))
    return to_frame(load_records(p))


def test_loader_fields_and_labels(df):
    assert {"uid", "code", "label", "cve_id", "repo", "graph_path"} <= set(df.columns)
    assert df["uid"].is_unique
    assert df.loc[df.label == 1, "code_after"].notna().all()
    assert df.loc[df.label == 0, "code_after"].isna().all()
    assert summarise(df, {"total": len(df)})["check"]["total"] == "OK"


def test_normalise_strips_comments_not_strings():
    a = 'int f(){ // hi\n String u = "http://x"; /* block */ return 1; }'
    assert "hi" not in normalise(a) and "block" not in normalise(a)
    assert '"http://x"' in normalise(a)


def test_dedup_conflicts_dropped():
    d = pd.DataFrame({"code": ["int a(){}", "int  a(){}", "int b(){}", "int b(){} // x", "int c(){}"],
                      "label": [0, 0, 1, 0, 1]})
    out, rep = deduplicate(d)
    assert rep["removed_exact_duplicates"] == 1
    assert rep["removed_label_conflicts"] == 2
    assert sorted(out["code"]) == ["int a(){}", "int c(){}"]


def test_split_no_leakage_and_deterministic(df):
    split = assign_splits(df, seed=42); info = summary(df, split)
    assert sum(info["group_overlap"].values()) == 0
    assert 0.6 < info["train"]["share"] < 0.8
    assert all(info[s]["vul"] > 0 for s in ("train", "val", "test"))
    assert (assign_splits(df, seed=42) == split).all()


def test_groups_fallback_when_cve_missing(df):
    d = df.copy(); d.loc[d.index[:10], "cve_id"] = None
    g = make_groups(d)
    assert g.notna().all() and g.iloc[0].startswith("fb_")