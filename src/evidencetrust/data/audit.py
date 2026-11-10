"""how often code exceeds CodeBERT's input ."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pandas as pd

CODEBERT = "microsoft/codebert-base"
MAX_TOKENS = 510  # 512 minus [CLS]/[SEP]


def token_lengths(codes: pd.Series, model: str = CODEBERT, batch: int = 512) -> pd.Series:
    from transformers import AutoTokenizer
    tok = AutoTokenizer.from_pretrained(model)
    out = []
    for i in range(0, len(codes), batch):
        enc = tok(list(codes.iloc[i:i + batch]), add_special_tokens=False, truncation=False)["input_ids"]
        out.extend(len(e) for e in enc)
    return pd.Series(out, index=codes.index, name="n_tokens")


def audit(df: pd.DataFrame) -> dict:
    over = df["n_tokens"] > MAX_TOKENS
    return {
        "n": int(len(df)),
        "tokens": {"median": float(df["n_tokens"].median()), "p90": float(df["n_tokens"].quantile(.9)),
                   "max": int(df["n_tokens"].max())},
        "truncated_by_512": {
            "all": round(float(over.mean()), 4),
            "vul": round(float(over[df.label == 1].mean()), 4),
            "non_vul": round(float(over[df.label == 0].mean()), 4),
            **{s: round(float(over[df.split == s].mean()), 4) for s in ("train", "val", "test")},
        },
        "visible_token_share_of_truncated_fns":
            round(float((MAX_TOKENS / df.loc[over, "n_tokens"]).mean()), 4) if over.any() else 1.0,
        "lines": {"median": float(df["n_lines"].median()), "p90": float(df["n_lines"].quantile(.9))},
        "top_cwes_vul": Counter(c for cs in df.loc[df.label == 1, "cwe_ids"] for c in cs).most_common(10),
    }


def plots(df: pd.DataFrame, out_dir) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    out = Path(out_dir); out.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(7, 4))
    for lab, name in ((0, "non-vulnerable"), (1, "vulnerable")):
        ax.hist(df.loc[df.label == lab, "n_tokens"].clip(upper=3000), bins=60, alpha=.6, density=True, label=name)
    ax.axvline(MAX_TOKENS, color="k", ls="--", lw=1, label="CodeBERT limit (510)")
    ax.set(xlabel="CodeBERT tokens per function (clipped at 3000)", ylabel="density",
           title="Function length vs CodeBERT input limit"); ax.legend()
    fig.tight_layout(); fig.savefig(out / "token_lengths.png", dpi=160); plt.close(fig)

    top = Counter(c for cs in df.loc[df.label == 1, "cwe_ids"] for c in cs).most_common(10)
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.barh([c for c, _ in top][::-1], [n for _, n in top][::-1], color="#087f82")
    ax.set(xlabel="vulnerable functions", title="Top-10 CWEs (vulnerable functions)")
    fig.tight_layout(); fig.savefig(out / "top_cwes.png", dpi=160); plt.close(fig)


def save(res: dict, out_dir) -> None:
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    (Path(out_dir) / "audit.json").write_text(json.dumps(res, indent=2, default=str))