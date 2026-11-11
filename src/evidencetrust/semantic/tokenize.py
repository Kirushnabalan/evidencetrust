from __future__ import annotations

import pandas as pd

from evidencetrust.diagnostics.semantic import d1_token_visibility, d2_context_covisibility, visible_lines

CODEBERT = "microsoft/codebert-base"
MAX_TOKENS = 510  # + [CLS] + [SEP] = 512


def get_tokenizer(model: str = CODEBERT):
    from transformers import AutoTokenizer
    return AutoTokenizer.from_pretrained(model)


def encode_one(code: str, offsets: list[tuple[int, int]], ids: list[int], max_tokens: int = MAX_TOKENS) -> dict:
    """offsets/ids = full (untruncated) tokenisation without special tokens."""
    n = len(ids)
    kept = min(n, max_tokens)
    vis_end = len(code) if n <= max_tokens else offsets[kept - 1][1]
    vl, tl = visible_lines(code, vis_end)
    return {
        "input_ids": ids[:kept],
        "n_tokens": n,
        "n_visible_tokens": kept,
        "truncated": n > max_tokens,
        "visible_char_end": int(vis_end),
        "visible_lines": vl,
        "total_lines": tl,
        "d1": round(d1_token_visibility(n, max_tokens), 6),
        "d2": round(d2_context_covisibility(code, vis_end), 6),
    }


def encode_frame(df: pd.DataFrame, tokenizer, max_tokens: int = MAX_TOKENS, batch: int = 256) -> pd.DataFrame:
    rows = []
    codes = df["code"].tolist()
    for i in range(0, len(codes), batch):
        chunk = codes[i:i + batch]
        enc = tokenizer(chunk, add_special_tokens=False, truncation=False, return_offsets_mapping=True)
        for code, ids, offs in zip(chunk, enc["input_ids"], enc["offset_mapping"]):
            rows.append(encode_one(code, offs, ids, max_tokens))
    out = pd.DataFrame(rows)
    out.insert(0, "uid", df["uid"].values)
    return out