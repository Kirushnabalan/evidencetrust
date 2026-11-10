import json
import sys
from pathlib import Path

import pandas as pd

from evidencetrust.data import audit as A
from evidencetrust.utils.config import load_config

cfg = load_config("configs/data.yaml", sys.argv[1] if len(sys.argv) > 1 else None); P = cfg["abs"]
df = pd.read_parquet(P["clean"])
print("tokenising", len(df), "functions with CodeBERT tokenizer...")
df["n_tokens"] = A.token_lengths(df["code"])
res = A.audit(df)
A.plots(df, P["audit_dir"]); A.save(res, P["audit_dir"])
df[["uid", "n_tokens"]].to_parquet(Path(P["clean"]).with_name("lengths.parquet"), index=False)
print(json.dumps(res, indent=2, default=str))