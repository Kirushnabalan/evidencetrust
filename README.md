# EvidenceTrust

Representation-adequacy-aware semantic–structural fusion for reliable Java vulnerability detection.
FYP · Kirushnabalan Vijayabalan (20232531) · Supervisor: Guhanathan Poravi · IIT / University of Westminster

EvidenceTrust measures **how much of each Java function the detectors actually saw**:
D1 token visibility, D2 context co-visibility, D3 source-to-graph traceability and D4 relation
preservation. It uses these to fuse CodeBERT (semantic) and R-GCN (structural) predictions into a
**Vulnerable / Non-vulnerable / Review Required** decision under a fixed review budget.

## Data

MegaVul, Java subset (Ni et al., 2024; MegaVul GitHub repository), with 41,949 functions
(2,433 vulnerable) from 362 repositories. The data lives in Google Drive and is **never committed**.

```
MyDrive/dataset/
├── raw/        megavul.json, megavul_graph/
├── splits/     train_ids.csv, val_ids.csv, test_ids.csv, split_summary.json   (frozen)
├── processed/  clean.parquet, lengths.parquet, dedup_report.json
└── artifacts/  checkpoints/, preds/, diagnostics/, reports/
```

## Data rules

- **Labels:** vulnerable = pre-fix `func_before`; non-vulnerable = unchanged functions. Patched versions are not used as negatives.
- **Deduplication:** functions are compared after stripping comments and whitespace. Same code with the same label keeps one copy. Same code with conflicting labels drops all copies.
- **Split:** 70/15/15, stratified by label and **grouped by CVE**, seed 42.
- **Test set:** locked until the final freeze. All interim (IPD) results are on validation.

## Quick start (Colab)

1. In Drive, move `megavul.json` and `megavul_graph/` into `dataset/raw/`.
2. Push this repo to GitHub.
3. Open `notebooks/00_setup_data_audit.ipynb` in Colab. Edit `DRIVE_ROOT` and `REPO`, then run all cells.

Locally:

```bash
pip install -r requirements.txt && pip install -e .
pytest -q
python scripts/prepare_data.py --drive-root /path/to/dataset
```

## Layout

```
configs/            YAML configs (paths, seeds, hyper-parameters)
src/evidencetrust/  data · semantic · structural · diagnostics · fusion · degradation · evaluation · utils
scripts/            runnable entry points
notebooks/          thin Colab notebooks that call src/
tests/              pytest suite (run in CI)
api/ web/ docker/   FastAPI backend, React UI, deployment (weeks 7-8)
```

## Status

| Week | Milestone | Status |
|---|---|---|
| 1 | Data preparation, deduplication, frozen split, audit | in progress |
| 2 | CodeBERT + D1/D2 | – |
| 3–4 | R-GCN + D3/D4 | – |
| 5–6 | Calibration, fusion gate, review policy | – |
| 7–8 | Pipeline, API, UI, hosting | – |
