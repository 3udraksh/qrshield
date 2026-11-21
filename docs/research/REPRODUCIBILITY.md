# QRShield 2.0 — Experimental Reproducibility Guide

## 1. Project Identity & Checkpoint
- **Repository**: `https://github.com/3udraksh/qrshield.git`
- **Branch**: `qrshield-v2`
- **Milestone 2 Checkpoint**: `0b70b98`
- **Historical Baseline Tag**: `qrshield-tier1-baseline-2026-11-02`
- **Production Artifact**: `ml/models/qrshield_hybrid_v2.joblib` (1,041 KB)
- **Historical Baseline**: `ml/qrshield_model.joblib` (76.7 KB)

---

## 2. Hardware, OS & Software Environment

| Component | Specification |
| :--- | :--- |
| **Operating System** | Ubuntu 24.04 LTS on WSL2 (x86_64) / Linux |
| **Python Runtime** | Python 3.14.0rc2 (Virtual Environment: `.venv`) |
| **Primary Libraries** | `scikit-learn==1.9.1`, `pandas==2.2.2`, `numpy==2.1.1`, `joblib==1.4.2`, `opencv-python-headless==4.10.0.84`, `cryptography==43.0.1` |
| **Random Seed** | Fixed to `42` across all stochastic operations |

---

## 3. Cryptographic Artifact Hashes (SHA-256)

All dataset and model artifacts have been verified with exact SHA-256 checksums:

| Artifact Path | Size (KB) | SHA-256 Checksum (Full) |
| :--- | :--- | :--- |
| `data/cleaned/cleaned_urls.csv` | 2,916.0 | `d11811e841c1302096700c3b063806fb4dfec3ca1e74a887ca1338a0f9b60d70` |
| `data/cleaned/dataset_manifest.json` | 1.2 | `34d2509b9dbdea94c4839cf9e54805eecba2d02c89694ff8a8109d93bb0b4b88` |
| `data/processed/split_manifest.json` | 1.0 | `d0a1a8aa6d50b6ea2a71bfb5a6c1a8a25c156f70a169b8274381014e7a0303ba` |
| `data/processed/train_domain_disjoint.csv` | 1,995.0 | `74d3f287850b711ff635c94c980fc28509e56304cb3b723d387ae4949efd3a0e` |
| `data/processed/val_domain_disjoint.csv` | 423.9 | `589720181e02857c7c34b8c5e626e3c09b02a28188188176ae21e257ca67c5e2` |
| `data/processed/test_domain_disjoint.csv` | 483.3 | `1daa8edfbb53bc7ca9d628b030df1fa7a7605d39ea30cefa0f07fa1458e3cb26` |
| `data/processed/test_random.csv` | 439.3 | `4d2dee9678cb9699689c17351bf6aeef7394ca562725514f7d45a9a4b2da8b74` |
| `ml/models/qrshield_hybrid_v2.joblib` | 1,041.5 | `b1f022f610f059187313a4ae49d837651a51aa00511d713c70fa5db825700763` |
| `ml/models/model_metadata.json` | 2.2 | `c16f45dddbed38217316fc1b473138b374945d81b4f4955b244d57c2e92ec421` |
| `ml/experiments/experiment_results.json` | 19.5 | `2ae87cdd7e2525bfdc4b85da8eb852ae4a141a0293049b49ca09be6905a5a1bf` |

---

## 4. End-to-End Execution Pipeline

### Step 1: Environment Setup
```bash
git clone https://github.com/3udraksh/qrshield.git
cd qrshield
git checkout qrshield-v2
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Step 2: Dataset Acquisition & Cleaning
To execute the multi-source pipeline (PhishTank, OpenPhish, Tranco):
```bash
PYTHONPATH=. .venv/bin/python ml/dataset/acquisition.py
PYTHONPATH=. .venv/bin/python ml/dataset/cleaner.py
PYTHONPATH=. .venv/bin/python ml/dataset/splitter.py
```
This generates:
- `data/cleaned/cleaned_urls.csv` (14,392 URLs, 12,225 unique eTLD+1 domains)
- `data/processed/train_domain_disjoint.csv` (9,989 rows, 8,557 domains)
- `data/processed/val_domain_disjoint.csv` (2,102 rows, 1,834 domains)
- `data/processed/test_domain_disjoint.csv` (2,301 rows, 1,834 domains)
- `data/processed/test_random.csv` (2,159 rows for leakage evaluation)

### Step 3: Run Full Benchmark Experiments
To train all 8 candidate configurations, run validation weight optimization, perform domain-disjoint evaluation, and serialize the production hybrid ensemble artifact:
```bash
PYTHONPATH=. .venv/bin/python ml/experiments/run_experiments.py
```
This updates:
- `ml/models/qrshield_hybrid_v2.joblib`
- `ml/models/model_metadata.json`
- `ml/experiments/experiment_results.json`

### Step 4: Run Automated Verification Suites
Execute the frozen Tier 1 baseline regression suite (66 tests):
```bash
.venv/bin/python -m unittest discover -s tests -p "test_*.py" -v
```
Execute the Tier 2 security, architecture, and hybrid ML suite (38 tests):
```bash
.venv/bin/python -m unittest discover -s tests_tier2 -p "test_*.py" -v
```

Total: 104 passing tests. Zero regressions.
