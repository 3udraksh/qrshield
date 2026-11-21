"""
QRShield Dataset Splitter and Leakage Prevention
Implements:
1. Domain-Disjoint Group Splitting (GroupShuffleSplit on registrable_domain)
   Ensures ZERO domain leakage between Train, Validation, and Test sets.
2. Random URL Splitting (StratifiedShuffleSplit)
   Baseline comparison to evaluate domain-leakage optimistic bias.
3. Formal leakage auditing & split manifest generation.
"""

import os
import json
import pandas as pd
import numpy as np
from sklearn.model_selection import GroupShuffleSplit, StratifiedShuffleSplit

CLEANED_DATA_PATH = "data/cleaned/cleaned_urls.csv"
PROCESSED_DATA_DIR = "data/processed"


def generate_splits(input_path=CLEANED_DATA_PATH, output_dir=PROCESSED_DATA_DIR, random_state=42):
    """
    Generate rigorous domain-disjoint splits and baseline random splits.
    Train: 70%, Validation: 15%, Test: 15%.
    """
    os.makedirs(output_dir, exist_ok=True)
    df = pd.read_csv(input_path)

    print(f"[Splitter] Loaded {len(df)} cleaned records from {input_path}")
    print(f"[Splitter] Unique registrable domains: {df['registrable_domain'].nunique()}")

    # -------------------------------------------------------------------------
    # 1. Domain-Disjoint Group Splitting (Zero Domain Overlap)
    # -------------------------------------------------------------------------
    # Step 1: Split into Train (70%) and Temp (30%)
    gss1 = GroupShuffleSplit(n_splits=1, train_size=0.70, random_state=random_state)
    train_idx, temp_idx = next(gss1.split(df, groups=df["registrable_domain"]))

    train_df = df.iloc[train_idx].copy().reset_index(drop=True)
    temp_df = df.iloc[temp_idx].copy().reset_index(drop=True)

    # Step 2: Split Temp (30%) equally into Val (15%) and Test (15%)
    gss2 = GroupShuffleSplit(n_splits=1, train_size=0.50, random_state=random_state)
    val_sub_idx, test_sub_idx = next(gss2.split(temp_df, groups=temp_df["registrable_domain"]))

    val_df = temp_df.iloc[val_sub_idx].copy().reset_index(drop=True)
    test_df = temp_df.iloc[test_sub_idx].copy().reset_index(drop=True)

    # Formal Leakage Verification
    train_domains = set(train_df["registrable_domain"])
    val_domains = set(val_df["registrable_domain"])
    test_domains = set(test_df["registrable_domain"])

    train_val_overlap = train_domains.intersection(val_domains)
    train_test_overlap = train_domains.intersection(test_domains)
    val_test_overlap = val_domains.intersection(test_domains)

    assert len(train_val_overlap) == 0, f"Domain leakage detected between train and val: {train_val_overlap}"
    assert len(train_test_overlap) == 0, f"Domain leakage detected between train and test: {train_test_overlap}"
    assert len(val_test_overlap) == 0, f"Domain leakage detected between val and test: {val_test_overlap}"

    train_urls = set(train_df["canonical_url"])
    test_urls = set(test_df["canonical_url"])
    url_overlap = train_urls.intersection(test_urls)
    assert len(url_overlap) == 0, f"Exact URL leakage detected: {len(url_overlap)}"

    print("[Splitter] Domain-Disjoint Verification Passed: ZERO domain or URL overlap.")

    # -------------------------------------------------------------------------
    # 2. Random Split (For Empirical Leakage Comparison)
    # -------------------------------------------------------------------------
    sss = StratifiedShuffleSplit(n_splits=1, test_size=0.15, random_state=random_state)
    _, random_test_idx = next(sss.split(df, df["label"]))
    random_test_df = df.iloc[random_test_idx].copy().reset_index(drop=True)

    # Save CSV splits
    train_path = os.path.join(output_dir, "train_domain_disjoint.csv")
    val_path = os.path.join(output_dir, "val_domain_disjoint.csv")
    test_path = os.path.join(output_dir, "test_domain_disjoint.csv")
    random_test_path = os.path.join(output_dir, "test_random.csv")

    train_df.to_csv(train_path, index=False)
    val_df.to_csv(val_path, index=False)
    test_df.to_csv(test_path, index=False)
    random_test_df.to_csv(random_test_path, index=False)

    # Manifest
    manifest = {
        "domain_disjoint": {
            "train": {
                "records": len(train_df),
                "unique_domains": len(train_domains),
                "benign": int((train_df["label"] == 0).sum()),
                "malicious": int((train_df["label"] == 1).sum()),
                "malicious_ratio": round(float((train_df["label"] == 1).mean()), 4)
            },
            "val": {
                "records": len(val_df),
                "unique_domains": len(val_domains),
                "benign": int((val_df["label"] == 0).sum()),
                "malicious": int((val_df["label"] == 1).sum()),
                "malicious_ratio": round(float((val_df["label"] == 1).mean()), 4)
            },
            "test": {
                "records": len(test_df),
                "unique_domains": len(test_domains),
                "benign": int((test_df["label"] == 0).sum()),
                "malicious": int((test_df["label"] == 1).sum()),
                "malicious_ratio": round(float((test_df["label"] == 1).mean()), 4)
            },
            "leakage_audit": {
                "train_val_domain_overlap": len(train_val_overlap),
                "train_test_domain_overlap": len(train_test_overlap),
                "val_test_domain_overlap": len(val_test_overlap),
                "exact_url_leakage": len(url_overlap)
            }
        },
        "random_test_baseline": {
            "records": len(random_test_df),
            "unique_domains": int(random_test_df["registrable_domain"].nunique()),
            "benign": int((random_test_df["label"] == 0).sum()),
            "malicious": int((random_test_df["label"] == 1).sum()),
            "domain_overlap_with_train": len(set(random_test_df["registrable_domain"]).intersection(train_domains))
        }
    }

    manifest_path = os.path.join(output_dir, "split_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=4)

    print(f"[Splitter] Splits saved to {output_dir}:")
    print(f"          Train (Domain-Disjoint): {len(train_df)} rows, {len(train_domains)} domains")
    print(f"          Val   (Domain-Disjoint): {len(val_df)} rows, {len(val_domains)} domains")
    print(f"          Test  (Domain-Disjoint): {len(test_df)} rows, {len(test_domains)} domains")
    print(f"          Test  (Random Split):    {len(random_test_df)} rows")
    print(f"          Manifest:               {manifest_path}")

    return manifest


if __name__ == "__main__":
    generate_splits()
