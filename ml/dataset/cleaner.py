"""
QRShield Dataset Cleaner and Canonicalization Pipeline
Prepares, validates, deduplicates, and canonicalizes raw URL records:
- Strict URL validation & schema parsing
- Dual URL representation: original URL and model-canonicalized URL
- Exact and near-duplicate detection
- Label conflict resolution (quarantine)
- Registrable domain (eTLD+1) extraction for group-aware splitting
- Detailed dataset provenance manifest generation
"""

import os
import csv
import json
import re
from urllib.parse import urlparse, urlunparse
from datetime import datetime, timezone
from collections import Counter

RAW_DATA_DIR = "data/raw"
CLEANED_DATA_DIR = "data/cleaned"

# Common multi-part public suffixes for accurate eTLD+1 grouping
TWO_PART_TLDS = {
    "co.uk", "org.uk", "gov.uk", "ac.uk",
    "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "org.nz", "govt.nz",
    "co.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in",
    "com.mx", "org.mx", "edu.mx",
    "com.sg", "edu.sg", "gov.sg",
    "co.za", "org.za", "web.za",
    "com.tr", "edu.tr", "gov.tr",
    "com.ru", "net.ru", "org.ru",
    "com.pl", "org.pl", "net.pl"
}

# Known free hosting / dynamic services where subdomain represents the registrant
DYNAMIC_HOSTING_DOMAINS = {
    "github.io", "gitlab.io", "weeblysite.com", "square.site",
    "blogspot.com", "wordpress.com", "wixsite.com", "firebaseapp.com",
    "web.app", "gitbook.io", "pages.dev", "vercel.app", "netlify.app",
    "azurewebsites.net", "herokuapp.com", "cloudfront.net"
}


def extract_registrable_domain(hostname):
    """
    Extract registrable domain (eTLD+1) from hostname for domain-disjoint splitting.
    Correctly recognizes two-part TLDs (e.g. .co.uk) and dynamic hosting providers.
    """
    if not hostname or not isinstance(hostname, str):
        return "unknown"

    hostname = hostname.lower().strip().rstrip(".")
    # IPv4 address literal
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        return hostname

    parts = hostname.split(".")
    if len(parts) <= 2:
        return hostname

    # Check dynamic hosting where the specific tenant subdomain is the meaningful group
    two_part = ".".join(parts[-2:])
    three_part = ".".join(parts[-3:])

    if two_part in DYNAMIC_HOSTING_DOMAINS:
        return three_part
    if two_part in TWO_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])

    return two_part


def canonicalize_url(raw_url):
    """
    Produce a clean, model-canonicalized representation of a URL
    without removing discriminating malicious characteristics.
    """
    if not raw_url or not isinstance(raw_url, str):
        return None, None, None

    url_str = raw_url.strip()
    if not re.match(r"^https?://", url_str, re.IGNORECASE):
        # If scheme is missing, assume http for normalization
        url_str = "http://" + url_str

    try:
        parsed = urlparse(url_str)
        if not parsed.hostname:
            return None, None, None

        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            return None, None, None

        hostname = parsed.hostname.lower()
        port = f":{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
        netloc = f"{parsed.username or ''}{':' + parsed.password if parsed.password else ''}{'@' if parsed.username else ''}{hostname}{port}"

        path = parsed.path or "/"
        # Retain query parameters exactly, discard fragment
        canonical = urlunparse((scheme, netloc, path, parsed.params, parsed.query, ""))
        registrable_domain = extract_registrable_domain(hostname)

        return canonical, hostname, registrable_domain
    except Exception:
        return None, None, None


def clean_datasets(raw_files=None, output_path=None):
    """
    Merge, validate, deduplicate, and clean raw dataset CSVs into a standardized dataset.
    """
    if raw_files is None:
        raw_files = [
            os.path.join(RAW_DATA_DIR, "phishtank_raw.csv"),
            os.path.join(RAW_DATA_DIR, "openphish_raw.csv"),
            os.path.join(RAW_DATA_DIR, "tranco_raw.csv")
        ]

    if output_path is None:
        output_path = os.path.join(CLEANED_DATA_DIR, "cleaned_urls.csv")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    total_read = 0
    invalid_records = 0
    exact_duplicates = 0
    conflicts_detected = 0

    seen_urls = {}       # canonical_url -> record
    url_to_labels = {}   # canonical_url -> set(labels)

    for file_path in raw_files:
        if not os.path.exists(file_path):
            print(f"[Cleaner] Warning: Raw file not found: {file_path}")
            continue

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                total_read += 1
                raw_url = row.get("url", "").strip()
                try:
                    label = int(row.get("label", 0))
                except ValueError:
                    invalid_records += 1
                    continue

                canonical, hostname, reg_domain = canonicalize_url(raw_url)
                if not canonical:
                    invalid_records += 1
                    continue

                if canonical not in url_to_labels:
                    url_to_labels[canonical] = set()
                url_to_labels[canonical].add(label)

                if canonical in seen_urls:
                    exact_duplicates += 1
                    # If conflict, we'll handle below
                    continue

                seen_urls[canonical] = {
                    "original_url": raw_url,
                    "canonical_url": canonical,
                    "hostname": hostname,
                    "registrable_domain": reg_domain,
                    "label": label,
                    "threat_category": row.get("threat_category", "unknown"),
                    "source": row.get("source", "unknown"),
                    "source_id": row.get("source_id", ""),
                    "target": row.get("target", "none"),
                    "submission_time": row.get("submission_time", ""),
                    "collection_timestamp": row.get("collection_timestamp", "")
                }

    # Resolve conflicts: any URL that was labeled both 0 and 1 is ambiguous and quarantined
    clean_records = []
    quarantined = []

    for canonical, record in seen_urls.items():
        labels = url_to_labels.get(canonical, set())
        if len(labels) > 1:
            conflicts_detected += 1
            quarantined.append(record)
            continue
        clean_records.append(record)

    # Near-duplicate reduction: limit identical (registrable_domain, path) combinations
    # to prevent single large phishing campaigns from dominating the distribution
    path_grouped = {}
    deduped_records = []
    near_duplicates_culled = 0

    for rec in clean_records:
        key = (rec["label"], rec["registrable_domain"], urlparse(rec["canonical_url"]).path)
        count = path_grouped.get(key, 0)
        if count >= 3:
            # Allow max 3 URLs per identical domain+path structure
            near_duplicates_culled += 1
            continue
        path_grouped[key] = count + 1
        deduped_records.append(rec)

    # Class balance and distribution analysis
    label_counts = Counter(r["label"] for r in deduped_records)
    source_counts = Counter(r["source"] for r in deduped_records)
    domain_counts = Counter(r["registrable_domain"] for r in deduped_records)

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        fieldnames = [
            "original_url",
            "canonical_url",
            "hostname",
            "registrable_domain",
            "label",
            "threat_category",
            "source",
            "source_id",
            "target",
            "submission_time",
            "collection_timestamp"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(deduped_records)

    manifest = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_records_read": total_read,
        "invalid_records_removed": invalid_records,
        "exact_duplicates_removed": exact_duplicates,
        "conflicting_labels_quarantined": conflicts_detected,
        "near_duplicates_culled": near_duplicates_culled,
        "final_clean_records": len(deduped_records),
        "class_distribution": {
            "benign_count": label_counts[0],
            "malicious_count": label_counts[1],
            "malicious_ratio": round(label_counts[1] / len(deduped_records), 4) if deduped_records else 0
        },
        "source_distribution": dict(source_counts),
        "unique_registrable_domains": len(domain_counts),
        "top_10_domains": domain_counts.most_common(10)
    }

    manifest_path = os.path.join(CLEANED_DATA_DIR, "dataset_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=4)

    print(f"[Cleaner] Preprocessing finished.")
    print(f"          Total raw read:        {total_read}")
    print(f"          Exact duplicates:      {exact_duplicates}")
    print(f"          Conflicts removed:     {conflicts_detected}")
    print(f"          Near duplicates culled:{near_duplicates_culled}")
    print(f"          Final clean records:   {len(deduped_records)}")
    print(f"          Class distribution:    Benign={label_counts[0]}, Malicious={label_counts[1]}")
    print(f"          Unique domains:        {len(domain_counts)}")
    print(f"          Cleaned dataset saved: {output_path}")
    print(f"          Manifest saved:        {manifest_path}")

    return output_path, manifest


if __name__ == "__main__":
    clean_datasets()
