"""
QRShield Dataset Acquisition Adapters
Fetches raw threat intelligence and legitimate URL datasets from authoritative open sources:
- PhishTank (Verified Online Phishing Feed)
- OpenPhish (Community Phishing Feed)
- Tranco (Research-oriented Top Sites Ranking)
"""

import os
import csv
import json
import io
import zipfile
import urllib.request
import urllib.error
from datetime import datetime, timezone

RAW_DATA_DIR = "data/raw"
USER_AGENT = "QRShield-Research/2.0 (Defensive Cybersecurity ML Pipeline; contact: security@qrshield.local)"


def _fetch_url(url, timeout=30):
    """Safely fetch URL content as bytes using standard urllib."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"}
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read()


class PhishTankAdapter:
    """Acquires verified online phishing records from PhishTank."""

    FEED_URL = "https://data.phishtank.com/data/online-valid.csv"

    @classmethod
    def acquire(cls, output_path=None, limit=None):
        if output_path is None:
            output_path = os.path.join(RAW_DATA_DIR, "phishtank_raw.csv")

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        print(f"[Acquisition] Fetching PhishTank verified phishing dump from {cls.FEED_URL}...")

        raw_bytes = _fetch_url(cls.FEED_URL, timeout=45)
        text_content = raw_bytes.decode("utf-8", errors="replace")

        records = []
        reader = csv.DictReader(io.StringIO(text_content))
        for row in reader:
            url = row.get("url", "").strip()
            if not url:
                continue
            records.append({
                "url": url,
                "label": 1,
                "threat_category": "phishing",
                "source": "phishtank",
                "source_id": str(row.get("phish_id", "")),
                "target": str(row.get("target", "unknown")),
                "submission_time": str(row.get("submission_time", "")),
                "verified": str(row.get("verified", "yes")),
                "collection_timestamp": datetime.now(timezone.utc).isoformat()
            })
            if limit and len(records) >= limit:
                break

        with open(output_path, "w", encoding="utf-8", newline="") as f:
            if records:
                writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
                writer.writeheader()
                writer.writerows(records)

        print(f"[Acquisition] PhishTank: saved {len(records)} raw records to {output_path}")
        return output_path, records


class OpenPhishAdapter:
    """Acquires active phishing URLs from the OpenPhish community feed."""

    FEED_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"

    @classmethod
    def acquire(cls, output_path=None, limit=None):
        if output_path is None:
            output_path = os.path.join(RAW_DATA_DIR, "openphish_raw.csv")

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        print(f"[Acquisition] Fetching OpenPhish community feed from {cls.FEED_URL}...")

        raw_bytes = _fetch_url(cls.FEED_URL, timeout=30)
        lines = raw_bytes.decode("utf-8", errors="replace").splitlines()

        records = []
        for idx, line in enumerate(lines):
            url = line.strip()
            if not url or url.startswith("#"):
                continue
            records.append({
                "url": url,
                "label": 1,
                "threat_category": "phishing",
                "source": "openphish",
                "source_id": f"openphish-{idx}",
                "target": "unknown",
                "submission_time": "",
                "verified": "yes",
                "collection_timestamp": datetime.now(timezone.utc).isoformat()
            })
            if limit and len(records) >= limit:
                break

        with open(output_path, "w", encoding="utf-8", newline="") as f:
            if records:
                writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
                writer.writeheader()
                writer.writerows(records)

        print(f"[Acquisition] OpenPhish: saved {len(records)} raw records to {output_path}")
        return output_path, records


class TrancoBenignAdapter:
    """Acquires and synthesizes legitimate URL samples from Tranco Top Sites ranking."""

    FEED_URL = "https://tranco-list.eu/top-1m.csv.zip"

    # Diverse legitimate URL paths to avoid trivial root-only bias in benign samples
    BENIGN_PATH_TEMPLATES = [
        "",
        "/",
        "/about",
        "/contact",
        "/help/faq",
        "/docs/api/v2",
        "/products/catalog?category=all",
        "/articles/2026/security-update",
        "/user/profile",
        "/login",
        "/services/overview.html",
        "/downloads/software-release",
        "/search?q=cybersecurity&page=1",
        "/privacy-policy",
        "/terms-of-service",
        "/portal/dashboard"
    ]

    @classmethod
    def acquire(cls, output_path=None, limit=10000):
        if output_path is None:
            output_path = os.path.join(RAW_DATA_DIR, "tranco_raw.csv")

        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        print(f"[Acquisition] Fetching Tranco Top 1M list from {cls.FEED_URL}...")

        raw_bytes = _fetch_url(cls.FEED_URL, timeout=45)
        with zipfile.ZipFile(io.BytesIO(raw_bytes)) as z:
            csv_filename = z.namelist()[0]
            with z.open(csv_filename) as f:
                content = f.read().decode("utf-8", errors="replace")

        records = []
        reader = csv.reader(io.StringIO(content))
        for row in reader:
            if not row or len(row) < 2:
                continue
            rank = row[0].strip()
            domain = row[1].strip().lower()
            if not domain:
                continue

            # Alternate between HTTPS and path diversity to reflect real legitimate web traffic
            path_idx = len(records) % len(cls.BENIGN_PATH_TEMPLATES)
            path = cls.BENIGN_PATH_TEMPLATES[path_idx]
            scheme = "https"

            url = f"{scheme}://{domain}{path}"
            records.append({
                "url": url,
                "label": 0,
                "threat_category": "benign",
                "source": "tranco",
                "source_id": f"tranco-rank-{rank}",
                "target": "none",
                "submission_time": "",
                "verified": "yes",
                "collection_timestamp": datetime.now(timezone.utc).isoformat()
            })
            if limit and len(records) >= limit:
                break

        with open(output_path, "w", encoding="utf-8", newline="") as f:
            if records:
                writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
                writer.writeheader()
                writer.writerows(records)

        print(f"[Acquisition] Tranco: saved {len(records)} raw records to {output_path}")
        return output_path, records


def run_acquisition(limit_per_source=7500):
    """Run full dataset acquisition across all candidate sources."""
    results = {}
    try:
        pt_path, pt_recs = PhishTankAdapter.acquire(limit=limit_per_source)
        results["phishtank"] = {"path": pt_path, "count": len(pt_recs)}
    except Exception as e:
        print(f"[Acquisition] PhishTank error: {e}")

    try:
        op_path, op_recs = OpenPhishAdapter.acquire(limit=limit_per_source)
        results["openphish"] = {"path": op_path, "count": len(op_recs)}
    except Exception as e:
        print(f"[Acquisition] OpenPhish error: {e}")

    try:
        # Match benign volume to total malicious volume
        malicious_count = sum(r["count"] for r in results.values())
        benign_limit = max(malicious_count, 7500)
        tr_path, tr_recs = TrancoBenignAdapter.acquire(limit=benign_limit)
        results["tranco"] = {"path": tr_path, "count": len(tr_recs)}
    except Exception as e:
        print(f"[Acquisition] Tranco error: {e}")

    manifest_path = os.path.join(RAW_DATA_DIR, "raw_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "sources": results,
            "total_raw_records": sum(r["count"] for r in results.values())
        }, f, indent=4)

    print(f"[Acquisition] Complete. Total raw records: {sum(r['count'] for r in results.values())}")
    return results


if __name__ == "__main__":
    run_acquisition()
