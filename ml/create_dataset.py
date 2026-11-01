"""
QRShield ML Dataset Generation Utility

NOTE: This script generates a small, synthetic dataset based on handcrafted seed
URLs (8 safe, 8 suspicious). It serves as an educational proof-of-concept
demonstrating the feature-extraction pipeline and Random Forest model training.
It is NOT representative of wide-scale web-threat distributions and must not
be regenerated during regression test execution.
"""

import csv
import random

from analyzer import analyze_url, extract_ml_features


SAFE_URLS = [
    "https://example.com",
    "https://example.org",
    "https://www.python.org",
    "https://www.wikipedia.org",
    "https://www.mozilla.org",
    "https://github.com",
    "https://www.microsoft.com",
    "https://www.google.com"
]


SUSPICIOUS_URLS = [
    "http://192.168.1.10/login",
    "http://example.com/verify/account/password",
    "http://example.com/login?redirect=http://evil.example",
    "http://secure-account-login.example.com/verify",
    "http://example.com/update/security/confirm/password",
    "http://example.com/login.php?user=admin&verify=1",
    "http://xn--pple-43d.example/login",
    "http://example.com/account/verify/password/reset"
]


FEATURES = [
    "URL Length",
    "Hostname Length",
    "Subdomain Count",
    "Path Depth",
    "Query Parameters",
    "Percent Encoded Characters",
    "Hostname Hyphens",
    "Hostname Digits",
    "Hostname Entropy"
]


def generate_dataset():

    rows = []

    for url in SAFE_URLS:

        result = analyze_url(url)

        rows.append(
            extract_ml_features(result) + [0]
        )

    for url in SUSPICIOUS_URLS:

        result = analyze_url(url)

        rows.append(
            extract_ml_features(result) + [1]
        )

    random.shuffle(rows)

    with open(
        "ml/dataset.csv",
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(file)

        writer.writerow(
            FEATURES + ["label"]
        )

        writer.writerows(rows)


if __name__ == "__main__":

    generate_dataset()

    print(
        "Dataset created: ml/dataset.csv"
    )