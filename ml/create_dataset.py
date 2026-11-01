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