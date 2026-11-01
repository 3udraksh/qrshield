# QRShield

## Explainable Defensive Security Analysis Engine for QR-Based Content

QRShield is an open-source, defensive cybersecurity analysis platform engineered to inspect, evaluate, and explain threats embedded in QR codes before users interact with untrusted destinations.

By synthesizing QR computer vision decoding, lexical heuristics, DNS/network intelligence, direct TLS certificate validation with DNS-pinning SSRF protection, HTTP redirect graph analysis, reputation intelligence, machine-learning consensus, and LLM-ready explainability contracts, QRShield delivers transparent, auditable security verdicts.

---

## 1. System Architecture

```text
               ┌────────────────────────────────────────────────────────┐
               │                    Input Surface                       │
               │         - Raw Destination URL / Payload                │
               │         - Multipart QR Image (PNG, JPG, JPEG)          │
               └──────────────────────────┬─────────────────────────────┘
                                          │
                                          ▼
               ┌────────────────────────────────────────────────────────┐
               │                     Web Presentation                   │
               │     Flask Application (app.py) & Modular Services      │
               │  - ScanService: In-Memory OpenCV QR Decoding           │
               │  - HistoryService: Telemetry & Corruption Recovery     │
               │  - ReportService: Bounded Scan Cache & Isolated Export │
               └──────────────────────────┬─────────────────────────────┘
                                          │
                                          ▼
               ┌────────────────────────────────────────────────────────┐
               │          qrshield Orchestrator (analyze_url)           │
               └───────┬────────────┬─────────────┬─────────────┬───────┘
                       │            │             │             │
        ┌──────────────┴──┐  ┌──────┴──────┐  ┌───┴──────────┐  │
        ▼                 ▼  ▼             ▼  ▼              ▼  ▼
 ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌────────────────┐
 │qrshield.     │ │qrshield.     │ │qrshield.     │ │qrshield.       │
 │content_types │ │lexical       │ │network       │ │redirects       │
 │- URL, Wi-Fi, │ │- Entropy     │ │- SSRF Guard  │ │- Loop Detect   │
 │  vCard, SMS, │ │- Layer Dec.  │ │- DNS Intel   │ │- Downgrade Det │
 │  Email, Text │ │- Punycode    │ │- TLS Pinning │ │- Cross-Domain  │
 └──────────────┘ └──────────────┘ └──────────────┘ └────────────────┘
        │                 │                │                 │
        └──────────────┬──┴────────────────┴──┬──────────────┘
                       │                      │
                       ▼                      ▼
               ┌────────────────┐     ┌────────────────┐
               │qrshield.       │     │qrshield.       │
               │reputation      │     │ml              │
               │- URLhaus API   │     │- 9-Feature RF  │
               │- Safe Browsing │     │- Consensus Eng │
               └───────┬────────┘     └───────┬────────┘
                       │                      │
                       └───────────┬──────────┘
                                   │
                                   ▼
               ┌────────────────────────────────────────────────┐
               │            qrshield.explainability             │
               │  - Multi-tier Risk Engine (Score & Severity)   │
               │  - Explainability Contract (Structured Audit)  │
               │  - AI Context & Guidance Synthesis             │
               │  - JSON Security Report Serializer             │
               └────────────────────────────────────────────────┘
```

---

## 2. Core Detection Subsystems

### 2.1 Lexical & Structural URL Intelligence (`qrshield.lexical`)
- **Shannon Entropy Analysis**: Detects pseudo-random and algorithmically generated subdomains and paths (`calculate_entropy`).
- **Multi-layer Recursive Percent-Unquoting**: Recursively unwraps double or multi-layer percent-encoded evasion payloads (`decode_url_layers`).
- **Punycode / IDN Detection**: Flags Internationalized Domain Names containing `xn--` indicators commonly abused for visual homoglyph spoofing (`analyze_punycode`).
- **Port Inspection**: Identifies non-standard explicit destination ports (e.g., `:8080`, `:8443`).
- **Credential & Deception Parsing**: Detects userinfo `@` deception patterns where fake domains mimic legitimacy, and suspicious path/query parameters (`login`, `verify`, `token`).

### 2.2 Content-Type Parser (`qrshield.content_types`)
Inspects raw QR payloads and extracts embedded targets across diverse communication protocols:
- `URL` (HTTP/HTTPS schemes)
- `WIFI` (`WIFI:S:...;T:...;P:...;;` network configurations with open-network detection)
- `VCARD` (Electronic business cards with embedded website URL extraction)
- `EMAIL` (`mailto:` schemes with body link extraction)
- `SMS` / `PHONE` (`sms:` and `tel:` schemes with embedded URI extraction)

### 2.3 SSRF Hardening & Network Transport (`qrshield.network`)
Prevents Server-Side Request Forgery (SSRF) and DNS rebinding attacks:
- **Strict Destination Validation**: Blocks direct non-public IP literals and resolved hostnames mapping to loopback (`127.0.0.0/8`, `::1`), RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local/cloud-metadata (`169.254.169.254`), documentation networks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), multicast, and carrier-grade NAT.
- **DNS Pinning**: `get_tls_certificate()` and `get_tls_connection()` pre-validate resolved IP addresses against SSRF filters, open raw TCP sockets directly to the validated IP, and bind the original hostname strictly to the TLS Server Name Indication (SNI) extension (`server_hostname=sni_hostname`). This prevents time-of-check to time-of-use (TOCTOU) DNS rebinding attacks.

### 2.4 Redirect Graph & Protocol Analysis (`qrshield.redirects`)
- **Hop-by-hop HTTP Inspection**: Uses custom `NoRedirectHandler` to trace redirection chains step-by-step.
- **Safety Checks**: Terminates immediately upon loop detection or encountering non-public destination IPs.
- **Protocol Downgrade Detection**: Flags HTTPS-to-HTTP downgrade transitions as high-severity risks.
- **Cross-Domain Auditing**: Quantifies multi-domain redirection hops frequently observed in traffic distribution systems (TDS).

### 2.5 Machine Learning & Consensus Scoring (`qrshield.ml`)
- **Model**: Offline `RandomForestClassifier` trained with scikit-learn (`ml/qrshield_model.joblib`).
- **Feature Vector**: 9 deterministic lexical signals extracted in exact order:
  1. `URL Length`
  2. `Hostname Length`
  3. `Subdomain Count`
  4. `Path Depth`
  5. `Query Parameters`
  6. `Percent Encoded Characters`
  7. `Hostname Hyphens`
  8. `Hostname Digits`
  9. `Hostname Entropy`
- **Consensus Logic**: Reconciles rule-based heuristic risk score with ML classifier predictions:
  - `AGREE_SAFE` / `AGREE_SUSPICIOUS`: Consensus between engines reinforces confidence.
  - `DISAGREE_ML_HIGH` / `DISAGREE_HEURISTIC_HIGH`: Escalates ambiguous findings for explicit human-in-the-loop audit.

---

## 3. High-Performance Ingestion & Export

### In-Memory QR Decoding
Uploaded QR images are decoded directly from memory buffers using `cv2.imdecode(np.frombuffer(file_bytes, np.uint8), cv2.IMREAD_COLOR)`. Temporary disk file artifacts in `uploads/` are completely eliminated.

### Cached Report Generation
`app.py` implements a thread-safe, bounded in-memory cache (`ReportService`). Exporting a security report for an already analyzed destination reuses pre-computed audit results rather than re-running network, TLS, DNS, or ML analysis. Reports are serialized into isolated temporary files and deleted immediately post-transmission via Flask `@after_this_request`.

---

## 4. Project Structure

```text
qrshield/
├── app.py                     # Flask application entry point and HTTP route handlers
├── analyzer.py                # Backward-compatible facade delegating to qrshield package
│
├── qrshield/                  # Modular Core Engine
│   ├── __init__.py            # Public API exports
│   ├── compat.py              # Internal dynamic dispatch compatibility helper
│   ├── constants.py           # Engine constants, thresholds, and keyword registries
│   ├── content_types.py       # QR payload scheme decoders (URL, Wi-Fi, vCard, SMS, Email)
│   ├── explainability.py      # Risk scoring engine, evidence aggregation, and report builder
│   ├── lexical.py             # Shannon entropy, unquoting, Punycode, and port analyzers
│   ├── ml.py                  # ML feature extraction, model loading, and consensus scoring
│   ├── network.py             # SSRF prevention, DNS pinning, and TLS inspection
│   ├── orchestrator.py        # Complete analyze_url analysis pipeline orchestration
│   ├── redirects.py           # Redirect chain inspection and loop detection
│   ├── reputation.py          # Threat intelligence query wrappers (URLhaus, Safe Browsing)
│   └── services.py            # Application services (ScanService, HistoryService, ReportService)
│
├── ml/                        # Machine Learning Pipeline
│   ├── dataset.csv            # Synthetic training demonstration dataset
│   ├── qrshield_model.joblib  # Serialized Random Forest classifier
│   ├── create_dataset.py      # Dataset generation script (reference only)
│   └── train_model.py         # Model training script (reference only)
│
├── templates/                 # Jinja2 HTML Templates
│   ├── index.html             # Interactive scan interface and explainability view
│   └── dashboard.html         # Historical scan telemetry and risk metrics dashboard
│
├── static/                    # Frontend Assets
│   └── style.css              # Cyber-defensive interface styling
│
├── demo_qr/                   # Demonstration Fixtures
│   ├── campus_safe.png        # Valid campus HTTPS QR fixture
│   └── campus_phishing_demo.png
│
├── tests/                     # Frozen Tier 1 Baseline Regression Suite (66 tests)
│   ├── test_base.py           # Isolated test harness with zero-network fixtures
│   ├── test_golden_master.py  # 12 deterministic Golden Master characterization cases
│   ├── test_lexical.py        # Lexical analysis unit tests
│   ├── test_content_types.py  # Content type parser unit tests
│   ├── test_ssrf_validator.py # SSRF and IP blocking unit tests
│   ├── test_redirects.py      # Redirect engine unit tests
│   ├── test_ml_consensus.py   # Machine learning consensus unit tests
│   ├── test_explainability_contract.py # Contract schema validation tests
│   ├── test_history.py        # History persistence and corruption recovery tests
│   └── test_routes.py         # Web endpoints integration tests
│
└── tests_tier2/               # Tier 2 Behavioral & Security Suites (9 tests)
    ├── test_tier2_security.py             # SSRF blocking, DNS pinning & transport tests
    └── test_tier2_ingestion_and_export.py # In-memory decoding & export cache tests
```

---

## 5. Verification & Testing

The repository maintains strict two-tier test isolation. All tests run deterministically with zero network emissions.

### 5.1 Run Tier 1 Baseline Regression Suite (66 tests)
```bash
python3 -m unittest discover -s tests -p "test_*.py" -v
```
Verifies complete preservation of legacy behavior across:
- GM-01 through GM-12 Golden Master contracts (scores, findings, risk levels, explainability validation)
- SSRF non-public IP blocking (IPv4, IPv6, loopback, private RFC 1918, link-local)
- History persistence, 20-item capping, and JSON corruption recovery
- In-memory route dispatch and error handling

### 5.2 Run Tier 2 Security & Architecture Suite (9 tests)
```bash
python3 -m unittest discover -s tests_tier2 -p "test_*.py" -v
```
Verifies architectural refactoring improvements:
- SSRF validation and socket DNS pinning during TLS inspection
- Elimination of temporary disk writes during QR image ingestion
- Thread-safe report exports without re-analyzing cached destinations

---

## 6. Running the Web Application

```bash
# 1. Activate virtual environment
source .venv/bin/activate

# 2. Run Flask server
python3 app.py
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

---

## 7. Known Limitations & Research Boundaries

1. **Synthetic Demonstration Model**: The included `ml/qrshield_model.joblib` artifact is trained on a small synthetic demonstration dataset (`ml/dataset.csv`). It is designed to illustrate the feature extraction and dual-engine consensus workflow, not for out-of-sample real-world threat classification without retraining on larger empirical corpora (e.g., PhishTank, URLhaus bulk feeds).
2. **Third-Party Reputation Feeds**: In default offline testing, URLhaus and Google Safe Browsing lookups are mocked or bypassed. Live production deployment requires configuring active API keys in environment variables (`URLHAUS_API_KEY`, `SAFE_BROWSING_API_KEY`).
3. **AI Explanations**: The Gemini-backed explanation engine requires a valid `GEMINI_API_KEY`. When unconfigured, QRShield falls back seamlessly to deterministic rule-based explainability summaries.
