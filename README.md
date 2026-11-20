# QRShield v2.0

## Explainable Defensive Cybersecurity Analysis Engine for QR-Based Content

QRShield is an open-source, defensive cybersecurity analysis platform engineered to inspect, evaluate, and explain threats embedded in QR codes before users interact with untrusted destinations.

By synthesizing QR computer vision decoding, lexical heuristics, DNS/network intelligence, direct TLS certificate validation with DNS-pinning SSRF protection, HTTP redirect graph analysis, reputation intelligence, machine-learning consensus, and LLM-ready explainability contracts, QRShield delivers transparent, auditable security verdicts.

---

## 1. System Architecture

```text
               ┌────────────────────────────────────────────────────────┐
               │                    Input Surface                       │
               │         - Raw Destination URL / Payload                │
               │         - Drag & Drop Multipart QR (PNG, JPG, JPEG)    │
               └──────────────────────────┬─────────────────────────────┘
                                          │
                                          ▼
               ┌────────────────────────────────────────────────────────┐
               │              Web Presentation Layer (v2)               │
               │     Flask Application (app.py) & Modular Services      │
               │  - ScanService: In-Memory OpenCV QR Decoding           │
               │  - HistoryService: Search, Filter, Clear & Telemetry   │
               │  - ReportService: Bounded Scan Cache & Isolated Export │
               │  - Config & Privacy: Environment Overrides & Redaction │
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
 │  vCard, SMS, │ │- Layer Dec.  │ │- DNS Pinning │ │- Downgrade Det │
 │  Email, Text │ │- Punycode    │ │- Pinned HTTP │ │- Cross-Domain  │
 └──────────────┘ └──────────────┘ └──────────────┘ └────────────────┘
        │                 │                │                 │
        └──────────────┬──┴────────────────┴──┬──────────────┘
                       │                      │
                       ▼                      ▼
               ┌────────────────┐     ┌────────────────┐
               │qrshield.       │     │qrshield.       │
               │reputation      │     │ml              │
               │- URLhaus API   │     │- 9-Feature RF  │
               │- Safe Browsing │     │- Tree-Vote Cal.│
               │- Local Mode    │     │- Uncertainty   │
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
               │  - JSON Security Report v2 Serializer          │
               │  - Credential & Token Redaction Masking        │
               └────────────────────────────────────────────────┘
```

---

## 2. Core Detection & Security Subsystems

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

### 2.3 SSRF Hardening & DNS Pinning (`qrshield.network`)
Prevents Server-Side Request Forgery (SSRF) and time-of-check to time-of-use (TOCTOU) DNS rebinding attacks:
- **Strict Destination Validation**: Blocks direct non-public IP literals and resolved hostnames mapping to loopback (`127.0.0.0/8`, `::1`), RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local/cloud-metadata (`169.254.169.254`), documentation networks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), multicast, and carrier-grade NAT.
- **Fail-Closed Mixed DNS Handling**: Hostnames resolving to a mixture of public and private IPs are rejected fail-closed.
- **Pinned HTTP/HTTPS Handlers**: Outbound requests employ `PinnedHTTPConnection` and `PinnedHTTPSConnection`, creating TCP sockets directly connected to pre-validated destination IPs while passing the original domain via the HTTP `Host` header and TLS `Server Name Indication` (SNI).

### 2.4 Privacy & Sensitive Credential Redaction (`qrshield.privacy`)
Protects user privacy and credential hygiene:
- **Wi-Fi Password Masking**: Automatically redacts Wi-Fi network passwords (`P:[REDACTED]`) from display, export reports, and persisted scan history.
- **URL Sensitive Query Redaction**: Redacts authentication tokens, passwords, session IDs, and secret keys in URL parameters (e.g., `token=[REDACTED]`).
- **Contract Preservation**: Keeps raw input within internal analysis buffers for contract compliance while exposing sanitized representations (`safe_content`) to templates, telemetry, and reports.

### 2.5 Machine Learning & Consensus Scoring (`qrshield.ml`)
- **Model**: Offline `RandomForestClassifier` trained with scikit-learn (`ml/qrshield_model.joblib`).
- **Feature Vector**: 9 deterministic lexical signals extracted in exact order:
  1. `URL Length`, 2. `Hostname Length`, 3. `Subdomain Count`, 4. `Path Depth`, 5. `Query Parameters`, 6. `Percent Encoded Characters`, 7. `Hostname Hyphens`, 8. `Hostname Digits`, 9. `Hostname Entropy`.
- **Tree-Vote Calibration Disclaimer**: Clarifies that tree-vote proportions represent voting fractions rather than calibrated posterior probabilities.
- **Uncertainty Flag**: Automatically raises an uncertainty alert when vote confidence sits near the classification boundary (40% to 60%).
- **Consensus Logic**: Reconciles rule-based heuristic risk score with ML classifier predictions:
  - `AGREE_SAFE` / `AGREE_SUSPICIOUS`: Consensus between engines reinforces confidence.
  - `ML_DISAGREEMENT`: Deterministic heuristic findings remain authoritative while flagging the discrepancy.

---

## 3. High-Performance Ingestion, History & Dashboard

### In-Memory QR Decoding & Drag-Drop Interface
Uploaded QR images are decoded directly from memory buffers using `cv2.imdecode(np.frombuffer(file_bytes, np.uint8), cv2.IMREAD_COLOR)`. An interactive drag-and-drop dropzone with client-side image preview provides zero-latency feedback without temporary disk writes.

### Telemetry Search, Filter & Sample vs. Live Scans
- **Search & Filtering**: Search historical scans by keywords, risk categories (`LOW RISK`, `CAUTION`, `HIGH RISK`), or content types (`URL`, `WIFI`, `VCARD`, `SMS`).
- **Dataset Traceability**: Clear labeling of demonstration records (`[Sample Data]`) vs. actual interactive user scans (`[Live Scan]`).
- **History Management**: One-click history clearance with interactive confirmation dialog.
- **Scan Detail Inspection**: Modal view for quick inspection of complete telemetry records.

### Cached Report Generation
`app.py` implements a thread-safe, bounded in-memory cache (`ReportService`). Exporting a security report for an already analyzed destination reuses pre-computed audit results rather than re-running network, TLS, DNS, or ML analysis. Reports are serialized into isolated temporary files and deleted immediately post-transmission via Flask `@after_this_request`.

---

## 4. Configuration & Environment Settings (`qrshield/config.py`)

QRShield is configured via environment variables with safe defaults:

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `QRSHIELD_LOCAL_MODE` | `1` | Zero external network egress for maximum user privacy |
| `REDACT_SENSITIVE_DATA` | `1` | Mask passwords and sensitive authentication tokens |
| `MAX_HISTORY` | `20` | Maximum number of persisted historical scans |
| `MAX_CACHE_SIZE` | `50` | Maximum in-memory cached scan reports |
| `URLHAUS_AUTH_KEY` | `""` | Optional threat intelligence API key for URLhaus |
| `GOOGLE_SAFE_BROWSING_API_KEY` | `""` | Optional Google Safe Browsing API key |
| `GEMINI_API_KEY` | `""` | Optional Gemini API key for natural language explanations |

---

## 5. Project Structure

```text
qrshield/
├── app.py                     # Flask application entry point and HTTP route handlers
├── analyzer.py                # Backward-compatible facade delegating to qrshield package
├── scan_history.json          # Telemetry datastore (demonstration seed data)
│
├── qrshield/                  # Modular Core Engine
│   ├── __init__.py            # Public API exports
│   ├── compat.py              # Internal dynamic dispatch compatibility helper
│   ├── config.py              # Runtime configuration & environment settings
│   ├── constants.py           # Engine constants, thresholds, and keyword registries
│   ├── content_types.py       # QR payload scheme decoders (URL, Wi-Fi, vCard, SMS, Email)
│   ├── explainability.py      # Risk scoring engine, evidence aggregation, and report builder
│   ├── lexical.py             # Shannon entropy, unquoting, Punycode, and port analyzers
│   ├── ml.py                  # ML feature extraction, model loading, and consensus scoring
│   ├── network.py             # SSRF prevention, DNS pinning, and TLS inspection
│   ├── orchestrator.py        # Complete analyze_url analysis pipeline orchestration
│   ├── privacy.py             # Sensitive credential masking & query parameter redaction
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
│   ├── index.html             # Interactive scan interface, dropzone, and explainability view
│   └── dashboard.html         # Historical scan telemetry, filters, and metrics dashboard
│
├── static/                    # Frontend Assets
│   └── style.css              # Cyber-defensive interface styling & dark-accent theme
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
└── tests_tier2/               # Tier 2 Behavioral & Security Suites (29 tests)
    ├── test_tier2_security.py             # SSRF blocking, DNS pinning & transport tests
    ├── test_tier2_ingestion_and_export.py # In-memory decoding & export cache tests
    └── test_tier2_v2_features.py          # Privacy redaction, ML metadata & telemetry tests
```

---

## 6. Verification & Automated Testing

The repository maintains strict two-tier test isolation. All tests run deterministically with zero network emissions:

### 6.1 Run Tier 1 Baseline Regression Suite (66 tests)
```bash
.venv/bin/python -m unittest discover -s tests -p "test_*.py" -v
```
Verifies complete preservation of baseline behavior across:
- GM-01 through GM-12 Golden Master contracts (scores, findings, risk levels, explainability validation)
- SSRF non-public IP blocking (IPv4, IPv6, loopback, private RFC 1918, link-local)
- History persistence, 20-item capping, and JSON corruption recovery
- In-memory route dispatch and error handling

### 6.2 Run Tier 2 Security & Architecture Suite (29 tests)
```bash
.venv/bin/python -m unittest discover -s tests_tier2 -p "test_*.py" -v
```
Verifies architectural refactoring improvements:
- SSRF validation and socket DNS pinning during TLS inspection (`PinnedHTTPConnection`, `PinnedHTTPSConnection`)
- Elimination of temporary disk writes during QR image ingestion
- Thread-safe report exports without re-analyzing cached destinations
- Sensitive credential redaction across Wi-Fi passwords and URL query parameters
- ML model metadata, tree-vote calibration disclaimers, and uncertainty indicator
- Telemetry keyword searching, risk level filtering, history clearance, and sample vs. live data tagging

---

## 7. Running the Web Application

```bash
# 1. Activate virtual environment
source .venv/bin/activate

# 2. Run Flask server
python app.py
```
Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.
