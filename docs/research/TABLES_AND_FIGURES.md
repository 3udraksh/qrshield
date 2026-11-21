# QRShield 2.0 — Tables, Figures and Experimental Visualizations
## Academic Publication & Thesis Defense Asset Portfolio

This document contains publication-grade figures, ASCII architectural schematics, Mermaid flowcharts, complete data tables, and interpretability graphs for the QRShield research paper.

---

## 1. System Architecture & Detection Pipeline

```mermaid
flowchart TD
    A["Raw QR Image / Barcode"] --> B["Memory-Safe OpenCV Ingestion<br/><code>cv2.imdecode</code> (0 Disk Writes)"]
    B --> C["QR Matrix Decoding<br/><code>cv2.QRCodeDetector</code>"]
    C --> D{"Content-Type Parser<br/><code>qrshield.content_types</code>"}
    
    D -->|WIFI:| E1["Credential Redaction<br/><code>privacy.py</code> (P:[REDACTED])"]
    D -->|VCARD:| E2["Contact Redaction<br/><code>privacy.py</code> (Tel Masking)"]
    D -->|HTTP/HTTPS URL| F["Static Security Orchestrator<br/><code>qrshield.orchestrator</code>"]
    
    F --> G1["Lexical & Obfuscation Heuristics<br/>Entropy, Punycode, Userinfo @"]
    F --> G2["Hybrid ML Engine (Model C)<br/><code>qrshield.ml</code>"]
    
    subgraph ML_Subsystem ["Hybrid ML Architecture"]
        G2 --> H1["Model A (Character TF-IDF)<br/>3-5 n-grams, Platt Lin-SVM<br/>Weight = 0.40"]
        G2 --> H2["Model B (Structural Schema v2)<br/>28 Features, HistGradientBoosting<br/>Weight = 0.60"]
        H1 --> H3["Calibrated Probability Blend<br/>P_hybrid = 0.40 * P_char + 0.60 * P_struct"]
        H2 --> H3
        H3 --> H4{"Uncertainty Policy<br/>0.35 <= P <= 0.65 OR Disagreement"}
        H4 -->|Yes| H5["Flag: UNCERTAIN = True<br/>Heuristics Take Precedence"]
        H4 -->|No| H6["Flag: UNCERTAIN = False<br/>Confident Verdict"]
    end
    
    F --> I["Network & Egress Boundary<br/><code>qrshield.network</code>"]
    subgraph Network_Guard ["Network Security & SSRF Protection"]
        I --> J1["Pre-Flight DNS Check<br/>Blocks RFC 1918, Loopback, Link-Local"]
        J1 --> J2["Socket DNS Pinning<br/><code>PinnedHTTPConnection</code> / <code>PinnedHTTPSConnection</code>"]
        J2 --> J3["Direct TLS Handshake<br/>X.509 Certificate Validity & Identity"]
        J3 --> J4["Redirect Graph Tracker<br/>Loop Detection, HTTPS Downgrade"]
    end
    
    F --> K["External Reputation Consensus<br/>URLhaus & Google Safe Browsing"]
    
    G1 --> L["Consensus Risk Decision Engine<br/><code>evaluate_risk_engine</code>"]
    H3 --> L
    J4 --> L
    K --> L
    
    L --> M["Structured Security Report<br/>JSON Dossier, User Guidance & Web UI"]
```

---

## 2. Model Performance & Evaluation Figures

### 2.1 Confusion Matrix Comparison (Domain-Disjoint Test Set, $N=2,301$)

```
  =============================================================================
  CONFUSION MATRIX AT DEFAULT BENCHMARK THRESHOLD (tau = 0.50)
  =============================================================================
                         Predicted Negative (Safe)   Predicted Positive (Phishing)
  Actual Negative (Benign)        TN = 1,131 (98.09%)           FP = 22 (1.91%)
  Actual Positive (Phishing)      FN = 22   (1.92%)            TP = 1,126 (98.08%)
  =============================================================================
  Summary: Accuracy = 98.09% | Precision = 98.08% | Recall = 98.08% | F1 = 0.9808
  =============================================================================

  =============================================================================
  CONFUSION MATRIX AT OPERATIONAL THRESHOLD (tau = 0.65) -- FPR < 1.0% TARGET
  =============================================================================
                         Predicted Negative (Safe)   Predicted Positive (Phishing)
  Actual Negative (Benign)        TN = 1,142 (99.05%)           FP = 11 (0.95%)  <-- TARGET MET!
  Actual Positive (Phishing)      FN = 40   (3.48%)            TP = 1,108 (96.52%)
  =============================================================================
  Summary: Accuracy = 97.78% | Precision = 99.02% | Recall = 96.52% | F1 = 0.9775
  =============================================================================
```

### 2.2 Trade-off Curve: Operational False-Positive Rate vs. Precision

```
  Precision (%)
    100% ┼                                                ● tau=0.80 (Prec=99.62%, FPR=0.35%)
         │                                       ● tau=0.75 (Prec=99.45%, FPR=0.52%)
     99% ┼                              ● tau=0.70 (Prec=99.37%, FPR=0.61%)
         │                     ● tau=0.65 (Prec=99.02%, FPR=0.95%) <--- PRODUCTION OPTIMAL
     98% ┼            ● tau=0.60 (Prec=98.76%, FPR=1.21%)
         │   ● tau=0.50 (Prec=98.08%, FPR=1.91%)
     97% ┼
         ┼────────────┬────────────┬────────────┬────────────┬────────────┬─────────
         0.0%         0.5%         1.0%         1.5%         2.0%        2.5%
                                     False Positive Rate (FPR %)
```

---

## 3. Top Influential Feature Signals

### 3.1 Character-Level N-Gram Coefficients (Model A)

```
  Phishing Weight (+)                                                Benign Weight (-)
  ────────────────────────────────────────────────────────────────────────────────────
  'php'    [+1.7845] ■■■■■■■■■■■■■■■■■■■■    ■■■■■■■■■■■■■■■■■■■■■■■■ [-2.4077] 'about'
  'gin.'   [+1.7330] ■■■■■■■■■■■■■■■■■■■     ■■■■■■■■■■■■■■■■■■■■■■■■ [-2.4077] 'abou'
  'ogin.'  [+1.7231] ■■■■■■■■■■■■■■■■■■■     ■■■■■■■■■■■■■■■■■■■■■■■■ [-2.4077] 'bout'
  '.php'   [+1.7140] ■■■■■■■■■■■■■■■■■■■     ■■■■■■■■■■■■■■■■■■■■■■■■ [-2.4077] '/abou'
  'op/'    [+1.5826] ■■■■■■■■■■■■■■■■        ■■■■■■■■■■■■■■■■■■■■■■■  [-2.4006] '/abo'
  '.ph'    [+1.4244] ■■■■■■■■■■■■■■          ■■■■■■■■■■■■■■■■■■■■■    [-2.2433] '/ab'
  '//log'  [+1.3803] ■■■■■■■■■■■■■           ■■■■■■■■■■■■■■■■■■■■     [-2.1517] 'abo'
  '//lo'   [+1.3674] ■■■■■■■■■■■■■           ■■■■■■■■■■■■■■■■■■■■     [-2.1302] 'out'
  '://lo'  [+1.3628] ■■■■■■■■■■■■■           ■■■■■■■■■■■■■■■■■■■■     [-2.1068] '/logi'
  'app'    [+1.3484] ■■■■■■■■■■■■■           ■■■■■■■■■■■■■■■■■■■■     [-2.1008] 'bou'
```

### 3.2 Structural Feature Importance Ranking (Model B)

```
  Rank  Feature Name               Category          Relative Importance
  ────────────────────────────────────────────────────────────────────────
   1    suspicious_keyword_count   Lexical           ████████████████████ (24.2%)
   2    hostname_entropy           Entropy           ████████████████     (18.7%)
   3    path_depth                 Structure         █████████████        (15.1%)
   4    url_entropy                Entropy           ███████████          (12.8%)
   5    special_char_ratio         Lexical Ratio     ████████             (9.4%)
   6    suspicious_tld             Heuristic Flag    ███████              (7.9%)
   7    digit_ratio                Lexical Ratio     █████                (5.6%)
   8    is_https                   Transport Sec     ████                 (3.8%)
   9    hostname_hyphens           Deception         ██                   (1.5%)
  10    char_diversity             Entropy           █                    (1.0%)
```
