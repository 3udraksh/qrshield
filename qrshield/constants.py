"""
QRShield Security Constants & Heuristic Configurations
"""

import os

ML_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "ml",
    "qrshield_model.joblib"
)

HYBRID_MODEL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "ml",
    "models",
    "qrshield_hybrid_v2.joblib"
)

SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "password",
    "passwd",
    "account",
    "secure",
    "update",
    "confirm",
    "wallet",
    "payment",
    "bank",
    "credential",
    "authenticate",
]

SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".buzz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
]

REDIRECT_STATUS_CODES = {
    301,
    302,
    303,
    307,
    308
}
