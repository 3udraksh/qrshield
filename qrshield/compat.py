"""
QRShield Internal Dynamic Dispatch Compatibility Helper
"""

import sys


def dispatch(name, default):
    """
    Look up `name` from the root `analyzer` module if it has been loaded and
    patched or overridden; otherwise fallback to `default`.
    This guarantees transparent compatibility with test fixtures that patch
    functions on the root `analyzer` module.
    """
    analyzer_mod = sys.modules.get("analyzer")
    if analyzer_mod is not None:
        val = getattr(analyzer_mod, name, None)
        if val is not None:
            return val
    return default
