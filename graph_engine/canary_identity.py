"""Canary credentials — fixed fake identity, overridable via environment.

The ``.invalid`` TLD is reserved by RFC 2606 and guaranteed non-routable:
no real mailbox can ever receive mail sent to it, so the canary email is
safe to submit into phishing forms.
"""

from __future__ import annotations

import os

# ---- email — .invalid TLD (RFC 2606), guaranteed non-deliverable ------------

CANARY_EMAIL: str = os.environ.get(
    "IVX_CANARY_EMAIL",
    "analyst.canary@ivx-research.invalid",
)

# ---- password — syntactically valid, obviously fake, passes client-side ------
#      validation (uppercase, lowercase, digit, symbol, length >= 12) ----------

CANARY_PASSWORD: str = os.environ.get(
    "IVX_CANARY_PASSWORD",
    "CanaryPass!2024#X",
)

# ---- metadata for Evidence records -------------------------------------------

CANARY_LABEL: str = os.environ.get(
    "IVX_CANARY_LABEL",
    "analyst-c4n4ry-0001",
)
