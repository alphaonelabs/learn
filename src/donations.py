"""
Business logic for the donations feature.
Validation, amount handling, and record formatting.
Email notifications live in api/donations.py (runtime layer).
"""
import re
from typing import Optional, Tuple

VALID_DONATION_TYPES = {"one-time", "monthly"}
MIN_AMOUNT_CENTS = 100        # $1.00
MAX_AMOUNT_CENTS = 1_000_000  # $10,000.00


def dollars_to_cents(amount_dollars: float) -> int:
    return round(float(amount_dollars) * 100)


def cents_to_dollars(amount_cents: int) -> float:
    return round(amount_cents / 100, 2)


def validate_donation_payload(body: dict) -> Tuple[Optional[dict], Optional[str]]:
    """Validate and normalise a donation payload.

    Returns (normalised_payload, error_message). One of the two will be None.
    """
    amount_raw = body.get("amount")
    if amount_raw is None:
        return None, "amount is required"

    try:
        amount_dollars = float(str(amount_raw).replace(",", ""))
    except (ValueError, TypeError):
        return None, "amount must be a valid number"

    amount_cents = dollars_to_cents(amount_dollars)
    if amount_cents < MIN_AMOUNT_CENTS:
        return None, "Minimum donation is $1.00"
    if amount_cents > MAX_AMOUNT_CENTS:
        return None, "Maximum donation is $10,000.00"

    donation_type = body.get("donation_type", "one-time")
    if donation_type not in VALID_DONATION_TYPES:
        return None, f"donation_type must be one of: {', '.join(VALID_DONATION_TYPES)}"

    email = (body.get("email") or "").strip()
    if not email:
        return None, "email is required"
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        return None, "Invalid email address"

    message = (body.get("message") or "").strip()
    if len(message) > 500:
        return None, "Message must be 500 characters or less"

    return {
        "amount_cents":   amount_cents,
        "amount_dollars": cents_to_dollars(amount_cents),
        "currency":       "usd",
        "donation_type":  donation_type,
        "email":          email,
        "message":        message,
        "anonymous":      bool(body.get("anonymous", False)),
    }, None


def build_donation_record(donation_id: str, user_id: Optional[str], validated: dict) -> dict:
    """Return a database-ready donation record dict."""
    return {
        "id":           donation_id,
        "user_id":      user_id,
        "amount":       validated["amount_cents"],
        "currency":     validated["currency"],
        "donation_type": validated["donation_type"],
        "donor_email":  validated["email"],
        "message":      validated["message"],
        "anonymous":    1 if validated["anonymous"] else 0,
        "status":       "pending",
    }


def format_donation_for_display(row) -> dict:
    """Convert a DB row into a public-facing donation summary."""
    anonymous = bool(getattr(row, "anonymous", 0))
    donor_name = getattr(row, "donor_name", None) or "Community Member"
    return {
        "id":            getattr(row, "id", ""),
        "donor_name":    "Anonymous" if anonymous else donor_name,
        "message":       getattr(row, "message", "") or "",
        "amount":        cents_to_dollars(getattr(row, "amount", 0)),
        "donation_type": getattr(row, "donation_type", "one-time"),
        "created_at":    getattr(row, "created_at", ""),
    }
