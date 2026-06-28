"""
Donation API handlers with full Stripe integration.

Handles one-time payments (PaymentIntent) and monthly subscriptions
(Customer + Subscription → latest_invoice.payment_intent).

Environment variables required:
  STRIPE_SECRET_KEY      — sk_live_... or sk_test_...
  STRIPE_PUBLISHABLE_KEY — pk_live_... or pk_test_...
  STRIPE_WEBHOOK_SECRET  — whsec_...
  MAILGUN_API_KEY        — for thank-you emails
  MAILGUN_DOMAIN         — e.g. mg.alphaonelabs.com
  FROM_EMAIL             — e.g. no-reply@alphaonelabs.com
"""
import base64
import hashlib
import hmac as _hmac
import json
import os
import time
from typing import Optional
from urllib.parse import urlencode

import js  # type: ignore[import]
from pyodide.ffi import to_js  # type: ignore[import]
from workers import Response

from donations import (
    validate_donation_payload,
    build_donation_record,
    format_donation_for_display,
)

# Response helpers

_CORS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


def _json_resp(data, status: int = 200):
    return Response(
        json.dumps(data),
        status=status,
        headers={"Content-Type": "application/json", **_CORS},
    )


def _ok(data=None, msg: str = "OK"):
    body = {"success": True, "message": msg}
    if data is not None:
        body["data"] = data
    return _json_resp(body)


def _err(msg: str, status: int = 400):
    return _json_resp({"error": msg}, status)


async def _parse_json(req):
    try:
        text = await req.text()
        body = json.loads(text)
    except Exception:
        return None, _err("Invalid JSON body")
    if not isinstance(body, dict):
        return None, _err("JSON body must be an object")
    return body, None


def _verify_token(raw: str, secret: str) -> Optional[dict]:
    if not raw:
        return None
    try:
        token = raw.removeprefix("Bearer ").strip()
        dot = token.rfind(".")
        if dot == -1:
            return None
        p, sig = token[:dot], token[dot + 1:]
        exp = _hmac.new(secret.encode(), p.encode(), hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(sig, exp):
            return None
        padding = (4 - len(p) % 4) % 4
        return json.loads(base64.b64decode(p + "=" * padding).decode())
    except Exception:
        return None


def _new_id() -> str:
    b = bytearray(os.urandom(16))
    b[6] = (b[6] & 0x0F) | 0x40
    b[8] = (b[8] & 0x3F) | 0x80
    h = b.hex()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"

# Stripe HTTP client

def _stripe_encode(data: dict, prefix: str = "") -> list:
    """Recursively flatten a nested dict into Stripe bracket-notation pairs."""
    pairs = []
    for key, value in data.items():
        full_key = f"{prefix}[{key}]" if prefix else key
        if isinstance(value, dict):
            pairs.extend(_stripe_encode(value, full_key))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                item_key = f"{full_key}[{i}]"
                if isinstance(item, dict):
                    pairs.extend(_stripe_encode(item, item_key))
                elif item is not None:
                    pairs.append((item_key, str(item)))
        elif isinstance(value, bool):
            pairs.append((full_key, "true" if value else "false"))
        elif value is not None:
            pairs.append((full_key, str(value)))
    return pairs


async def _stripe(method: str, path: str, data: dict, key: str, *, idempotency_key: str = ""):
    """Make a Stripe REST API call. Returns (response_dict, error_str)."""
    url  = f"https://api.stripe.com/v1/{path.lstrip('/')}"
    body = urlencode(_stripe_encode(data)) if data else None

    headers: dict = {
        "Authorization": f"Bearer {key}",
        "Content-Type":  "application/x-www-form-urlencoded",
    }
    if idempotency_key and method.upper() in ("POST", "PUT", "PATCH"):
        headers["Idempotency-Key"] = idempotency_key

    fetch_opts = {"method": method.upper(), "headers": headers}
    if body and method.upper() != "GET":
        fetch_opts["body"] = body

    try:
        resp = await js.fetch(url, to_js(fetch_opts, dict_converter=js.Object.fromEntries))
        text = await resp.text()
        obj  = json.loads(text)
        if not resp.ok:
            msg = (obj.get("error") or {}).get("message") or "Stripe API error"
            print(f"[stripe] {method} {path} → {resp.status}: {msg}")
            return None, msg
        return obj, None
    except Exception as exc:
        print(f"[stripe] fetch error: {exc}")
        return None, str(exc)


# Webhook signature verification

_WEBHOOK_TOLERANCE_SECONDS = 300  # Stripe's recommended 5-minute replay window


def _verify_stripe_webhook(raw_body: str, sig_header: str, secret: str) -> bool:
    """Verify a Stripe-Signature header using HMAC-SHA256 with replay protection."""
    try:
        parts: dict = {}
        for chunk in sig_header.split(","):
            k, v = chunk.split("=", 1)
            parts.setdefault(k.strip(), []).append(v.strip())

        timestamp = parts.get("t", [None])[0]
        v1_sigs   = parts.get("v1", [])
        if not timestamp or not v1_sigs:
            return False

        # Reject replayed signatures older than the tolerance window
        try:
            if abs(time.time() - int(timestamp)) > _WEBHOOK_TOLERANCE_SECONDS:
                print("[webhook] Signature timestamp out of tolerance — possible replay")
                return False
        except (ValueError, TypeError):
            return False

        signed   = f"{timestamp}.{raw_body}"
        expected = _hmac.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()
        return any(_hmac.compare_digest(expected, s) for s in v1_sigs)
    except Exception:
        return False


# Email — lives here because it uses js.fetch (runtime-only)

async def _send_thank_you_email(env, info: dict) -> None:
    """Send a donation thank-you email via Mailgun."""
    try:
        to_email = (info.get("email") or "").strip()
        if not to_email:
            return

        mailgun_key    = getattr(env, "MAILGUN_API_KEY",  "") or ""
        mailgun_domain = getattr(env, "MAILGUN_DOMAIN",   "") or ""
        from_email     = getattr(env, "FROM_EMAIL", f"noreply@{mailgun_domain}") or ""

        if not mailgun_key or not mailgun_domain:
            print("[email] Mailgun not configured — skipping thank-you email")
            return

        amount_cents = int(info.get("amount", 0))
        amount_str   = f"${amount_cents / 100:.2f}"
        type_label   = "monthly" if info.get("type") == "monthly" else "one-time"

        html_body = f"""
<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:20px;color:#374151;">
  <div style="background:linear-gradient(135deg,#0d9488,#06b6d4);padding:32px;border-radius:12px;text-align:center;margin-bottom:24px;">
    <h1 style="color:white;margin:0;font-size:28px;">Thank You!</h1>
    <p style="color:rgba(255,255,255,.9);margin:8px 0 0;">Your generosity makes a real difference.</p>
  </div>
  <p style="font-size:16px;line-height:1.6;">
    We received your {type_label} donation of
    <strong style="color:#0d9488;">{amount_str}</strong>.
    Your support helps us provide quality education to students around the world.
  </p>
  <p style="font-size:15px;line-height:1.6;">With your donation we can:</p>
  <ul style="font-size:15px;line-height:2;">
    <li>Provide scholarships to students in need</li>
    <li>Develop new educational content and resources</li>
    <li>Improve our platform and technology</li>
    <li>Expand our reach to underserved communities</li>
  </ul>
  <p style="font-size:16px;line-height:1.6;">
    Thank you for being part of our mission to make quality education accessible to everyone.
  </p>
  <p style="font-size:13px;color:#6b7280;margin-top:32px;border-top:1px solid #e5e7eb;padding-top:16px;">
    Alpha One Labs &mdash;
    <a href="https://alphaonelabs.com" style="color:#0d9488;">alphaonelabs.com</a>
  </p>
</div>"""

        plain_body = (
            f"Thank you for your {type_label} donation of {amount_str} to Alpha One Labs!\n\n"
            "Your support helps us provide quality education to students around the world.\n\n"
            "Visit https://alphaonelabs.com to learn more."
        )

        credentials = base64.b64encode(f"api:{mailgun_key}".encode()).decode()
        form_data   = urlencode({
            "from":    from_email,
            "to":      to_email,
            "subject": "Thank You for Your Donation to Alpha One Labs!",
            "html":    html_body,
            "text":    plain_body,
        })

        opts = to_js({
            "method":  "POST",
            "headers": {
                "Authorization": f"Basic {credentials}",
                "Content-Type":  "application/x-www-form-urlencoded",
            },
            "body": form_data,
        }, dict_converter=js.Object.fromEntries)

        resp = await js.fetch(
            f"https://api.mailgun.net/v3/{mailgun_domain}/messages", opts
        )
        if resp.ok:
            print("[email] Thank-you email sent")
        else:
            print(f"[email] Mailgun error {resp.status}")
    except Exception as exc:
        print(f"[email] _send_thank_you_email error: {exc}")


# DB helper shared by webhook handlers

_ALLOWED_DONATION_FIELDS = frozenset({
    "stripe_payment_intent_id",
    "stripe_subscription_id",
    "stripe_customer_id",
})

# Status values ordered from "least final" to "most final".
# An update that would move the status backward is skipped unless
# allow_downgrade=True (used for explicit cancellation/failure events).
_STATUS_RANK = {"pending": 0, "completed": 1, "cancelled": 2, "failed": 2}


async def _mark_donation(env, field: str, value: str, status: str, *, allow_downgrade: bool = False):
    """Find a donation by a Stripe ID field and update its status.

    Raises ValueError for unknown field names (SQL-injection guard).
    Raises on DB errors so callers can propagate a 5xx to Stripe for retry.
    """
    if field not in _ALLOWED_DONATION_FIELDS:
        raise ValueError(f"_mark_donation: unknown field '{field}'")
    row = await env.DB.prepare(
        f"SELECT * FROM donations WHERE {field} = ? LIMIT 1"  # noqa: S608 — field is allowlisted above
    ).bind(value).first()
    if not row:
        return None
    current = getattr(row, "status", "pending") or "pending"
    if not allow_downgrade and _STATUS_RANK.get(current, 0) >= _STATUS_RANK.get(status, 0) and current != status:
        print(f"[donations] Skipping status regression {current!r} → {status!r} for {field}={value}")
        return row
    await env.DB.prepare(
        "UPDATE donations SET status = ? WHERE id = ?"
    ).bind(status, row.id).run()
    return row


# Public API handlers

async def get_donation_config(_, env):
    """GET /api/donations/config — return Stripe publishable key."""
    pub_key = getattr(env, "STRIPE_PUBLISHABLE_KEY", "") or ""
    return _ok({"publishable_key": pub_key})


async def get_donation_stats(request, env):
    """GET /api/donations/stats"""
    try:
        row = await env.DB.prepare(
            "SELECT COUNT(*) AS donor_count, SUM(amount) AS total_cents"
            " FROM donations WHERE status = 'completed'"
        ).first()
        total_cents = getattr(row, "total_cents", 0) or 0
        donor_count = int(getattr(row, "donor_count", 0) or 0)
        return _ok({"total_donated": round(total_cents / 100, 2), "donor_count": donor_count})
    except Exception as exc:
        print(f"[donations/stats] DB error: {exc}")
        return _ok({"total_donated": 0, "donor_count": 0})


async def get_recent_donations(request, env):
    """GET /api/donations/recent"""
    try:
        result = await env.DB.prepare(
            "SELECT id, donor_name, message, amount, donation_type, anonymous, created_at"
            " FROM donations WHERE status = 'completed'"
            " ORDER BY created_at DESC LIMIT 10"
        ).all()
        rows = result.results or []
        return _ok({"donations": [format_donation_for_display(r) for r in rows]})
    except Exception as exc:
        print(f"[donations/recent] DB error: {exc}")
        return _ok({"donations": []})


async def create_donation_intent(request, env):
    """POST /api/donations/one-time

    Creates a Stripe PaymentIntent and a pending donation record.
    Returns client_secret for the frontend to confirm with Stripe.js.
    """
    body, error_resp = await _parse_json(request)
    if error_resp:
        return error_resp

    body["donation_type"] = "one-time"
    validated, err_msg = validate_donation_payload(body)
    if err_msg:
        return _err(err_msg)

    stripe_key = getattr(env, "STRIPE_SECRET_KEY", "") or ""
    if not stripe_key:
        return _err("Payment processing is not configured", 503)

    user    = _verify_token(request.headers.get("Authorization") or "", env.JWT_SECRET)
    user_id = user["id"] if user else None

    donation_id = _new_id()  # generate first so it can serve as idempotency key

    intent, stripe_err = await _stripe("POST", "/payment_intents", {
        "amount":   validated["amount_cents"],
        "currency": "usd",
        "automatic_payment_methods": {"enabled": True, "allow_redirects": "always"},
        "receipt_email": validated["email"],
        "metadata": {
            "donation_type": "one-time",
            "user_id":       user_id or "",
            "message":       validated["message"][:100],
            "anonymous":     "true" if validated["anonymous"] else "false",
            "email":         validated["email"],
        },
    }, stripe_key, idempotency_key=f"pi-{donation_id}")

    if stripe_err:
        return _err(f"Payment setup failed: {stripe_err}", 502)
    record      = build_donation_record(donation_id, user_id, validated)

    try:
        await env.DB.prepare(
            "INSERT INTO donations"
            " (id, user_id, amount, currency, donation_type, donor_email, message,"
            "  anonymous, status, stripe_payment_intent_id)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)"
        ).bind(
            record["id"], record["user_id"], record["amount"], record["currency"],
            record["donation_type"], record["donor_email"], record["message"],
            record["anonymous"], intent["id"],
        ).run()
    except Exception as exc:
        print(f"[donations/one-time] DB insert error: {exc}")
        return _err("Failed to record donation", 500)

    return _ok({
        "donation_id":   donation_id,
        "client_secret": intent["client_secret"],
        "amount":        validated["amount_dollars"],
        "currency":      "usd",
    }, "PaymentIntent created")


async def create_subscription_intent(request, env):
    """POST /api/donations/monthly

    Creates a Stripe Customer, a dynamic Price, and a Subscription with
    payment_behavior=default_incomplete so that the first payment is handled
    via the Subscription's latest_invoice PaymentIntent client_secret.

    Subsequent monthly charges are handled automatically by Stripe and
    recorded via the invoice.payment_succeeded webhook.
    """
    body, error_resp = await _parse_json(request)
    if error_resp:
        return error_resp

    body["donation_type"] = "monthly"
    validated, err_msg = validate_donation_payload(body)
    if err_msg:
        return _err(err_msg)

    stripe_key = getattr(env, "STRIPE_SECRET_KEY", "") or ""
    if not stripe_key:
        return _err("Payment processing is not configured", 503)

    user    = _verify_token(request.headers.get("Authorization") or "", env.JWT_SECRET)
    user_id = user["id"] if user else None

    donation_id = _new_id()  # generate first so it anchors all idempotency keys

    # 1. Create or retrieve Stripe Customer
    customer, stripe_err = await _stripe("POST", "/customers", {
        "email":    validated["email"],
        "metadata": {"user_id": user_id or ""},
    }, stripe_key, idempotency_key=f"cus-{donation_id}")
    if stripe_err:
        return _err(f"Payment setup failed: {stripe_err}", 502)

    # 2. Create a dynamic per-amount Price (recurring monthly)
    price, stripe_err = await _stripe("POST", "/prices", {
        "currency":     "usd",
        "unit_amount":  validated["amount_cents"],
        "recurring":    {"interval": "month"},
        "product_data": {"name": "Alpha One Labs Monthly Donation"},
    }, stripe_key, idempotency_key=f"prc-{donation_id}")
    if stripe_err:
        return _err(f"Payment setup failed: {stripe_err}", 502)

    # 3. Create Subscription — default_incomplete means the first invoice
    #    is left unpaid and a PaymentIntent is created for us to confirm.
    subscription, stripe_err = await _stripe("POST", "/subscriptions", {
        "customer":         customer["id"],
        "items":            [{"price": price["id"]}],
        "payment_behavior": "default_incomplete",
        "payment_settings": {"save_default_payment_method": "on_subscription"},
        "expand":           ["latest_invoice.payment_intent"],
        "metadata": {
            "donation_type": "monthly",
            "user_id":       user_id or "",
            "message":       validated["message"][:100],
            "anonymous":     "true" if validated["anonymous"] else "false",
            "email":         validated["email"],
        },
    }, stripe_key, idempotency_key=f"sub-{donation_id}")
    if stripe_err:
        return _err(f"Subscription setup failed: {stripe_err}", 502)

    try:
        payment_intent    = subscription["latest_invoice"]["payment_intent"]
        client_secret     = payment_intent["client_secret"]
        payment_intent_id = payment_intent["id"]
    except (KeyError, TypeError):
        return _err("Failed to retrieve payment details from subscription", 502)

    record = build_donation_record(donation_id, user_id, validated)

    try:
        await env.DB.prepare(
            "INSERT INTO donations"
            " (id, user_id, amount, currency, donation_type, donor_email, message,"
            "  anonymous, status, stripe_payment_intent_id, stripe_subscription_id, stripe_customer_id)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)"
        ).bind(
            record["id"], record["user_id"], record["amount"], record["currency"],
            record["donation_type"], record["donor_email"], record["message"],
            record["anonymous"],
            payment_intent_id, subscription["id"], customer["id"],
        ).run()
    except Exception as exc:
        print(f"[donations/monthly] DB insert error: {exc}")
        return _err("Failed to record subscription", 500)

    return _ok({
        "donation_id":     donation_id,
        "client_secret":   client_secret,
        "subscription_id": subscription["id"],
        "amount":          validated["amount_dollars"],
        "currency":        "usd",
    }, "Subscription created")


async def handle_donation_webhook(request, env):
    """POST /api/donations/webhook — process Stripe webhook events."""
    webhook_secret = getattr(env, "STRIPE_WEBHOOK_SECRET", "") or ""
    if not webhook_secret:
        return _err("Webhook not configured", 503)

    raw_body   = await request.text()
    sig_header = request.headers.get("Stripe-Signature") or ""

    if not _verify_stripe_webhook(raw_body, sig_header, webhook_secret):
        print("[webhook] Invalid Stripe signature")
        return _err("Invalid signature", 400)

    try:
        event = json.loads(raw_body)
    except Exception:
        return _err("Invalid JSON", 400)

    event_type = event.get("type", "")
    obj        = (event.get("data") or {}).get("object") or {}
    print(f"[webhook] {event_type}")

    handler_exc = None
    try:
        if   event_type == "payment_intent.succeeded":
            await _on_payment_succeeded(env, obj)
        elif event_type == "payment_intent.payment_failed":
            await _on_payment_failed(env, obj)
        elif event_type == "customer.subscription.created":
            await _on_subscription_created(env, obj)
        elif event_type == "customer.subscription.updated":
            await _on_subscription_updated(env, obj)
        elif event_type == "customer.subscription.deleted":
            await _on_subscription_cancelled(env, obj)
        elif event_type == "invoice.payment_succeeded":
            await _on_invoice_paid(env, obj)
        elif event_type == "invoice.payment_failed":
            await _on_invoice_failed(env, obj)
    except Exception as exc:
        print(f"[webhook] Error processing {event_type}: {exc}")
        handler_exc = exc

    # Return 500 for transient errors (DB failures, etc.) so Stripe retries.
    # Return 200 for unknown event types — no retry needed.
    if handler_exc is not None:
        return _json_resp({"error": "processing_failed"}, 500)
    return _json_resp({"received": True}, 200)


# Webhook event handlers (mirrors the old Django signal handlers)

async def _on_payment_succeeded(env, intent: dict) -> None:
    intent_id = intent.get("id", "")
    row = await _mark_donation(env, "stripe_payment_intent_id", intent_id, "completed")
    if row:
        print(f"[webhook] Donation {row.id} completed")
        await _send_thank_you_email(env, {
            "email":  getattr(row, "donor_email", "") or "",
            "amount": getattr(row, "amount", 0),
            "type":   getattr(row, "donation_type", "one-time"),
        })
    else:
        print(f"[webhook] No donation found for PaymentIntent {intent_id}")


async def _on_payment_failed(env, intent: dict) -> None:
    intent_id = intent.get("id", "")
    await _mark_donation(env, "stripe_payment_intent_id", intent_id, "failed", allow_downgrade=True)
    print(f"[webhook] PaymentIntent {intent_id} failed")


async def _on_subscription_created(env, sub: dict) -> None:
    sub_id = sub.get("id", "")
    # Only set to pending if not already completed (payment_intent.succeeded fires first
    # for the initial payment and owns setting completed).
    if sub.get("status") != "active":
        await _mark_donation(env, "stripe_subscription_id", sub_id, "pending")
    print(f"[webhook] Subscription {sub_id} created → {sub.get('status')}")


async def _on_subscription_updated(env, sub: dict) -> None:
    sub_id = sub.get("id", "")
    stripe_status = sub.get("status", "")
    # Only map downgrade states; "active" is not forced here because
    # payment_intent.succeeded already owns the completed transition.
    status_map = {"past_due": "pending", "canceled": "cancelled", "unpaid": "pending"}
    if stripe_status in status_map:
        await _mark_donation(env, "stripe_subscription_id", sub_id, status_map[stripe_status], allow_downgrade=True)
    print(f"[webhook] Subscription {sub_id} updated → {stripe_status}")


async def _on_subscription_cancelled(env, sub: dict) -> None:
    sub_id = sub.get("id", "")
    await _mark_donation(env, "stripe_subscription_id", sub_id, "cancelled", allow_downgrade=True)
    print(f"[webhook] Subscription {sub_id} cancelled")


async def _on_invoice_paid(env, invoice: dict) -> None:
    """Recurring monthly charge succeeded — insert a new completed donation row."""
    sub_id = invoice.get("subscription")
    if not sub_id:
        return

    try:
        # Find the original subscription donation to copy its details
        row = await env.DB.prepare(
            "SELECT * FROM donations WHERE stripe_subscription_id = ? LIMIT 1"
        ).bind(sub_id).first()
        if not row:
            print(f"[webhook] No donation found for subscription {sub_id}")
            return

        # Avoid duplicating the first payment already handled by payment_intent.succeeded
        invoice_pi = invoice.get("payment_intent") or ""
        if invoice_pi:
            existing = await env.DB.prepare(
                "SELECT id FROM donations WHERE stripe_payment_intent_id = ? LIMIT 1"
            ).bind(invoice_pi).first()
            if existing:
                return

        new_id = _new_id()
        await env.DB.prepare(
            "INSERT INTO donations"
            " (id, user_id, amount, currency, donation_type, donor_email, message,"
            "  anonymous, status, stripe_subscription_id, stripe_customer_id, stripe_payment_intent_id)"
            " VALUES (?, ?, ?, ?, 'monthly', ?, ?, ?, 'completed', ?, ?, ?)"
        ).bind(
            new_id,
            getattr(row, "user_id", None),
            getattr(row, "amount", 0),
            getattr(row, "currency", "usd"),
            getattr(row, "donor_email", ""),
            getattr(row, "message", ""),
            getattr(row, "anonymous", 0),
            sub_id,
            getattr(row, "stripe_customer_id", None),
            invoice_pi or None,
        ).run()

        print(f"[webhook] Recurring donation {new_id} recorded for subscription {sub_id}")
        await _send_thank_you_email(env, {
            "email":  getattr(row, "donor_email", "") or "",
            "amount": getattr(row, "amount", 0),
            "type":   "monthly",
        })
    except Exception as exc:
        print(f"[webhook] _on_invoice_paid error: {exc}")


async def _on_invoice_failed(_, invoice: dict) -> None:
    sub_id = invoice.get("subscription")
    if sub_id:
        print(f"[webhook] Invoice payment failed for subscription {sub_id}")
