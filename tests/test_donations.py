"""
Tests for the donation helpers in worker.py: payload validation, Stripe
field encoding, and webhook signature verification.
"""

import hashlib
import hmac
import time

from tests.helpers import load_worker

worker = load_worker()


# ---------------------------------------------------------------------------
# _validate_donation_payload
# ---------------------------------------------------------------------------

class TestValidateDonationPayload:
    def _valid_body(self, **overrides):
        body = {"amount": "25", "email": "donor@example.com"}
        body.update(overrides)
        return body

    def test_valid_one_time_payload(self):
        validated, error = worker._validate_donation_payload(self._valid_body())
        assert error is None
        assert validated["amount_cents"] == 2500
        assert validated["donation_type"] == "one-time"
        assert validated["anonymous"] is False

    def test_missing_amount(self):
        body = self._valid_body()
        del body["amount"]
        _, error = worker._validate_donation_payload(body)
        assert error == "amount is required"

    def test_non_numeric_amount(self):
        _, error = worker._validate_donation_payload(self._valid_body(amount="not-a-number"))
        assert "valid number" in error

    def test_amount_below_minimum(self):
        _, error = worker._validate_donation_payload(self._valid_body(amount="0.50"))
        assert "Minimum donation" in error

    def test_amount_above_maximum(self):
        _, error = worker._validate_donation_payload(self._valid_body(amount="20000"))
        assert "Maximum donation" in error

    def test_invalid_donation_type(self):
        _, error = worker._validate_donation_payload(self._valid_body(donation_type="yearly"))
        assert "donation_type must be one of" in error

    def test_donation_type_wrong_shape_rejected(self):
        _, error = worker._validate_donation_payload(self._valid_body(donation_type=["monthly"]))
        assert "donation_type must be one of" in error

    def test_missing_email(self):
        body = self._valid_body()
        del body["email"]
        _, error = worker._validate_donation_payload(body)
        assert error == "email is required"

    def test_invalid_email_format(self):
        _, error = worker._validate_donation_payload(self._valid_body(email="not-an-email"))
        assert error == "Invalid email address"

    def test_email_wrong_shape_rejected(self):
        _, error = worker._validate_donation_payload(self._valid_body(email={"nested": "dict"}))
        assert error == "email must be a string"

    def test_message_wrong_shape_rejected(self):
        _, error = worker._validate_donation_payload(self._valid_body(message=["hi"]))
        assert error == "message must be a string"

    def test_message_too_long(self):
        _, error = worker._validate_donation_payload(self._valid_body(message="x" * 501))
        assert "500 characters" in error

    def test_name_too_long(self):
        _, error = worker._validate_donation_payload(self._valid_body(name="x" * 121))
        assert "120 characters" in error

    def test_anonymous_non_boolean_rejected(self):
        _, error = worker._validate_donation_payload(self._valid_body(anonymous="true"))
        assert error == "anonymous must be a boolean"

    def test_anonymous_true_accepted(self):
        validated, error = worker._validate_donation_payload(self._valid_body(anonymous=True))
        assert error is None
        assert validated["anonymous"] is True

    def test_name_and_message_trimmed(self):
        validated, error = worker._validate_donation_payload(
            self._valid_body(name="  Alice  ", message="  thanks!  ")
        )
        assert error is None
        assert validated["name"] == "Alice"
        assert validated["message"] == "thanks!"


# ---------------------------------------------------------------------------
# _stripe_encode
# ---------------------------------------------------------------------------

class TestStripeEncode:
    def test_flat_scalar_fields(self):
        pairs = worker._stripe_encode({"amount": 500, "currency": "usd"})
        assert ("amount", "500") in pairs
        assert ("currency", "usd") in pairs

    def test_nested_dict_uses_bracket_notation(self):
        pairs = worker._stripe_encode({"metadata": {"user_id": "abc"}})
        assert ("metadata[user_id]", "abc") in pairs

    def test_list_of_dicts_indexed(self):
        pairs = worker._stripe_encode({"items": [{"price": "price_1"}]})
        assert ("items[0][price]", "price_1") in pairs

    def test_booleans_encoded_as_lowercase_strings(self):
        pairs = worker._stripe_encode({"enabled": True, "disabled": False})
        assert ("enabled", "true") in pairs
        assert ("disabled", "false") in pairs

    def test_none_values_dropped(self):
        pairs = worker._stripe_encode({"optional": None})
        assert pairs == []

    def test_pre_bracketed_flat_key_passes_through(self):
        # Older call sites pass already-bracketed keys as flat strings.
        pairs = worker._stripe_encode({"line_items[0][price_data][currency]": "usd"})
        assert ("line_items[0][price_data][currency]", "usd") in pairs


# ---------------------------------------------------------------------------
# _verify_donation_webhook
# ---------------------------------------------------------------------------

class TestVerifyDonationWebhook:
    SECRET = "whsec_test_secret"

    def _sign(self, body: str, timestamp: int, secret: str = SECRET) -> str:
        signed = f"{timestamp}.{body}"
        sig = hmac.new(secret.encode(), signed.encode(), hashlib.sha256).hexdigest()
        return f"t={timestamp},v1={sig}"

    def test_valid_signature_within_tolerance(self):
        body = '{"type":"payment_intent.succeeded"}'
        header = self._sign(body, int(time.time()))
        assert worker._verify_donation_webhook(body, header, self.SECRET) is True

    def test_signature_too_old_rejected(self):
        body = '{"type":"payment_intent.succeeded"}'
        header = self._sign(body, int(time.time()) - 400)
        assert worker._verify_donation_webhook(body, header, self.SECRET) is False

    def test_signature_from_future_rejected(self):
        body = '{"type":"payment_intent.succeeded"}'
        header = self._sign(body, int(time.time()) + 400)
        assert worker._verify_donation_webhook(body, header, self.SECRET) is False

    def test_wrong_secret_rejected(self):
        body = '{"type":"payment_intent.succeeded"}'
        header = self._sign(body, int(time.time()), secret="wrong_secret")
        assert worker._verify_donation_webhook(body, header, self.SECRET) is False

    def test_malformed_header_rejected(self):
        body = '{"type":"payment_intent.succeeded"}'
        assert worker._verify_donation_webhook(body, "not-a-valid-header", self.SECRET) is False

    def test_empty_header_rejected(self):
        assert worker._verify_donation_webhook("{}", "", self.SECRET) is False

    def test_second_v1_value_matches_during_secret_rotation(self):
        body = '{"type":"payment_intent.succeeded"}'
        timestamp = int(time.time())
        signed = f"{timestamp}.{body}"
        good_sig = hmac.new(self.SECRET.encode(), signed.encode(), hashlib.sha256).hexdigest()
        header = f"t={timestamp},v1=deadbeef,v1={good_sig}"
        assert worker._verify_donation_webhook(body, header, self.SECRET) is True


# ---------------------------------------------------------------------------
# _mark_donation status-transition reporting
# ---------------------------------------------------------------------------

class TestInvoiceFieldExtraction:
    def test_subscription_id_legacy_shape(self):
        assert worker._invoice_subscription_id({"subscription": "sub_123"}) == "sub_123"

    def test_subscription_id_new_shape(self):
        invoice = {"parent": {"subscription_details": {"subscription": "sub_456"}}}
        assert worker._invoice_subscription_id(invoice) == "sub_456"

    def test_subscription_id_missing_returns_empty(self):
        assert worker._invoice_subscription_id({}) == ""

    def test_payment_intent_id_legacy_shape(self):
        assert worker._invoice_payment_intent_id({"payment_intent": "pi_123"}) == "pi_123"

    def test_payment_intent_id_new_shape(self):
        invoice = {"payments": [{"payment": {"payment_intent": "pi_789"}}]}
        assert worker._invoice_payment_intent_id(invoice) == "pi_789"

    def test_payment_intent_id_missing_returns_empty(self):
        assert worker._invoice_payment_intent_id({}) == ""
