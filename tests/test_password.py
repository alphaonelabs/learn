"""
Tests for password hashing: hash_password(), verify_password().
"""

import base64
from tests.helpers import load_worker

worker = load_worker()


class TestHashPassword:
    def test_returns_string(self):
        assert isinstance(worker.hash_password("password", "alice"), str)

    def test_returns_non_empty(self):
        assert worker.hash_password("password", "alice") != ""

    def test_output_is_base64(self):
        h = worker.hash_password("password", "alice")
        # Should not raise
        base64.b64decode(h)

    def test_deterministic(self):
        h1 = worker.hash_password("password123", "alice")
        h2 = worker.hash_password("password123", "alice")
        assert h1 == h2

    def test_different_passwords_differ(self):
        h1 = worker.hash_password("password1", "alice")
        h2 = worker.hash_password("password2", "alice")
        assert h1 != h2

    def test_same_password_different_users_differ(self):
        h1 = worker.hash_password("samepassword", "alice")
        h2 = worker.hash_password("samepassword", "bob")
        assert h1 != h2

    def test_empty_password_allowed(self):
        h = worker.hash_password("", "alice")
        assert isinstance(h, str) and h != ""

    def test_unicode_password(self):
        h = worker.hash_password("pässwörd!", "alice")
        assert isinstance(h, str)


class TestVerifyPassword:
    def test_correct_password_returns_true(self):
        stored = worker.hash_password("mypassword", "alice")
        assert worker.verify_password("mypassword", stored, "alice") is True

    def test_wrong_password_returns_false(self):
        stored = worker.hash_password("mypassword", "alice")
        assert worker.verify_password("wrongpassword", stored, "alice") is False

    def test_wrong_username_returns_false(self):
        stored = worker.hash_password("mypassword", "alice")
        # Same password, different username → different salt → different hash
        assert worker.verify_password("mypassword", stored, "bob") is False

    def test_empty_password_correct(self):
        stored = worker.hash_password("", "alice")
        assert worker.verify_password("", stored, "alice") is True

    def test_empty_password_incorrect(self):
        stored = worker.hash_password("", "alice")
        assert worker.verify_password("notempty", stored, "alice") is False

    def test_case_sensitive(self):
        stored = worker.hash_password("Password", "alice")
        assert worker.verify_password("password", stored, "alice") is False


class TestDynamicPepper:
    def teardown_method(self):
        worker.reset_pepper()

    def test_explicit_pepper_alters_hash(self):
        h_default = worker.hash_password("secret", "user1")
        h_pepper_a = worker.hash_password("secret", "user1", pepper=b"custom-pepper-A")
        h_pepper_b = worker.hash_password("secret", "user1", pepper=b"custom-pepper-B")

        assert h_pepper_a != h_pepper_b
        assert h_pepper_a != h_default
        assert h_pepper_b != h_default

    def test_verify_password_with_matching_and_mismatched_pepper(self):
        stored = worker.hash_password("secret", "user1", pepper=b"test-pepper")
        assert worker.verify_password("secret", stored, "user1", pepper=b"test-pepper") is True
        assert worker.verify_password("secret", stored, "user1", pepper=b"wrong-pepper") is False
        assert worker.verify_password("secret", stored, "user1") is False

    def test_pepper_injection_from_env_binding(self):
        from tests.helpers import make_env
        env = make_env()
        env.PASSWORD_PEPPER = "env-injected-pepper-12345"
        h = worker.hash_password("secret", "user1", env=env)
        assert worker.verify_password("secret", h, "user1", env=env) is True
        assert worker.verify_password("secret", h, "user1") is False

    def test_pepper_alias_support(self):
        from tests.helpers import make_env
        env = make_env()
        env.PASSWORD_PEPPER = None
        env.PEPPER = "legacy-alias-pepper"
        h = worker.hash_password("secret", "user1", env=env)
        assert worker.verify_password("secret", h, "user1", env=env) is True

    def test_pepper_injection_from_os_environ(self, monkeypatch):
        monkeypatch.setenv("PASSWORD_PEPPER", "os-env-pepper-999")
        h = worker.hash_password("secret", "user1")
        assert worker.verify_password("secret", h, "user1") is True

    def test_production_fails_closed_when_pepper_missing(self):
        import pytest
        from tests.helpers import make_env
        env = make_env()
        env.ENVIRONMENT = "production"
        env.PASSWORD_PEPPER = None
        env.PEPPER = None

        with pytest.raises(RuntimeError, match="Missing required environment secret: PASSWORD_PEPPER"):
            worker.get_pepper(env)

    def test_production_succeeds_when_pepper_is_present(self):
        from tests.helpers import make_env
        env = make_env()
        env.ENVIRONMENT = "production"
        env.PASSWORD_PEPPER = "production-secure-pepper-abc"
        assert worker.get_pepper(env) == b"production-secure-pepper-abc"

    def test_init_pepper_caches_active_pepper(self):
        from tests.helpers import make_env
        env = make_env()
        env.PASSWORD_PEPPER = "cached-active-pepper"
        worker.init_pepper(env)
        h = worker.hash_password("secret", "user1")
        assert worker.verify_password("secret", h, "user1") is True
