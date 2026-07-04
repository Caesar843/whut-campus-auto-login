import pytest

from campus_login.core.result import mask_account, sanitize_url


@pytest.mark.parametrize(
    ("account", "expected"),
    [
        ("", ""),
        ("1", "*"),
        ("12", "**"),
        ("123", "***"),
        ("1234", "****"),
        ("12345", "1****5"),
        ("123456", "1****6"),
        ("12345678", "1****8"),
        ("123456789", "12****89"),
    ],
)
def test_mask_account_uses_conservative_short_account_rules(account, expected):
    assert mask_account(account) == expected


def test_mask_account_does_not_expose_short_accounts():
    assert "123" not in mask_account("123")
    assert "1234" not in mask_account("1234")


def test_sanitize_url_masks_short_username_occurrences():
    sanitized = sanitize_url(
        "https://auth.example/portal/123?username=123&redirect=1234",
        username="123",
    )

    assert sanitized == "https://auth.example/portal/***?username=redacted&redirect=***4"
    assert "123" not in sanitized
