from __future__ import annotations

from graylog_unifi_gim.sanitizer import sanitize_message


def test_sanitizer_is_deterministic_and_preserves_correlations() -> None:
    raw = "DEVICE aabbccddeeff client aa:bb:cc:dd:ee:ff at 10.20.30.40"
    first = sanitize_message(raw)
    assert first == sanitize_message(raw)
    assert "aabbccddeeff" not in first
    assert "aa:bb:cc:dd:ee:ff" not in first
    assert "10.20.30.40" not in first
    assert "192.0." in first


def test_sanitizer_does_not_change_message_shape() -> None:
    raw = "HOST aabbccddeeff,U6-LR-6.7.54+15663: kernel: Port 1 link down"
    sanitized = sanitize_message(raw)
    assert sanitized.endswith(",U6-LR-6.7.54+15663: kernel: Port 1 link down")

