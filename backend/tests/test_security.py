"""Security-control unit tests: SSRF guard, archive-bomb protection,
webhook HMAC verification (brief §29, §15)."""

from __future__ import annotations

import io
import zipfile

import pytest

from app.security.ssrf_guard import SSRFBlocked, assert_safe_url
from app.security.uploads import ArchiveBombSuspected, inspect_zip_bomb_safe
from app.security.webhooks import verify_hmac_sha256


def test_ssrf_guard_blocks_loopback():
    with pytest.raises(SSRFBlocked):
        assert_safe_url("http://127.0.0.1/admin")


def test_ssrf_guard_blocks_link_local_metadata_address():
    with pytest.raises(SSRFBlocked):
        assert_safe_url("http://169.254.169.254/latest/meta-data/")


def test_ssrf_guard_blocks_non_http_scheme():
    with pytest.raises(SSRFBlocked):
        assert_safe_url("file:///etc/passwd")


def test_ssrf_guard_allows_public_hostname():
    # example.com is a stable, always-resolvable public domain reserved by
    # IANA for documentation/testing — safe to resolve in a unit test.
    assert_safe_url("https://example.com/path")


def _make_zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_normal_zip_passes_inspection():
    data = _make_zip({"readme.txt": b"hello world"})
    result = inspect_zip_bomb_safe(data)
    assert result.entry_count == 1
    assert result.total_uncompressed_bytes == len(b"hello world")


def test_declared_oversized_uncompressed_size_is_rejected():
    # Simulate a bomb by writing many entries whose *declared* sizes sum
    # past the configured cap, without needing to actually generate
    # gigabytes of data on disk for the test.
    import app.security.uploads as uploads_module

    original_cap = uploads_module.get_settings().max_archive_uncompressed_bytes
    uploads_module.get_settings().max_archive_uncompressed_bytes = 1000
    try:
        data = _make_zip({f"file{i}.txt": b"x" * 2000 for i in range(3)})
        with pytest.raises(ArchiveBombSuspected):
            inspect_zip_bomb_safe(data)
    finally:
        uploads_module.get_settings().max_archive_uncompressed_bytes = original_cap


def test_hmac_verification_accepts_correct_signature():
    import hmac
    from hashlib import sha256

    secret = "shh"
    body = b'{"hello":"world"}'
    sig = "sha256=" + hmac.new(secret.encode(), body, sha256).hexdigest()
    assert verify_hmac_sha256(secret=secret, payload=body, signature_header=sig) is True


def test_hmac_verification_rejects_tampered_body():
    import hmac
    from hashlib import sha256

    secret = "shh"
    sig = "sha256=" + hmac.new(secret.encode(), b"original", sha256).hexdigest()
    assert verify_hmac_sha256(secret=secret, payload=b"tampered", signature_header=sig) is False


def test_hmac_verification_rejects_missing_header():
    assert verify_hmac_sha256(secret="shh", payload=b"x", signature_header=None) is False
