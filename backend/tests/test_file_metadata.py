"""Magic-byte sniffing, hashing, entropy, extension-mismatch detection —
the deterministic first stage of the file pipeline (brief §7)."""

from __future__ import annotations

import hashlib
import os

from app.detectors.file import magic_bytes
from app.detectors.file.hashing import sha256_hex, shannon_entropy
from app.detectors.file.metadata import analyze_file

EICAR = (
    "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
).encode("ascii")


def test_sha256_matches_stdlib():
    data = b"sentivra-test-payload"
    assert sha256_hex(data) == hashlib.sha256(data).hexdigest()


def test_entropy_of_empty_is_zero():
    assert shannon_entropy(b"") == 0.0


def test_entropy_of_repeated_byte_is_zero():
    assert shannon_entropy(b"A" * 1000) == 0.0


def test_entropy_of_random_bytes_is_high():
    random_data = os.urandom(4096)
    assert shannon_entropy(random_data) > 7.0


def test_pe_magic_detected():
    fake_pe = b"MZ" + b"\x00" * 100
    assert "pe" in magic_bytes.sniff(fake_pe)


def test_pdf_magic_detected():
    fake_pdf = b"%PDF-1.4\n%..."
    assert "pdf" in magic_bytes.sniff(fake_pdf)


def test_extension_mismatch_flagged_when_exe_named_as_jpg():
    fake_pe = b"MZ" + b"\x00" * 200
    meta = analyze_file("invoice.jpg", fake_pe)
    assert meta.extension_mismatch is True
    assert "pe" in meta.matched_magic_types


def test_extension_matches_when_pdf_named_correctly():
    fake_pdf = b"%PDF-1.4\n" + b"x" * 200
    meta = analyze_file("report.pdf", fake_pdf)
    assert meta.extension_mismatch is False


def test_eicar_string_is_present_but_not_flagged_by_metadata_stage_alone():
    # Metadata stage is structural only — EICAR detection is YaraDetector's
    # job (tested separately). This test just confirms hashing/entropy run
    # cleanly against a real-world-shaped small text payload.
    meta = analyze_file("eicar.com", EICAR)
    assert meta.sha256 == hashlib.sha256(EICAR).hexdigest()
    assert meta.size_bytes == len(EICAR)
