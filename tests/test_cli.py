"""Tests for rclone-encrypt-test-grok-python cipher and CLI."""
from __future__ import annotations

import io
import os
import tempfile
from pathlib import Path

import pytest

from rclone_encrypt_test_grok_python.cipher import Cipher
from rclone_encrypt_test_grok_python import cli


def roundtrip(password: str, salt: str | None, encoding: str, data: bytes) -> bool:
    c = Cipher(password, salt, filename_encoding=encoding)
    fin = io.BytesIO(data)
    fout = io.BytesIO()
    c.encrypt_file(fin, fout)
    ct = fout.getvalue()
    fin2 = io.BytesIO(ct)
    fout2 = io.BytesIO()
    c.decrypt_file(fin2, fout2)
    return fout2.getvalue() == data and c.decrypt_name(c.encrypt_name("TEST_FILE.txt")) == "TEST_FILE.txt"


def test_roundtrip_no_salt_base32():
    assert roundtrip("Testpassword1", None, "base32", b"secret data 1234567890")


def test_roundtrip_with_salt_base32():
    assert roundtrip("Testpassword1", "mysalt123", "base32", b"another payload")


def test_roundtrip_base64():
    assert roundtrip("Testpassword1", None, "base64", b"payload for base64")


def test_roundtrip_with_password_via_cipher():
    # direct construction with password (simulates --password)
    assert roundtrip("p4ssW0rd!WithSpecial", "somesalt", "base32", os.urandom(12345))


def test_cli_encrypt_decrypt_via_functions(tmp_path: Path):
    # Use the functions behind the CLI
    pt = b"BIP39 TEST alpha beta gamma delta epsilon zeta eta theta iota kappa"
    src = tmp_path / "in.bin"
    src.write_bytes(pt)
    enc = tmp_path / "enc.bin"
    dec = tmp_path / "dec.bin"

    # simulate args
    class A: pass
    a = A()
    a.input_file = str(src)
    a.output_file = str(enc)
    a.password = "Testpassword1"
    a.salt = None
    a.filename_encoding = "base32"

    rc = cli.do_encrypt(a)
    assert rc == 0
    assert enc.exists() and enc.stat().st_size > 0

    a2 = A()
    a2.input_file = str(enc)
    a2.output_file = str(dec)
    a2.password = "Testpassword1"
    a2.salt = None
    a2.filename_encoding = "base32"
    rc2 = cli.do_decrypt(a2)
    assert rc2 == 0
    assert dec.read_bytes() == pt


def test_cli_base64_encoding(tmp_path: Path):
    pt = b"base64 test content " + os.urandom(100)
    src = tmp_path / "i.bin"
    src.write_bytes(pt)
    enc = tmp_path / "e.bin"
    dec = tmp_path / "d.bin"

    class A: pass
    a = A()
    a.input_file = str(src); a.output_file = str(enc); a.password = "pw"; a.salt = "salt"; a.filename_encoding = "base64"
    assert cli.do_encrypt(a) == 0

    a2 = A()
    a2.input_file = str(enc); a2.output_file = str(dec); a2.password = "pw"; a2.salt = "salt"; a2.filename_encoding = "base64"
    assert cli.do_decrypt(a2) == 0
    assert dec.read_bytes() == pt


def test_name_encoding_switch():
    c32 = Cipher("pw", None, filename_encoding="base32")
    c64 = Cipher("pw", None, filename_encoding="base64")
    name = "dir/sub/TEST_FILE.txt"
    e32 = c32.encrypt_name(name)
    e64 = c64.encrypt_name(name)
    assert e32 != e64  # different encodings
    assert c32.decrypt_name(e32) == name
    assert c64.decrypt_name(e64) == name


def test_password_warning_is_printed(capsys):
    # ensure the warning function writes to stderr
    cli._warn_password_flag()
    captured = capsys.readouterr()
    assert "WARNING" in captured.err
    assert "--password" in captured.err or "insecure" in captured.err.lower()


def test_prompt_path_monkeypatched(monkeypatch, tmp_path: Path):
    # Test that when password is not given via flag, the CLI prompts (we stub getpass)
    calls = {"pw": 0, "salt": 0}
    def fake_getpass(prompt=""):
        if "Salt" in prompt:
            calls["salt"] += 1
            return ""
        calls["pw"] += 1
        if calls["pw"] == 1:
            return "Testpassword1"
        return "Testpassword1"
    monkeypatch.setattr(cli, "getpass", __import__("getpass"))
    monkeypatch.setattr("getpass.getpass", fake_getpass)

    pt = b"prompted input data"
    src = tmp_path / "p.bin"; src.write_bytes(pt)
    enc = tmp_path / "pe.bin"; dec = tmp_path / "pd.bin"

    class A: pass
    a = A()
    a.input_file = str(src)
    a.output_file = str(enc)
    a.password = None
    a.salt = None
    a.filename_encoding = "base32"

    rc = cli.do_encrypt(a)
    assert rc == 0

    a2 = A()
    a2.input_file = str(enc)
    a2.output_file = str(dec)
    a2.password = None
    a2.salt = None
    a2.filename_encoding = "base32"
    rc2 = cli.do_decrypt(a2)
    assert rc2 == 0
    assert dec.read_bytes() == pt
