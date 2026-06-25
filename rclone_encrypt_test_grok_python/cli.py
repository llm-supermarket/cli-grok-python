"""CLI entrypoint for rclone-encrypt-test-grok-python."""
from __future__ import annotations

import argparse
import getpass
import sys
import warnings
from pathlib import Path
from typing import Optional

from .cipher import Cipher

def _warn_password_flag() -> None:
    msg = (
        "WARNING: Using --password on the command line is insecure.\n"
        "  - It may be visible in process listings.\n"
        "  - It is stored in your shell history.\n"
        "  - Consider using an environment variable or letting the tool prompt you.\n"
        "  - After use, clear your shell history entry for this command.\n"
    )
    print(msg, file=sys.stderr)

def _get_password(arg_password: Optional[str], prompt_label: str = "Password") -> str:
    if arg_password is not None:
        _warn_password_flag()
        return arg_password
    # prompt twice for confirmation on encrypt path, once on decrypt (rclone style: once is fine, but be user friendly)
    while True:
        p1 = getpass.getpass(f"{prompt_label}: ")
        if not p1:
            print("Password cannot be empty.", file=sys.stderr)
            continue
        p2 = getpass.getpass(f"Confirm {prompt_label}: ")
        if p1 != p2:
            print("Passwords do not match.", file=sys.stderr)
            continue
        return p1

def _get_salt(arg_salt: Optional[str]) -> Optional[str]:
    if arg_salt is not None:
        return arg_salt
    s = getpass.getpass("Salt (optional, press Enter to use rclone default): ")
    return s or None

def _resolve_output(in_path: str, out_path: Optional[str], decrypting: bool) -> Optional[Path]:
    if out_path:
        return Path(out_path)
    # If no output specified, we write to stdout (binary). Caller decides.
    return None

def do_encrypt(args: argparse.Namespace) -> int:
    c = Cipher(
        password=args.password or "",  # will be filled below if needed
        salt=args.salt,
        mode="standard",
        dir_name_encrypt=True,
        filename_encoding=args.filename_encoding or "base32",
    )
    pw = args.password
    if not pw:
        pw = _get_password(None, "Password")
        salt = _get_salt(args.salt)
        # recreate cipher with real pw
        c = Cipher(pw, salt, "standard", True, args.filename_encoding or "base32")
    else:
        _warn_password_flag()
        c = Cipher(pw, args.salt, "standard", True, args.filename_encoding or "base32")

    in_p = Path(args.input_file)
    if not in_p.exists():
        print(f"Input not found: {in_p}", file=sys.stderr)
        return 2
    out_p = Path(args.output_file) if args.output_file else None

    if out_p:
        with in_p.open("rb") as fin, out_p.open("wb") as fout:
            c.encrypt_file(fin, fout)
    else:
        import sys as _sys
        fout = getattr(_sys.stdout, "buffer", _sys.stdout)
        with in_p.open("rb") as fin:
            c.encrypt_file(fin, fout)  # type: ignore[arg-type]
    return 0

def do_decrypt(args: argparse.Namespace) -> int:
    pw = args.password
    if not pw:
        pw = getpass.getpass("Password: ")
    else:
        _warn_password_flag()
    c = Cipher(pw, args.salt, "standard", True, args.filename_encoding or "base32")

    in_p = Path(args.input_file)
    if not in_p.exists():
        print(f"Input not found: {in_p}", file=sys.stderr)
        return 2
    out_p = Path(args.output_file) if args.output_file else None

    if out_p:
        with in_p.open("rb") as fin, out_p.open("wb") as fout:
            c.decrypt_file(fin, fout)
    else:
        import sys as _sys
        fout = getattr(_sys.stdout, "buffer", _sys.stdout)
        with in_p.open("rb") as fin:
            c.decrypt_file(fin, fout)  # type: ignore[arg-type]
    return 0

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rclone-encrypt-test-grok-python",
        description="Encrypt/decrypt files using rclone crypt defaults (NaCl SecretBox + EME-AES + scrypt).",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # shared options
    def add_common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("-i", "--input-file", required=True, help="Input file path")
        sp.add_argument("-o", "--output-file", required=False, default=None, help="Output file path (optional; writes to stdout if omitted)")
        sp.add_argument("--password", required=False, default=None, help="Password (insecure on CLI; prefer prompt or env). Prints security warning.")
        sp.add_argument("--salt", required=False, default=None, help="Optional salt (if omitted, rclone built-in default is used)")
        sp.add_argument("--filename-encoding", required=False, default="base32",
                        choices=["base32", "base64", "base32768"],
                        help="Filename encoding (default: base32 as used by rclone)")

    sp_enc = sub.add_parser("encrypt", help="Encrypt a file")
    add_common(sp_enc)
    sp_enc.set_defaults(func=do_encrypt)

    sp_dec = sub.add_parser("decrypt", help="Decrypt a file")
    add_common(sp_dec)
    sp_dec.set_defaults(func=do_decrypt)

    return p

def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)  # type: ignore
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
