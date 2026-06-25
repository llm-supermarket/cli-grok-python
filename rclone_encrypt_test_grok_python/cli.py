"""CLI for rclone compatible encrypt/decrypt."""
import argparse
import getpass
import os
import sys
import warnings

from .cipher import Cipher


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    p = argparse.ArgumentParser(
        prog="rclone-encrypt-test-grok-python",
        description="Encrypt/decrypt files using rclone crypt defaults."
    )
    p.add_argument("-i", "--input-file", required=True, help="Input file path")
    p.add_argument("-o", "--output-file", default=None, help="Output file (optional)")
    p.add_argument("--password", default=None, help="Password (insecure; prefer prompt or RCLONE_ENCRYPT_PASSWORD env)")
    p.add_argument("--salt", default="", help="Optional salt (default uses rclone built-in)")
    p.add_argument("--filename-encoding", default="base32", choices=["base32", "base64"], help="Filename encoding (default: base32)")
    p.add_argument("--encrypt", action="store_true", help="Force encrypt even if looks encrypted")
    p.add_argument("--decrypt", action="store_true", help="Force decrypt")

    args = p.parse_args(argv)

    infile = args.input_file
    if not os.path.exists(infile):
        print(f"Error: input not found: {infile}", file=sys.stderr)
        return 2

    pw = args.password
    if pw is None:
        env = os.environ.get("RCLONE_ENCRYPT_PASSWORD")
        if env:
            pw = env
        else:
            pw = getpass.getpass("Password: ")
            if not args.salt:
                s2 = getpass.getpass("Salt (optional, enter to use default): ")
                if s2:
                    args.salt = s2

    if args.password:
        print("WARNING: --password exposes secret in process list and shell history. Use env var RCLONE_ENCRYPT_PASSWORD or prompt instead, and clear history.", file=sys.stderr)

    try:
        c = Cipher(filename_encoding=args.filename_encoding)
        c.key(pw, args.salt or "")
    except Exception as e:
        print(f"Key error: {e}", file=sys.stderr)
        return 3

    with open(infile, "rb") as f:
        content = f.read()

    is_enc = content.startswith(b"RCLONE\x00\x00")
    do_dec = args.decrypt or (is_enc and not args.encrypt)

    if do_dec:
        try:
            out = c.decrypt_data(content)
        except Exception as e:
            print(f"Decrypt failed (bad pw/salt/encoding?): {e}", file=sys.stderr)
            return 4
        plain_name = args.output_file
        if not plain_name:
            name = os.path.basename(infile)
            # try decode if name looks encrypted, else suffix remove .bin
            try:
                plain_name = c.decrypt_file_name(name)
            except Exception:
                plain_name = name[:-4] if name.endswith(".bin") else name + ".dec"
            plain_name = os.path.join(os.path.dirname(infile) or ".", plain_name)
        outp = plain_name
    else:
        try:
            out = c.encrypt_data(content)
        except Exception as e:
            print(f"Encrypt failed: {e}", file=sys.stderr)
            return 5
        if args.output_file:
            outp = args.output_file
        else:
            bname = os.path.basename(infile)
            try:
                encname = c.encrypt_file_name(bname)
            except Exception:
                encname = bname + ".bin"
            outp = os.path.join(os.path.dirname(infile) or ".", encname)

    with open(outp, "wb") as f:
        f.write(out)
    print(f"Wrote: {outp}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
