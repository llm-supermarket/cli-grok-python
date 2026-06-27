# cli-grok-python

A small CLI tool that encrypts and decrypts using the rclone encryption defaults.

Rclone uses a custom salt if no salt is provided, which this tool will use by default. A few similar tools:

- https://github.com/rclone/rclone
- https://github.com/mcolatosti/rclonedecrypt
- https://github.com/br0kenpixel/rclone-rcc
- @fyears/rclone-crypt

Rclone encryption uses:
- NaCl SecretBox (XSalsa20 + Poly1305) for the file contents.
- AES256 for the filenames.
- scrypt for keymaterial.

## Installation

Install from source using pip (recommended for this project):

```bash
python -m pip install -e .
```

After installation the command is available globally:

```bash
cli-grok-python --help
```

Uninstall:

```bash
python -m pip uninstall -y cli-grok-python
```

## Usage

Encrypt a file (will prompt for password and optional salt):

```bash
cli-grok-python encrypt -i plaintext.txt -o ciphertext.bin
```

Decrypt a file:

```bash
cli-grok-python decrypt -i ciphertext.bin -o recovered.txt
```

Use a custom filename encoding (base64 shown):

```bash
cli-grok-python encrypt -i in.txt -o out.bin --filename-encoding base64
```

Pass password via flag (insecure; tool prints a warning):

```bash
cli-grok-python encrypt -i in.txt -o out.bin --password 'MyPassw0rd!'
```

Provide salt and base32 explicitly:

```bash
cli-grok-python decrypt -i enc.bin -o plain.txt --salt 'mysalt' --filename-encoding base32
```

Write to stdout by omitting -o:

```bash
cli-grok-python decrypt -i enc.bin | cat
```

## Security notes

- Using `--password` on the command line is insecure. It may appear in process listings and shell history.
- Prefer letting the tool prompt (uses getpass) or supply via a short-lived environment variable you clear afterwards.
- After using `--password` in a shell, clear that history entry.

## Testing

```bash
python -m pip install -e '.[dev]' pytest
python -m pytest -q
```

## License

MIT
