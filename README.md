# rclone-encrypt-test-grok-python
A small CLI tool that encrypts and decrypts using the rclone encryption defaults. 

Rclone uses a custom salt if no salt is provided, which this tool will use by default. A few similar tools:

- https://github.com/rclone/rclone
- https://github.com/mcolatosti/rclonedecrypt
- https://github.com/br0kenpixel/rclone-rcc
- @fyears/rclone-crypt

Rclone encryption uses: 
- NaCl SecretBox (XSalsa20 + Poly1305) for the file contents.
- AES-256-EME for the filenames.
- scrypt (N=16384, r=8, p=1) for key derivation.

## Installation

The recommended one-line way to install a standalone Python CLI app:

```bash
pipx install git+https://github.com/llm-supermarket/rclone-encrypt-test-grok-python.git
```

(Requires `pipx`; or falling back use `pip install git+...` )

Uninstall:

```bash
pipx uninstall rclone-encrypt-test-grok-python
```

Call from anywhere:

```bash
rclone-encrypt-test-grok-python --help
```

## Usage

The CLI prompts for password and optional salt by default (recommended).

### Basic usage (auto detect)
```bash
# Encrypt
rclone-encrypt-test-grok-python -i TEST_FILE.txt
# decrypts reverse
rclone-encrypt-test-grok-python -i kr9tu4e1da4u3nifdd99g9tf5o -o TEST_FILE.txt
```

### Using --password (not recommended)
WARNING: use of --password logs in history and process, use env or prompt.

```bash
rclone-encrypt-test-grok-python --password "Testpassword1" -i TEST_FILE.txt
```

### Recommended: env var
```bash
export RCLONE_ENCRYPT_PASSWORD="Testpassword1"
rclone-encrypt-test-grok-python -i file.txt
```

### With custom salt
```bash
rclone-encrypt-test-grok-python --password "Testpassword1" --salt "mysalt" -i file.txt
```

### Output file
```bash
rclone-encrypt-test-grok-python -i plain.txt -o enc.bin
```

### Filename encoding
```bash
rclone-encrypt-test-grok-python --filename-encoding base64 -i file.txt
```

## Flags
| Flag                  | Default | Description |
|-----------------------|---------|-------------|
| --password            | prompt | Insecure password. Prefer RCLONE_ENCRYPT_PASSWORD or prompt. |
| --salt                | default | Optional scrypt salt. |
| --filename-encoding   | base32  | base32 or base64 |
| -i, --input-file      |         | Input (required) |
| -o, --output-file     | auto    | Output filename |

## Building / dev
```bash
pip install -e ".[dev]"   # if dev deps added
pytest
```

## License
MIT (inferred)
