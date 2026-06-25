"""Core rclone crypt implementation ported/adapted from rclone Go code."""
import base64
import hashlib
import os
from nacl.bindings import crypto_secretbox_easy, crypto_secretbox_open_easy
from nacl.exceptions import CryptoError
from .eme import eme_transform

# Constants from rclone
NAME_CIPHER_BLOCK_SIZE = 16
FILE_MAGIC = b"RCLONE\x00\x00"
FILE_MAGIC_SIZE = len(FILE_MAGIC)
FILE_NONCE_SIZE = 24
FILE_HEADER_SIZE = FILE_MAGIC_SIZE + FILE_NONCE_SIZE
BLOCK_HEADER_SIZE = 16  # nacl secret mac inner
BLOCK_DATA_SIZE = 64 * 1024
BLOCK_SIZE = BLOCK_HEADER_SIZE + BLOCK_DATA_SIZE

DEFAULT_SALT = bytes([
    0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08,
    0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1
])

# Errors
class RcloneCryptError(Exception):
    pass

class ErrorNotAMultipleOfBlocksize(RcloneCryptError):
    pass

class ErrorEncryptedBadMagic(RcloneCryptError):
    pass

class ErrorEncryptedBadBlock(RcloneCryptError):
    pass

class ErrorEncryptedFileTooShort(RcloneCryptError):
    pass

class ErrorBadBase32Encoding(RcloneCryptError):
    pass


class CaseInsensitiveBase32Encoding:
    """Modified base32 hex, lower no pad, for rclone filenames."""

    @staticmethod
    def encode_to_string(src: bytes) -> str:
        # Use standard base32 hex (0-9 A-V), upper by py? then adjust
        encoded = base64.b32hexencode(src).decode("ascii").rstrip("=")
        return encoded.lower()

    @staticmethod
    def decode_string(s: str) -> bytes:
        if s.endswith("="):
            raise ErrorBadBase32Encoding
        # round up to mult of 8
        round_up = (len(s) + 7) & ~7
        equals = round_up - len(s)
        # upper and add pads
        s = s.upper() + "=" * equals
        try:
            return base64.b32hexdecode(s)
        except Exception as e:
            raise ErrorBadBase32Encoding from e


def get_filename_encoder(encoding: str):
    enc = encoding.lower()
    if enc == "base32":
        return CaseInsensitiveBase32Encoding()
    elif enc == "base64":
        return Base64RawURLEncoding()
    else:
        raise ValueError(f"unknown file name encoding mode {encoding}")

# Patch for base64 encoder to match interface
class Base64RawURLEncoding:
    @staticmethod
    def encode_to_string(src: bytes) -> str:
        return base64.urlsafe_b64encode(src).decode("ascii").rstrip("=")

    @staticmethod
    def decode_string(s: str) -> bytes:
        # may need padding
        pad = (-len(s)) % 4
        try:
            return base64.urlsafe_b64decode(s + "=" * pad)
        except Exception:
            # try with no mods first
            return base64.urlsafe_b64decode(s)


_FILENAME_ENCODERS = {
    "base32": CaseInsensitiveBase32Encoding(),
    "base64": Base64RawURLEncoding(),
}


def new_filename_encoder(name: str):
    name = name.lower()
    if name in _FILENAME_ENCODERS:
        return _FILENAME_ENCODERS[name]
    raise ValueError(f"unknown file name encoding mode {name}")


def pkcs7_pad(block_size: int, data: bytes) -> bytes:
    """PKCS#7 pad as rclone does."""
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(block_size: int, data: bytes) -> bytes:
    """PKCS#7 unpad."""
    if not data or len(data) % block_size != 0:
        raise RcloneCryptError("bad padding size")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size or data[-pad_len:] != bytes([pad_len] * pad_len):
        raise RcloneCryptError("bad padding")
    return data[:-pad_len]


# EME logic moved to .eme (imported) - see eme.py for eme_transform



class Cipher:
    """Rclone cipher for name and data."""

    def __init__(self, filename_encoding: str = "base32", dir_name_encrypt: bool = True):
        self.data_key = bytearray(32)
        self.name_key = bytearray(32)
        self.name_tweak = bytearray(16)
        self.filename_encoder = new_filename_encoder(filename_encoding)
        self.dir_name_encrypt = dir_name_encrypt
        self.encrypted_suffix = ".bin"

    def key(self, password: str, salt: str = "") -> None:
        salt_bytes = DEFAULT_SALT if not salt else salt.encode("utf-8")
        key_size = 32 + 32 + 16
        if password == "":
            key = b"\x00" * key_size
        else:
            # scrypt N=16384, r=8, p=1
            key = hashlib.scrypt(
                password.encode("utf-8"), salt=salt_bytes,
                n=16384, r=8, p=1, dklen=key_size
            )
        self.data_key[:] = key[:32]
        self.name_key[:] = key[32:64]
        self.name_tweak[:] = key[64:80]

    def _encrypt_segment(self, plaintext: str) -> str:
        if plaintext == "":
            return ""
        padded = pkcs7_pad(NAME_CIPHER_BLOCK_SIZE, plaintext.encode("utf-8"))
        ciphertext = eme_transform(bytes(self.name_key), bytes(self.name_tweak), padded, True)
        return self.filename_encoder.encode_to_string(ciphertext)

    def _decrypt_segment(self, ciphertext: str) -> str:
        if ciphertext == "":
            return ""
        raw = self.filename_encoder.decode_string(ciphertext)
        if len(raw) % NAME_CIPHER_BLOCK_SIZE != 0:
            raise ErrorNotAMultipleOfBlocksize
        if len(raw) == 0:
            raise RcloneCryptError("too short")
        padded = eme_transform(bytes(self.name_key), bytes(self.name_tweak), raw, False)
        plaintext = pkcs7_unpad(NAME_CIPHER_BLOCK_SIZE, padded)
        return plaintext.decode("utf-8")

    def encrypt_file_name(self, filename: str) -> str:
        if "/" in filename or "\\" in filename:
            # support simple relative paths, encrypt each segment
            # but for CLI we mainly do basename for file, handle path segments
            segments = filename.replace("\\", "/").split("/")
            enc = []
            for i, seg in enumerate(segments):
                if not self.dir_name_encrypt and i != len(segments) - 1:
                    enc.append(seg)
                else:
                    enc.append(self._encrypt_segment(seg))
            return "/".join(enc)
        return self._encrypt_segment(filename)

    def decrypt_file_name(self, enc_filename: str) -> str:
        if "/" in enc_filename or "\\" in enc_filename:
            segments = enc_filename.replace("\\", "/").split("/")
            dec = []
            for i, seg in enumerate(segments):
                if not self.dir_name_encrypt and i != len(segments) - 1:
                    dec.append(seg)
                else:
                    dec.append(self._decrypt_segment(seg))
            return "/".join(dec)
        return self._decrypt_segment(enc_filename)

    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt whole data (for small files; used in tests)."""
        nonce = os.urandom(FILE_NONCE_SIZE)
        header = FILE_MAGIC + nonce
        out_chunks = [header]
        curr = bytearray(nonce)
        k = bytes(self.data_key)
        for i in range(0, len(data), BLOCK_DATA_SIZE):
            chunk = data[i:i + BLOCK_DATA_SIZE]
            enc_block = crypto_secretbox_easy(chunk, bytes(curr), k)
            out_chunks.append(enc_block)
            self._nonce_increment(curr)
        return b"".join(out_chunks)

    def _nonce_increment(self, n: bytearray) -> None:
        i = 0
        while i < len(n):
            n[i] = (n[i] + 1) & 0xff
            if n[i] != 0:
                return
            i += 1

    def _nonce_add(self, n: bytearray, x: int) -> None:
        """Exact rclone nonce add from Go for seek/dec compat."""
        carry = 0
        xx = x
        for i in range(8):
            digit = n[i]
            x_digit = xx & 0xff
            xx >>= 8
            carry += digit + x_digit
            n[i] = carry & 0xff
            carry >>= 8
        i_pos = 8
        while carry != 0 and i_pos < len(n):
            digit = n[i_pos]
            new_d = (digit + 1) & 0xff
            n[i_pos] = new_d
            carry = 0 if new_d >= digit else 1
            i_pos += 1

    def decrypt_data(self, enc_data: bytes) -> bytes:
        if len(enc_data) < FILE_HEADER_SIZE:
            raise ErrorEncryptedFileTooShort
        if enc_data[:FILE_MAGIC_SIZE] != FILE_MAGIC:
            raise ErrorEncryptedBadMagic
        curr_nonce = bytearray(enc_data[FILE_MAGIC_SIZE:FILE_HEADER_SIZE])
        plain = bytearray()
        pos = FILE_HEADER_SIZE
        first = True
        k = bytes(self.data_key)
        while pos < len(enc_data):
            if not first:
                self._nonce_increment(curr_nonce)
            first = False
            chunk_size = min(BLOCK_SIZE, len(enc_data) - pos)
            if chunk_size < BLOCK_HEADER_SIZE:
                raise ErrorEncryptedFileTooShort
            enc_block = enc_data[pos:pos + chunk_size]
            try:
                dec = crypto_secretbox_open_easy(enc_block, bytes(curr_nonce), k)
            except Exception as e:
                raise ErrorEncryptedBadBlock from e
            plain.extend(dec)
            pos += chunk_size
        return bytes(plain)
