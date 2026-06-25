"""Core rclone crypt implementation (compatible with rclone defaults).

- scrypt(N=16384,r=8,p=1) for key material
- EME-AES for filename encryption (standard mode)
- NaCl SecretBox (XSalsa20+Poly1305) for file contents, 64KiB chunks
- filename encodings: base32 (rclone default), base64, base32768
"""
from __future__ import annotations

import os
import base64
import hashlib
from typing import BinaryIO, Optional

from cryptography.hazmat.primitives.ciphers import Cipher as _CryptoCipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import nacl.bindings as _nacl_bindings

FILE_MAGIC = b"RCLONE\x00\x00"
FILE_MAGIC_SIZE = 8
FILE_NONCE_SIZE = 24
FILE_HEADER_SIZE = FILE_MAGIC_SIZE + FILE_NONCE_SIZE
BLOCK_DATA_SIZE = 64 * 1024
BLOCK_HEADER_SIZE = 16
DEFAULT_SALT = bytes([0xA8,0x0D,0xF4,0x3A,0x8F,0xBD,0x03,0x08,0xA7,0xCA,0xB8,0x3E,0x58,0x1F,0x86,0xB1])

class NameEncoding:
    def encode(self, b: bytes) -> str: ...
    def decode(self, s: str) -> bytes: ...

class Base32Enc(NameEncoding):
    def encode(self, b: bytes) -> str:
        if not b: return ""
        s = base64.b32hexencode(b).decode("ascii").rstrip("=")
        return s.lower()
    def decode(self, s: str) -> bytes:
        if s.endswith("="): raise ValueError("bad base32")
        pad = (-len(s)) % 8
        return base64.b32hexdecode(s.upper() + "="*pad)

class Base64Enc(NameEncoding):
    def encode(self, b: bytes) -> str:
        if not b: return ""
        return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")
    def decode(self, s: str) -> bytes:
        pad = (-len(s)) % 4
        return base64.urlsafe_b64decode(s + "="*pad)

try:
    import base32768 as b32k  # type: ignore
    class Base32768Enc(NameEncoding):
        def encode(self, b: bytes) -> str: return b32k.encode(b)
        def decode(self, s: str) -> bytes: return b32k.decode(s)
except Exception:
    class Base32768Enc(NameEncoding):  # type: ignore
        def encode(self, b: bytes) -> str: raise NotImplementedError("install base32768")
        def decode(self, s: str) -> bytes: raise NotImplementedError("install base32768")

def get_encoding(name: str) -> NameEncoding:
    n = (name or "base32").lower()
    if n in ("base32", ""): return Base32Enc()
    if n == "base64": return Base64Enc()
    if n == "base32768": return Base32768Enc()
    raise ValueError("unknown filename_encoding")

# EME
def _mult_by_two(out: bytearray, inp: bytes) -> None:
    tmp = bytearray(16)
    tmp[0] = (2 * inp[0]) & 0xFF
    if inp[15] >= 128: tmp[0] ^= 135
    for j in range(1, 16):
        tmp[j] = (2 * inp[j]) & 0xFF
        if inp[j-1] >= 128: tmp[j] = (tmp[j] + 1) & 0xFF
    out[:] = tmp

def _xor16(out: bytearray, a: bytes, b: bytes) -> None:
    for i in range(16): out[i] = a[i] ^ b[i]

class _AesBc:
    def __init__(self, key: bytes):
        self._c = _CryptoCipher(algorithms.AES(key), modes.ECB())
    def encrypt(self, b: bytes) -> bytes:
        e = self._c.encryptor(); return e.update(b) + e.finalize()
    def decrypt(self, b: bytes) -> bytes:
        d = self._c.decryptor(); return d.update(b) + d.finalize()

def eme_transform(bc: _AesBc, tweak: bytes, data: bytes, encrypt: bool) -> bytes:
    if len(tweak) != 16 or len(data) % 16 != 0 or len(data) == 0:
        raise ValueError("EME: bad tweak or data size")
    m = len(data) // 16
    if m > 128: raise ValueError("EME too many blocks")
    C = bytearray(data)
    eZero = bytes(16)
    Li = bytearray(bc.encrypt(eZero))
    Ls = []
    pool = bytearray(m * 16)
    for i in range(m):
        _mult_by_two(Li, Li)
        sl = pool[i*16:(i+1)*16]; sl[:] = Li; Ls.append(sl)
    PPj = bytearray(16)
    for j in range(m):
        Pj = data[j*16:(j+1)*16]
        _xor16(PPj, Pj, Ls[j])
        if encrypt:
            C[j*16:(j+1)*16][:] = bc.encrypt(PPj)
        else:
            C[j*16:(j+1)*16][:] = bc.decrypt(PPj)
    MP = bytearray(16); _xor16(MP, C[0:16], tweak)
    for j in range(1, m): _xor16(MP, MP, C[j*16:(j+1)*16])
    MC = bytearray(16)
    if encrypt: MC[:] = bc.encrypt(MP)
    else: MC[:] = bc.decrypt(MP)
    M = bytearray(16); _xor16(M, MP, MC)
    CCCj = bytearray(16)
    for j in range(1, m):
        _mult_by_two(M, M)
        _xor16(CCCj, C[j*16:(j+1)*16], M)
        C[j*16:(j+1)*16][:] = CCCj
    CCC1 = bytearray(16); _xor16(CCC1, MC, tweak)
    for j in range(1, m): _xor16(CCC1, CCC1, C[j*16:(j+1)*16])
    C[0:16][:] = CCC1
    for j in range(m):
        if encrypt:
            C[j*16:(j+1)*16][:] = bc.encrypt(C[j*16:(j+1)*16])
        else:
            C[j*16:(j+1)*16][:] = bc.decrypt(C[j*16:(j+1)*16])
        _xor16(C[j*16:(j+1)*16], C[j*16:(j+1)*16], Ls[j])
    return bytes(C)

class Cipher:
    def __init__(self, password: str, salt: Optional[str], mode: str = "standard",
                 dir_name_encrypt: bool = True, filename_encoding: str = "base32"):
        if mode not in ("standard", "off", "obfuscate"):
            raise ValueError("bad mode")
        self.mode = mode
        self.dir_name_encrypt = dir_name_encrypt
        self.enc = get_encoding(filename_encoding)
        self.suffix = ".bin"
        key_material = self._derive(password, salt)
        self.data_key = key_material[:32]
        self.name_key = key_material[32:64]
        self.name_tweak = key_material[64:80]
        self._bc = _AesBc(self.name_key)

    @staticmethod
    def _derive(password: str, salt: Optional[str]) -> bytes:
        salt_b = DEFAULT_SALT if not salt else salt.encode("utf-8")
        if not password: return bytes(80)
        return hashlib.scrypt(password.encode("utf-8"), salt=salt_b, n=16384, r=8, p=1, dklen=80)

    def set_suffix(self, s: Optional[str]) -> None:
        if not s or s.lower() == "none":
            self.suffix = ""
        else:
            self.suffix = s if s.startswith(".") else "." + s

    def _pad(self, b: bytes) -> bytes:
        p = padding.PKCS7(128).padder(); return p.update(b) + p.finalize()
    def _unpad(self, b: bytes) -> bytes:
        u = padding.PKCS7(128).unpadder(); return u.update(b) + u.finalize()

    def _enc_seg(self, s: str) -> str:
        if not s: return ""
        ct = eme_transform(self._bc, self.name_tweak, self._pad(s.encode("utf-8")), True)
        return self.enc.encode(ct)

    def _dec_seg(self, s: str) -> str:
        if not s: return ""
        raw = self.enc.decode(s)
        if len(raw) % 16 != 0: raise ValueError("not multiple of 16")
        pt = eme_transform(self._bc, self.name_tweak, raw, False)
        return self._unpad(pt).decode("utf-8")

    def _obf_seg(self, s: str) -> str:
        if not s: return ""
        d = sum(ord(c) for c in s) % 256
        res = [str(d), "."]
        rd = d
        for b in self.name_key: rd = (rd + b) & 0xFF
        for ch in s:
            c = ord(ch)
            if c == 33: res.append("!!"); continue
            if 48 <= c <= 57:
                dd = (rd % 9) + 1; res.append(chr(48 + (c - 48 + dd) % 10))
            elif 65 <= c <= 90 or 97 <= c <= 122:
                dd = (rd % 25) + 1; pos = c - 65
                if pos >= 26: pos -= 6
                pos = (pos + dd) % 52
                if pos >= 26: pos += 6
                res.append(chr(65 + pos))
            else: res.append(ch)
        return "".join(res)

    def _deobf_seg(self, s: str) -> str:
        if not s or "." not in s: raise ValueError("bad obf")
        num, rest = s.split(".", 1)
        if num == "!": return rest
        d0 = int(num); rd = d0
        for b in self.name_key: rd = (rd + b) & 0xFF
        out = []; i = 0
        while i < len(rest):
            ch = rest[i]
            if ch == "!":
                if i+1 < len(rest): out.append(rest[i+1]); i += 2; continue
            c = ord(ch)
            if 48 <= c <= 57:
                dd = (rd % 9) + 1; nc = c - dd
                if nc < 48: nc += 10; out.append(chr(nc))
            elif 65 <= c <= 90 or 97 <= c <= 122:
                dd = (rd % 25) + 1; pos = c - 65
                if pos >= 26: pos -= 6
                pos -= dd
                if pos < 0: pos += 52
                if pos >= 26: pos += 6
                out.append(chr(65 + pos))
            else: out.append(ch)
            i += 1
        return "".join(out)

    def encrypt_name(self, path: str) -> str:
        if self.mode == "off":
            return path + self.suffix if self.suffix else path
        segs = path.split("/")
        out = []
        for i, seg in enumerate(segs):
            if not self.dir_name_encrypt and i != len(segs)-1:
                out.append(seg); continue
            out.append(self._enc_seg(seg) if self.mode == "standard" else self._obf_seg(seg))
        return "/".join(out)

    def decrypt_name(self, path: str) -> str:
        if self.mode == "off":
            if self.suffix and path.endswith(self.suffix):
                return path[:-len(self.suffix)]
            if self.suffix: raise ValueError("bad suffix")
            return path
        segs = path.split("/")
        out = []
        for i, seg in enumerate(segs):
            if not self.dir_name_encrypt and i != len(segs)-1:
                out.append(seg); continue
            out.append(self._dec_seg(seg) if self.mode == "standard" else self._deobf_seg(seg))
        return "/".join(out)

    def encrypt_file(self, src: BinaryIO, dst: BinaryIO) -> None:
        nonce = bytearray(os.urandom(FILE_NONCE_SIZE))
        dst.write(FILE_MAGIC); dst.write(nonce)
        while True:
            blk = src.read(BLOCK_DATA_SIZE)
            if not blk: break
            ct = _nacl_bindings.crypto_secretbox(blk, bytes(nonce), self.data_key)
            dst.write(ct)
            n = int.from_bytes(nonce, "little") + 1
            nonce[:] = n.to_bytes(FILE_NONCE_SIZE, "little")

    def decrypt_file(self, src: BinaryIO, dst: BinaryIO) -> None:
        hdr = src.read(FILE_HEADER_SIZE)
        if len(hdr) < FILE_HEADER_SIZE or not hdr.startswith(FILE_MAGIC):
            raise ValueError("bad magic / too short")
        nonce = bytearray(hdr[FILE_MAGIC_SIZE:])
        while True:
            chunk = src.read(BLOCK_HEADER_SIZE + BLOCK_DATA_SIZE)
            if not chunk: break
            if len(chunk) < BLOCK_HEADER_SIZE: raise ValueError("truncated block")
            try:
                pt = _nacl_bindings.crypto_secretbox_open(chunk, bytes(nonce), self.data_key)
            except Exception:
                if getattr(self, "pass_bad_blocks", False):
                    pt = b"\x00" * (len(chunk) - BLOCK_HEADER_SIZE)
                else: raise
            dst.write(pt)
            n = int.from_bytes(nonce, "little") + 1
            nonce[:] = n.to_bytes(FILE_NONCE_SIZE, "little")
