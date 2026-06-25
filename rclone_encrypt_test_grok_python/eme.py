"""Port of EME to match finally on L0 value from standalone go."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.modes import ECB


def mult_by_two(outp: bytearray, inb):
    tmp = bytearray(16)
    tmp[0] = (2 * inb[0]) & 0xff
    tmp[0] ^= (135 & ((- (inb[15] >> 7 )) & 0xff))
    for j in range(1, 16):
        tmp[j] = (2 * inb[j]) & 0xff
        tmp[j] += (inb[j-1] >> 7)
        tmp[j] &= 0xff
    outp[:] = tmp


def xor_blocks(outp: bytearray, a, b):
    for i in range(16):
        outp[i] = a[i] ^ b[i]


class Bc:
    def __init__(self, k):
        self.bc = Cipher(algorithms.AES(k), ECB())

    def Encrypt(self, dst, bp):
        e = self.bc.encryptor()
        dst[:] = e.update(bp) + e.finalize()

    def Decrypt(self, dst, bp):
        d = self.bc.decryptor()
        dst[:] = d.update(bp) + d.finalize()


def tabulateL(bc, m):
    eZero = bytes(16)
    Li = bytearray(16)
    bc.Encrypt(Li , eZero)
    LTab = []
    pool = bytearray(16 * m)
    for i in range(m):
        nxt = pool[i*16:(i+1)*16]
        mult_by_two(nxt , Li)
        LTab.append(nxt)
        Li = bytearray(nxt)
    return LTab


def Transform(bckey, twk, ind, encdir):
    m = len(ind) // 16
    bc = Bc(bckey)
    LTab = tabulateL(bc, m)
    C = bytearray(len(ind))
    pp = bytearray(16)
    for j in range(m):
        pj = ind[j*16:(j+1)*16]
        xor_blocks(pp, pj, LTab[j])
        dest = bytearray(16)
        if encdir:
            bc.Encrypt(dest, bytes(pp))
        else:
            bc.Decrypt(dest, bytes(pp))
        C[j*16:(j+1)*16] = dest
    mp = bytearray(16)
    xor_blocks(mp, C[0:16], twk)
    for j in range(1, m):
        xor_blocks(mp, mp, C[j*16:(j+1)*16])
    mc = bytearray(16)
    if encdir:
        bc.Encrypt(mc, bytes(mp))
    else:
        bc.Decrypt(mc, bytes(mp))
    mm = bytearray(16)
    xor_blocks(mm, mp, mc)
    ccc = bytearray(16)
    for j in range(1, m):
        mult_by_two(mm, mm)
        xor_blocks(ccc, C[j*16:(j+1)*16], mm)
        C[j*16:(j+1)*16] = ccc
    c1 = bytearray(16)
    xor_blocks(c1, mc, twk)
    for j in range(1, m):
        xor_blocks(c1, c1, C[j*16:(j+1)*16])
    C[0:16] = c1
    tmp = bytearray(16)
    for j in range(m):
        seg = C[j*16:(j+1)*16]
        if encdir:
            bc.Encrypt(tmp, bytes(seg))
        else:
            bc.Decrypt(tmp, bytes(seg))
        C[j*16:(j+1)*16] = tmp
        tmp2 = bytearray(16)
        xor_blocks(tmp2, tmp, LTab[j])
        C[j*16:(j+1)*16] = tmp2
    return bytes(C)


def eme_transform(k, t, data, e):
    return Transform(k, t, data, e)
