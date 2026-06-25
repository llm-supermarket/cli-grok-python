package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
	"log"
)

type directionConst bool

const (
	DirectionEncrypt = directionConst(true)
	DirectionDecrypt = directionConst(false)
)

func multByTwo(out []byte, inb []byte) {
	if len(inb) != 16 {
		panic("len must be 16")
	}
	tmp := make([]byte, 16)

	tmp[0] = 2 * inb[0]
	tmp[0] = tmp[0] ^ (135 & byte(-(inb[15] >> 7)))
	for j := 1; j < 16; j++ {
		tmp[j] = 2 * inb[j]
		tmp[j] += inb[j-1] >> 7
	}
	copy(out, tmp)
}

func xorBlocks(out []byte, in1 []byte, in2 []byte) {
	if len(in1) != len(in2) {
		log.Panicf("len mismatch")
	}
	subtle.XORBytes(out, in1, in2)
}

func aesTransform(dst []byte, src []byte, direction directionConst, bc cipher.Block) {
	if direction {
		bc.Encrypt(dst, src)
	} else {
		bc.Decrypt(dst, src)
	}
}

func tabulateL(bc cipher.Block, m int) [][]byte {
	eZero := make([]byte, 16)
	Li := make([]byte, 16)
	bc.Encrypt(Li, eZero)

	LTable := make([][]byte, m)
	pool := make([]byte, m*16)
	for i := 0; i < m; i++ {
		multByTwo(Li, Li)
		LTable[i] = pool[i*16 : (i+1)*16]
		copy(LTable[i], Li)
	}
	return LTable
}

func Transform(bc cipher.Block, tweak []byte, inputData []byte, direction directionConst) []byte {
	T := tweak
	P := inputData
	if bc.BlockSize() != 16 {
		panic("blocksize")
	}
	if len(T) != 16 || len(P)%16 != 0 {
		panic("bad")
	}
	m := len(P) / 16
	if m == 0 || m > 128 {
		panic("bad m")
	}

	C := make([]byte, len(P))

	LTable := tabulateL(bc, m)

	PPj := make([]byte, 16)
	for j := 0; j < m; j++ {
		Pj := P[j*16 : (j+1)*16]
		xorBlocks(PPj, Pj, LTable[j])
		aesTransform(C[j*16:(j+1)*16], PPj, direction, bc)
	}

	MP := make([]byte, 16)
	xorBlocks(MP, C[0:16], T)
	for j := 1; j < m; j++ {
		xorBlocks(MP, MP, C[j*16:(j+1)*16])
	}

	MC := make([]byte, 16)
	aesTransform(MC, MP, direction, bc)

	M := make([]byte, 16)
	xorBlocks(M, MP, MC)
	CCCj := make([]byte, 16)
	for j := 1; j < m; j++ {
		multByTwo(M, M)
		xorBlocks(CCCj, C[j*16:(j+1)*16], M)
		copy(C[j*16:(j+1)*16], CCCj)
	}

	CCC1 := make([]byte, 16)
	xorBlocks(CCC1, MC, T)
	for j := 1; j < m; j++ {
		xorBlocks(CCC1, CCC1, C[j*16:(j+1)*16])
	}
	copy(C[0:16], CCC1)

	for j := 0; j < m; j++ {
		aesTransform(C[j*16:(j+1)*16], C[j*16:(j+1)*16], direction, bc)
		xorBlocks(C[j*16:(j+1)*16], C[j*16:(j+1)*16], LTable[j])
	}

	return C
}

func main() {
	keyb := make([]byte, 32)
	t := make([]byte, 16)
	padded := []byte("TEST_FILE.txt")
	bc, _ := aes.NewCipher(keyb)
	LTable := tabulateL(bc, 1)
	fmt.Printf("L: %x
", LTable[0])
	C0 := make([]byte,16)
	pp := make([]byte,16)
	xorBlocks(pp, padded, LTable[0])
	aesTransform(C0, pp, DirectionEncrypt, bc)
	fmt.Printf("C0:%x
", C0)
	MP := make([]byte, 16)
	xorBlocks(MP, C0, t)
	fmt.Printf("MP:%x
", MP)
	MCb := make([]byte,16)
	aesTransform(MCb , MP , DirectionEncrypt, bc)
	fmt.Printf("MC:%x
", MCb)
	Cb := Transform(bc, t, padded , DirectionEncrypt)
	fmt.Printf("CT:%x
", Cb)
}
