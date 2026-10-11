// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

package session

// Keccak-256 implementation (standard Keccak-f[1600] permutation with padding 0x01).
// Differential tested against standard Ethereum address derivation.

const (
	rate256 = 136 // 1088 bits / 8
)

var rc = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

var rho = [25]uint{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

func rotl64(v uint64, n uint) uint64 {
	n %= 64
	if n == 0 {
		return v
	}
	return (v << n) | (v >> (64 - n))
}

func keccakF1600(st *[25]uint64) {
	for round := 0; round < 24; round++ {
		// Theta
		var c [5]uint64
		for x := 0; x < 5; x++ {
			c[x] = st[x] ^ st[x+5] ^ st[x+10] ^ st[x+15] ^ st[x+20]
		}
		var d [5]uint64
		for x := 0; x < 5; x++ {
			d[x] = c[(x+4)%5] ^ rotl64(c[(x+1)%5], 1)
		}
		for i := 0; i < 25; i++ {
			st[i] ^= d[i%5]
		}

		// Rho and Pi
		var b [25]uint64
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				idx := x + 5*y
				b[y+5*((2*x+3*y)%5)] = rotl64(st[idx], rho[idx])
			}
		}

		// Chi
		for x := 0; x < 5; x++ {
			for y := 0; y < 5; y++ {
				st[x+5*y] = b[x+5*y] ^ ((^b[((x+1)%5)+5*y]) & b[((x+2)%5)+5*y])
			}
		}

		// Iota
		st[0] ^= rc[round]
	}
}

// Keccak256 computes standard Ethereum Keccak-256 hash.
func Keccak256(data []byte) [32]byte {
	var st [25]uint64

	// Pad
	padLen := rate256 - (len(data) % rate256)
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)
	padded[len(data)] = 0x01
	padded[len(padded)-1] |= 0x80

	// Absorb
	for offset := 0; offset < len(padded); offset += rate256 {
		block := padded[offset : offset+rate256]
		for i := 0; i < rate256/8; i++ {
			var w uint64
			for b := 0; b < 8; b++ {
				w |= uint64(block[i*8+b]) << (8 * b)
			}
			st[i] ^= w
		}
		keccakF1600(&st)
	}

	// Squeeze 32 bytes
	var out [32]byte
	for i := 0; i < 4; i++ {
		w := st[i]
		for b := 0; b < 8; b++ {
			out[i*8+b] = byte((w >> (8 * b)) & 0xff)
		}
	}
	return out
}
