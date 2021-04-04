package cryptonight

import (
	"encoding/binary"
	"github.com/esrrhs/go-engine/src/crypto/cryptonight/inter/aes"
	"github.com/esrrhs/go-engine/src/crypto/cryptonight/inter/sha3"
	"github.com/esrrhs/go-engine/src/loggo"
)

func (cc *cache) sum(data []byte, variant int, height uint64) []byte {
	//////////////////////////////////////////////////
	// these variables never escape to heap
	var (
		// used in memory hard
		a [2]uint64
		b [2]uint64
		c [2]uint64
		d [2]uint64

		// for variant 1
		v1Tweak uint64

		// for variant 2
		e          [2]uint64
		divResult  uint64
		sqrtResult uint64
	)

	//////////////////////////////////////////////////
	// as per CNS008 sec.3 Scratchpad Initialization
	sha3.Keccak1600State(&cc.finalState, data)

	if variant == 1 {
		if len(data) < 43 {
			panic("cryptonight: variant 2 requires at least 43 bytes of input")
		}
		v1Tweak = cc.finalState[24] ^ binary.LittleEndian.Uint64(data[35:43])
	}

	var r [9]uint32
	var rcode [NUM_INSTRUCTIONS_MAX + 1]V4_Instruction
	if variant == 4 {
		r[0] = uint32(cc.finalState[12])
		r[1] = uint32(cc.finalState[12] >> 32)
		r[2] = uint32(cc.finalState[13])
		r[3] = uint32(cc.finalState[13] >> 32)
		v4_random_math_init(rcode[:], height)
		var test_opcode uint32
		var test_srcindex uint32
		var test_dst_index uint32
		var test_code uint32
		for index, code := range rcode {
			loggo.Info("before rcode %v %v %v %v %v", index, code.opcode, code.dst_index, code.src_index, code.C)
			test_opcode += uint32(code.opcode)
			test_dst_index += uint32(code.dst_index)
			test_srcindex += uint32(code.src_index)
			test_code ^= code.C
		}
		loggo.Info("before rcode sum %v %v %v %v", test_opcode, test_srcindex, test_dst_index, test_code)
	}

	// scratchpad init
	aes.CnExpandKeyGo(cc.finalState[:4], &cc.rkeys)
	copy(cc.blocks[:], cc.finalState[8:24])

	for i := 0; i < 2*1024*1024/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			aes.CnRoundsGo(cc.blocks[j:j+2], cc.blocks[j:j+2], &cc.rkeys)
		}
		copy(cc.scratchpad[i:i+16], cc.blocks[:16])
	}

	//////////////////////////////////////////////////
	// as per CNS008 sec.4 Memory-Hard Loop
	a[0] = cc.finalState[0] ^ cc.finalState[4]
	a[1] = cc.finalState[1] ^ cc.finalState[5]
	b[0] = cc.finalState[2] ^ cc.finalState[6]
	b[1] = cc.finalState[3] ^ cc.finalState[7]
	if variant == 2 || variant == 4 {
		e[0] = cc.finalState[8] ^ cc.finalState[10]
		e[1] = cc.finalState[9] ^ cc.finalState[11]
		divResult = cc.finalState[12]
		sqrtResult = cc.finalState[13]
	}

	loggo.Info("before r %v %v %v %v %v %v %v %v %v", r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8])

	for i := 0; i < 524288; i++ {
		addr := (a[0] & 0x1ffff0) >> 3
		aes.CnSingleRoundGo(c[:2], cc.scratchpad[addr:addr+2], &a)

		if variant == 2 || variant == 4 {
			// since we use []uint64 instead of []uint8 as scratchpad, the offset applies too
			offset0 := addr ^ 0x02
			offset1 := addr ^ 0x04
			offset2 := addr ^ 0x06

			chunk0_0 := cc.scratchpad[offset0+0]
			chunk0_1 := cc.scratchpad[offset0+1]
			chunk1_0 := cc.scratchpad[offset1+0]
			chunk1_1 := cc.scratchpad[offset1+1]
			chunk2_0 := cc.scratchpad[offset2+0]
			chunk2_1 := cc.scratchpad[offset2+1]

			cc.scratchpad[offset0+0] = chunk2_0 + e[0]
			cc.scratchpad[offset0+1] = chunk2_1 + e[1]
			cc.scratchpad[offset2+0] = chunk1_0 + a[0]
			cc.scratchpad[offset2+1] = chunk1_1 + a[1]
			cc.scratchpad[offset1+0] = chunk0_0 + b[0]
			cc.scratchpad[offset1+1] = chunk0_1 + b[1]

			if variant == 4 {
				c[0] = (c[0] ^ chunk2_0) ^ (chunk0_0 ^ chunk1_0)
				c[1] = (c[1] ^ chunk2_1) ^ (chunk0_1 ^ chunk1_1)
			}
		}

		cc.scratchpad[addr+0] = b[0] ^ c[0]
		cc.scratchpad[addr+1] = b[1] ^ c[1]

		if variant == 1 {
			t := cc.scratchpad[addr+1] >> 24
			t = ((^t)&1)<<4 | (((^t)&1)<<4&t)<<1 | (t&32)>>1
			cc.scratchpad[addr+1] ^= t << 24
		}

		addr = (c[0] & 0x1ffff0) >> 3
		d[0] = cc.scratchpad[addr]
		d[1] = cc.scratchpad[addr+1]
		//loggo.Info("round addr c[0]=%v addr=%v d0=%v d1=%v", c[0], addr*8, d[0], d[1])

		if variant == 2 {
			// equivalent to VARIANT2_PORTABLE_INTEGER_MATH in slow-hash.c
			// VARIANT2_INTEGER_MATH_DIVISION_STEP
			d[0] ^= divResult ^ (sqrtResult << 32)
			divisor := (c[0]+(sqrtResult<<1))&0xffffffff | 0x80000001
			divResult = (c[1]/divisor)&0xffffffff | (c[1]%divisor)<<32
			sqrtInput := c[0] + divResult

			// VARIANT2_INTEGER_MATH_SQRT_STEP_FP64 and
			// VARIANT2_INTEGER_MATH_SQRT_FIXUP
			sqrtResult = v2Sqrt(sqrtInput)

		} else if variant == 4 {
			//loggo.Info("v4_random_math before r %v %v %v %v %v %v %v %v %v", r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8])
			//loggo.Info("round before a0=%v a1=%v b0=%v b1=%v c0=%v c1=%v d0=%v d1=%v e0=%v e1=%v", a[0], a[1], b[0], b[1], c[0], c[1], d[0], d[1], e[0], e[1])
			d[0] ^= uint64(r[0]+r[1]) | (uint64(r[2]+r[3]) << 32)
			r[4] = uint32(a[0])
			r[5] = uint32(a[1])
			r[6] = uint32(b[0])
			r[7] = uint32(e[0])
			r[8] = uint32(e[1])
			v4_random_math(rcode[:], r[:])
			a[0] ^= uint64(r[2]) | ((uint64)(r[3]) << 32)
			a[1] ^= uint64(r[0]) | ((uint64)(r[1]) << 32)
			//loggo.Info("round end a0=%v a1=%v b0=%v b1=%v c0=%v c1=%v d0=%v d1=%v e0=%v e1=%v", a[0], a[1], b[0], b[1], c[0], c[1], d[0], d[1], e[0], e[1])
			loggo.Info("round %d crc=%v", i, a[0]^a[1]^b[0]^b[1]^c[0]^c[1]^d[0]^d[1]^e[0]^e[1])
		}

		// byteMul
		lo, hi := mul128(c[0], d[0])

		if variant == 2 || variant == 4 {
			// shuffle again, it's the same process as above
			offset0 := addr ^ 0x02
			offset1 := addr ^ 0x04
			offset2 := addr ^ 0x06

			chunk0_0 := cc.scratchpad[offset0+0]
			chunk0_1 := cc.scratchpad[offset0+1]
			chunk1_0 := cc.scratchpad[offset1+0]
			chunk1_1 := cc.scratchpad[offset1+1]
			chunk2_0 := cc.scratchpad[offset2+0]
			chunk2_1 := cc.scratchpad[offset2+1]

			if variant == 2 {
				// VARIANT2_2
				chunk0_0 ^= hi
				chunk0_1 ^= lo
				hi ^= chunk1_0
				lo ^= chunk1_1
			}

			cc.scratchpad[offset0+0] = chunk2_0 + e[0]
			cc.scratchpad[offset0+1] = chunk2_1 + e[1]
			cc.scratchpad[offset2+0] = chunk1_0 + a[0]
			cc.scratchpad[offset2+1] = chunk1_1 + a[1]
			cc.scratchpad[offset1+0] = chunk0_0 + b[0]
			cc.scratchpad[offset1+1] = chunk0_1 + b[1]

			if variant == 4 {
				c[0] = (c[0] ^ chunk2_0) ^ (chunk0_0 ^ chunk1_0)
				c[1] = (c[1] ^ chunk2_1) ^ (chunk0_1 ^ chunk1_1)
			}
		}

		// byteAdd
		a[0] += hi
		a[1] += lo

		cc.scratchpad[addr+0] = a[0]
		cc.scratchpad[addr+1] = a[1]

		if variant == 1 {
			cc.scratchpad[addr+1] ^= v1Tweak
		}

		a[0] ^= d[0]
		a[1] ^= d[1]

		e[0] = b[0]
		e[1] = b[1]

		b[0] = c[0]
		b[1] = c[1]
	}

	loggo.Info("end loop round a0=%v a1=%v b0=%v b1=%v c0=%v c1=%v d0=%v d1=%v e0=%v e1=%v", a[0], a[1], b[0], b[1], c[0], c[1], d[0], d[1], e[0], e[1])

	//////////////////////////////////////////////////
	// as per CNS008 sec.5 Result Calculation
	aes.CnExpandKeyGo(cc.finalState[4:8], &cc.rkeys)
	tmp := cc.finalState[8:24] // a temp pointer

	for i := 0; i < 2*1024*1024/8; i += 16 {
		for j := 0; j < 16; j += 2 {
			cc.scratchpad[i+j+0] ^= tmp[j+0]
			cc.scratchpad[i+j+1] ^= tmp[j+1]
			aes.CnRoundsGo(cc.scratchpad[i+j:i+j+2], cc.scratchpad[i+j:i+j+2], &cc.rkeys)
		}
		tmp = cc.scratchpad[i : i+16]
	}

	copy(cc.finalState[8:24], tmp)
	sha3.Keccak1600Permute(&cc.finalState)

	return cc.finalHash()
}
