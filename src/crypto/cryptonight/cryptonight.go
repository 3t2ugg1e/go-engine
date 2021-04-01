package cryptonight

import (
	"encoding/binary"
	"encoding/hex"
	"github.com/decred/dcrd/crypto/blake256"
	"github.com/esrrhs/go-engine/src/crypto/cryptonight/internal/aes"
	"github.com/esrrhs/go-engine/src/crypto/cryptonight/internal/groestl"
	"github.com/esrrhs/go-engine/src/crypto/cryptonight/internal/jh"
	"github.com/esrrhs/go-engine/src/crypto/cryptonight/internal/sha3"
	"github.com/esrrhs/go-engine/src/crypto/cryptonight/internal/skein"
	"hash"
	"sync"
	"unsafe"
)

type cache struct {
	// DO NOT change the order of these fields in this struct!
	// They are carefully placed in this order to keep at least 16-byte aligned
	// for some fields.
	//
	// In the future the alignment may be set explicitly, see
	// https://github.com/golang/go/issues/19057

	scratchpad [2 * 1024 * 1024 / 8]uint64 // 2 MiB scratchpad for memhard loop
	finalState [25]uint64                  // state of keccak1600
	_          [8]byte                     // padded to keep 16-byte align (0x2000d0)

	blocks [16]uint64 // temporary chunk/pointer of data
	rkeys  [40]uint32 // 10 rounds, instead of 14 as in standard AES-256
}

func (cc *cache) sum(data []byte, variant int) []byte {
	//////////////////////////////////////////////////
	// these variables never escape to heap
	var (
		// used in memory hard
		a, b, c, d [2]uint64

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
	if variant == 2 {
		e[0] = cc.finalState[8] ^ cc.finalState[10]
		e[1] = cc.finalState[9] ^ cc.finalState[11]
		divResult = cc.finalState[12]
		sqrtResult = cc.finalState[13]
	}

	for i := 0; i < 524288; i++ {
		addr := (a[0] & 0x1ffff0) >> 3
		aes.CnSingleRoundGo(c[:2], cc.scratchpad[addr:addr+2], &a)

		if variant == 2 {
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
		}

		// byteMul
		lo, hi := mul128(c[0], d[0])

		if variant == 2 {
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

			// VARIANT2_2
			chunk0_0 ^= hi
			chunk0_1 ^= lo
			hi ^= chunk1_0
			lo ^= chunk1_1

			cc.scratchpad[offset0+0] = chunk2_0 + e[0]
			cc.scratchpad[offset0+1] = chunk2_1 + e[1]
			cc.scratchpad[offset2+0] = chunk1_0 + a[0]
			cc.scratchpad[offset2+1] = chunk1_1 + a[1]
			cc.scratchpad[offset1+0] = chunk0_0 + b[0]
			cc.scratchpad[offset1+1] = chunk0_1 + b[1]

			// re-asign higher-order of b
			e[0] = b[0]
			e[1] = b[1]
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

		b[0] = c[0]
		b[1] = c[1]
	}

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

var hashPool = [...]*sync.Pool{
	{New: func() interface{} { return blake256.New() }},
	{New: func() interface{} { return groestl.New256() }},
	{New: func() interface{} { return jh.New256() }},
	{New: func() interface{} { return skein.New256(nil) }},
}

func (cc *cache) finalHash() []byte {
	hp := hashPool[cc.finalState[0]&0x03]
	h := hp.Get().(hash.Hash)
	h.Reset()
	h.Write((*[200]byte)(unsafe.Pointer(&cc.finalState))[:])
	sum := h.Sum(nil)
	hp.Put(h)
	return sum
}

// cachePool is a pool of cache.
var cachePool = sync.Pool{
	New: func() interface{} {
		return new(cache)
	},
}

// Sum calculate a CryptoNight hash digest. The return value is exactly 32 bytes
// long.
//
// When variant is 1, data is required to have at least 43 bytes.
// This is assumed and not checked by Sum. If this condition doesn't meet, Sum
// will panic straightforward.
func Sum(data []byte, variant int) []byte {
	cc := cachePool.Get().(*cache)
	sum := cc.sum(data, variant)
	cachePool.Put(cc)

	return sum
}

type hashSpec struct {
	input, output string // both in hex
	variant       int
}

type hashSpecBin struct {
	input, output []byte // both in hex
	variant       int
}

var (
	hashSpecBinV0 = []hashSpecBin{
		// from xmrig cn/0
		{[]byte{0x03, 0x05, 0xA0, 0xDB, 0xD6, 0xBF, 0x05, 0xCF, 0x16, 0xE5, 0x03, 0xF3, 0xA6, 0x6F, 0x78, 0x00,
			0x7C, 0xBF, 0x34, 0x14, 0x43, 0x32, 0xEC, 0xBF, 0xC2, 0x2E, 0xD9, 0x5C, 0x87, 0x00, 0x38, 0x3B,
			0x30, 0x9A, 0xCE, 0x19, 0x23, 0xA0, 0x96, 0x4B, 0x00, 0x00, 0x00, 0x08, 0xBA, 0x93, 0x9A, 0x62,
			0x72, 0x4C, 0x0D, 0x75, 0x81, 0xFC, 0xE5, 0x76, 0x1E, 0x9D, 0x8A, 0x0E, 0x6A, 0x1C, 0x3F, 0x92,
			0x4F, 0xDD, 0x84, 0x93, 0xD1, 0x11, 0x56, 0x49, 0xC0, 0x5E, 0xB6, 0x01,
			0x01, 0x00, 0xFB, 0x8E, 0x8A, 0xC8, 0x05, 0x89, 0x93, 0x23, 0x37, 0x1B, 0xB7, 0x90, 0xDB, 0x19,
			0x21, 0x8A, 0xFD, 0x8D, 0xB8, 0xE3, 0x75, 0x5D, 0x8B, 0x90, 0xF3, 0x9B, 0x3D, 0x55, 0x06, 0xA9,
			0xAB, 0xCE, 0x4F, 0xA9, 0x12, 0x24, 0x45, 0x00, 0x00, 0x00, 0x00, 0xEE, 0x81, 0x46, 0xD4, 0x9F,
			0xA9, 0x3E, 0xE7, 0x24, 0xDE, 0xB5, 0x7D, 0x12, 0xCB, 0xC6, 0xC6, 0xF3, 0xB9, 0x24, 0xD9, 0x46,
			0x12, 0x7C, 0x7A, 0x97, 0x41, 0x8F, 0x93, 0x48, 0x82, 0x8F, 0x0F, 0x02,
			0x07, 0x07, 0xB4, 0x87, 0xD0, 0xD6, 0x05, 0x26, 0xE0, 0xC6, 0xDD, 0x9B, 0xC7, 0x18, 0xC3, 0xCF,
			0x52, 0x04, 0xBD, 0x4F, 0x9B, 0x27, 0xF6, 0x73, 0xB9, 0x3F, 0xEF, 0x7B, 0xB2, 0xF7, 0x2B, 0xBB,
			0x3F, 0x3E, 0x9C, 0x3E, 0x9D, 0x33, 0x1E, 0xDE, 0xAD, 0xBE, 0xEF, 0x4E, 0x00, 0x91, 0x81, 0x29,
			0x74, 0xB2, 0x70, 0xE7, 0x6D, 0xD2, 0x2A, 0x5F, 0x52, 0x04, 0x93, 0xE6, 0x18, 0x89, 0x40, 0xD8,
			0xC6, 0xE3, 0x90, 0x6E, 0xAA, 0x6A, 0xB7, 0xE2, 0x08, 0x7E, 0x78, 0x0E,
			0x01, 0x00, 0xEE, 0xB2, 0xD1, 0xD6, 0x05, 0xFF, 0x27, 0x7F, 0x26, 0xDB, 0xAA, 0xB2, 0xC9, 0x26,
			0x30, 0xC6, 0xCF, 0x11, 0x64, 0xEA, 0x6C, 0x8A, 0xE0, 0x98, 0x01, 0xF8, 0x75, 0x4B, 0x49, 0xAF,
			0x79, 0x70, 0xAE, 0xEE, 0xA7, 0x62, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x47, 0x8C, 0x63, 0xE7, 0xD8,
			0x40, 0x02, 0x3C, 0xDA, 0xEA, 0x92, 0x52, 0x53, 0xAC, 0xFD, 0xC7, 0x8A, 0x4C, 0x31, 0xB2, 0xF2,
			0xEC, 0x72, 0x7B, 0xFF, 0xCE, 0xC0, 0xE7, 0x12, 0xD4, 0xE9, 0x2A, 0x01,
			0x07, 0x07, 0xA9, 0xB7, 0xD1, 0xD6, 0x05, 0x3F, 0x0D, 0x5E, 0xFD, 0xC7, 0x03, 0xFC, 0xFC, 0xD2,
			0xCE, 0xBC, 0x44, 0xD8, 0xAB, 0x44, 0xA6, 0xA0, 0x3A, 0xE4, 0x4D, 0x8F, 0x15, 0xAF, 0x62, 0x17,
			0xD1, 0xE0, 0x92, 0x85, 0xE4, 0x73, 0xF9, 0x00, 0x00, 0x00, 0xA0, 0xFC, 0x09, 0xDE, 0xAB, 0xF5,
			0x8B, 0x6F, 0x1D, 0xCA, 0xA8, 0xBA, 0xAC, 0x74, 0xDD, 0x74, 0x19, 0xD5, 0xD6, 0x10, 0xEC, 0x38,
			0xCF, 0x50, 0x29, 0x6A, 0x07, 0x0B, 0x93, 0x8F, 0x8F, 0xA8, 0x10, 0x04}, []byte{0x1A, 0x3F, 0xFB, 0xEE, 0x90, 0x9B, 0x42, 0x0D, 0x91, 0xF7, 0xBE, 0x6E, 0x5F, 0xB5, 0x6D, 0xB7,
			0x1B, 0x31, 0x10, 0xD8, 0x86, 0x01, 0x1E, 0x87, 0x7E, 0xE5, 0x78, 0x6A, 0xFD, 0x08, 0x01, 0x00,
			0x1B, 0x60, 0x6A, 0x3F, 0x4A, 0x07, 0xD6, 0x48, 0x9A, 0x1B, 0xCD, 0x07, 0x69, 0x7B, 0xD1, 0x66,
			0x96, 0xB6, 0x1C, 0x8A, 0xE9, 0x82, 0xF6, 0x1A, 0x90, 0x16, 0x0F, 0x4E, 0x52, 0x82, 0x8A, 0x7F,
			0xA1, 0xB4, 0xFA, 0xE3, 0xE5, 0x76, 0xCE, 0xCF, 0xB7, 0x9C, 0xAF, 0x3E, 0x29, 0x92, 0xE4, 0xE0,
			0x31, 0x24, 0x05, 0x48, 0xBF, 0x8D, 0x5F, 0x7B, 0x11, 0x03, 0x60, 0xAA, 0xD7, 0x50, 0x3F, 0x0C,
			0x2D, 0x30, 0xF3, 0x87, 0x4F, 0x86, 0xA1, 0x4A, 0xB5, 0xA2, 0x1A, 0x08, 0xD0, 0x44, 0x2C, 0x9D,
			0x16, 0xE9, 0x28, 0x49, 0xA1, 0xFF, 0x85, 0x6F, 0x12, 0xBB, 0x7D, 0xAB, 0x11, 0x1C, 0xE7, 0xF7,
			0x2D, 0x9D, 0x19, 0xE4, 0xD2, 0x26, 0x44, 0x1E, 0xCD, 0x22, 0x08, 0x24, 0xA8, 0x97, 0x46, 0x62,
			0x04, 0x84, 0x90, 0x4A, 0xEE, 0x99, 0x14, 0xED, 0xB8, 0xC6, 0x0D, 0x37, 0xA1, 0x66, 0x17, 0xB0}, 0},
	}

	hashSpecsV0 = []hashSpec{
		// From CNS008
		{"", "eb14e8a833fac6fe9a43b57b336789c46ffe93f2868452240720607b14387e11", 0},
		{
			"5468697320697320612074657374", // "This is a test"
			"a084f01d1437a09c6985401b60d43554ae105802c5f5d8a9b3253649c0be6605",
			0,
		},

		// From monero: tests/hash/tests-slow.txt
		{"6465206f6d6e69627573206475626974616e64756d", "2f8e3df40bd11f9ac90c743ca8e32bb391da4fb98612aa3b6cdc639ee00b31f5", 0},
		{"6162756e64616e732063617574656c61206e6f6e206e6f636574", "722fa8ccd594d40e4a41f3822734304c8d5eff7e1b528408e2229da38ba553c4", 0},
		{"63617665617420656d70746f72", "bbec2cacf69866a8e740380fe7b818fc78f8571221742d729d9d02d7f8989b87", 0},
		{"6578206e6968696c6f206e6968696c20666974", "b1257de4efc5ce28c6b40ceb1c6c8f812a64634eb3e81c5220bee9b2b76a6f05", 0},
	}
	hashSpecsV1 = []hashSpec{
		// From monero: tests/hash/tests-slow-1.txt
		{"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "b5a7f63abb94d07d1a6445c36c07c7e8327fe61b1647e391b4c7edae5de57a3d", 1},
		{"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "80563c40ed46575a9e44820d93ee095e2851aa22483fd67837118c6cd951ba61", 1},
		{"8519e039172b0d70e5ca7b3383d6b3167315a422747b73f019cf9528f0fde341fd0f2a63030ba6450525cf6de31837669af6f1df8131faf50aaab8d3a7405589", "5bb40c5880cef2f739bdb6aaaf16161eaae55530e7b10d7ea996b751a299e949", 1},
		{"37a636d7dafdf259b7287eddca2f58099e98619d2f99bdb8969d7b14498102cc065201c8be90bd777323f449848b215d2977c92c4c1c2da36ab46b2e389689ed97c18fec08cd3b03235c5e4c62a37ad88c7b67932495a71090e85dd4020a9300", "613e638505ba1fd05f428d5c9f8e08f8165614342dac419adc6a47dce257eb3e", 1},
		{"38274c97c45a172cfc97679870422e3a1ab0784960c60514d816271415c306ee3a3ed1a77e31f6a885c3cb", "ed082e49dbd5bbe34a3726a0d1dad981146062b39d36d62c71eb1ed8ab49459b", 1},

		// Produced by monero: src/crypto/slow-hash.c:cn_slow_hash
		{
			"e5ad98e59ca8e8a8bce6988ee38292e38081e38193e381aee682b2e9b3b4e38292e38081e68896e38184e381afe6ad8ce38292",
			"24aa73ab3b1e74bf119b31c62470e5cf29dde98c9a8af33ac243d3103ebca0e5",
			1,
		},
	}
	hashSpecsV2 = []hashSpec{
		// From monero: tests/hash/test-slow-2.txt
		{"5468697320697320612074657374205468697320697320612074657374205468697320697320612074657374", "353fdc068fd47b03c04b9431e005e00b68c2168a3cc7335c8b9b308156591a4f", 2},
		{"4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e67", "72f134fc50880c330fe65a2cb7896d59b2e708a0221c6a9da3f69b3a702d8682", 2},
		{"656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f7265", "410919660ec540fc49d8695ff01f974226a2a28dbbac82949c12f541b9a62d2f", 2},
		{"657420646f6c6f7265206d61676e6120616c697175612e20557420656e696d206164206d696e696d2076656e69616d2c", "4472fecfeb371e8b7942ce0378c0ba5e6d0c6361b669c587807365c787ae652d", 2},
		{"71756973206e6f737472756420657865726369746174696f6e20756c6c616d636f206c61626f726973206e697369", "577568395203f1f1225f2982b637f7d5e61b47a0f546ba16d46020b471b74076", 2},
		{"757420616c697175697020657820656120636f6d6d6f646f20636f6e7365717561742e20447569732061757465", "f6fd7efe95a5c6c4bb46d9b429e3faf65b1ce439e116742d42b928e61de52385", 2},
		{"697275726520646f6c6f7220696e20726570726568656e646572697420696e20766f6c7570746174652076656c6974", "422f8cfe8060cf6c3d9fd66f68e3c9977adb683aea2788029308bbe9bc50d728", 2},
		{"657373652063696c6c756d20646f6c6f726520657520667567696174206e756c6c612070617269617475722e", "512e62c8c8c833cfbd9d361442cb00d63c0a3fd8964cfd2fedc17c7c25ec2d4b", 2},
		{"4578636570746575722073696e74206f6363616563617420637570696461746174206e6f6e2070726f6964656e742c", "12a794c1aa13d561c9c6111cee631ca9d0a321718d67d3416add9de1693ba41e", 2},
		{"73756e7420696e2063756c706120717569206f666669636961206465736572756e74206d6f6c6c697420616e696d20696420657374206c61626f72756d2e", "2659ff95fc74b6215c1dc741e85b7a9710101b30620212f80eb59c3c55993f9d", 2},
	}

	// This test data set is specially picked, as the final hash functions for
	// all v0, v1, v2 when they are passed through are the same, and they cover
	// all the four final hashes, so it can just be more fair.
	//
	// Also, each row is 76 bytes long, matching the size of hashingBlob.
	benchData = [4][]byte{
		{0xa8, 0xab, 0xb6, 0xb, 0x87, 0xa3, 0x49, 0x26, 0x72, 0xbf, 0x9d, 0x18, 0xd4, 0xd5, 0x2c, 0x4c, 0x7b, 0x3f, 0x5a, 0xdd, 0x25, 0xdd, 0x8c, 0xd5, 0xe5, 0xd7, 0x85, 0xcd, 0x30, 0xde, 0x5f, 0x10, 0xb7, 0x32, 0xce, 0x45, 0xb8, 0x74, 0x5d, 0xf5, 0x2a, 0x87, 0x93, 0xcb, 0x51, 0x2b, 0xf7, 0x77, 0xc2, 0xa7, 0xcc, 0xc0, 0xb4, 0x96, 0x3e, 0x43, 0x8f, 0x3f, 0xbf, 0x16, 0x78, 0xf7, 0xa8, 0xb4, 0x5d, 0xb, 0x4d, 0xdf, 0xc5, 0x10, 0xbe, 0xaa, 0xd1, 0xf3, 0xef, 0x29},
		{0xe, 0xa3, 0x74, 0x46, 0xbf, 0x65, 0x53, 0xb4, 0xab, 0xc0, 0x11, 0x3e, 0x2b, 0x5b, 0x9, 0x26, 0xb8, 0x59, 0xf6, 0xb9, 0xbf, 0x5a, 0xb, 0x43, 0x95, 0x45, 0x8a, 0xa, 0x5f, 0xed, 0xb9, 0x9c, 0x79, 0xce, 0x6c, 0xbc, 0x7f, 0xa, 0x4a, 0xe3, 0x6f, 0x67, 0xb9, 0x89, 0xe6, 0x4, 0x2f, 0xe9, 0xe0, 0xd6, 0x8a, 0x50, 0x9f, 0x44, 0x7d, 0x96, 0x3f, 0xee, 0xc2, 0x71, 0x27, 0xfc, 0xf1, 0x43, 0xcd, 0xe8, 0x36, 0x34, 0x29, 0x8e, 0xd, 0xe9, 0x89, 0xb4, 0xae, 0xfd},
		{0xc5, 0xf0, 0x6f, 0xd5, 0x8, 0xe, 0x1d, 0x60, 0xb2, 0x6b, 0xe0, 0xd7, 0x7e, 0xa, 0x56, 0xef, 0x6c, 0xfb, 0x3b, 0xc7, 0x2d, 0xc5, 0x7b, 0x8, 0xb6, 0x54, 0x1, 0x65, 0xe1, 0x20, 0x22, 0xf2, 0x26, 0x5e, 0x4b, 0xe2, 0x49, 0x6c, 0x10, 0x1b, 0x8c, 0x43, 0xcb, 0xd5, 0xbd, 0x1e, 0x7c, 0x61, 0xd8, 0x6e, 0xe2, 0x47, 0x8c, 0x46, 0x44, 0xc3, 0x1a, 0x5, 0xb7, 0x5f, 0x85, 0x8b, 0x2a, 0x68, 0x55, 0xb0, 0x5f, 0xe4, 0xc8, 0xc3, 0xac, 0x52, 0x1e, 0x3f, 0xe3, 0x18},
		{0xfc, 0x11, 0x56, 0x9f, 0xae, 0xe8, 0x99, 0xd3, 0x62, 0xb8, 0x1a, 0xf6, 0xd3, 0xdc, 0x29, 0x69, 0x34, 0xd3, 0x98, 0x3c, 0x7f, 0x27, 0x93, 0x3, 0x3f, 0xf4, 0x28, 0x42, 0xcb, 0xe9, 0x9d, 0x5e, 0xc6, 0xad, 0x89, 0x36, 0x61, 0x87, 0x72, 0x30, 0x3c, 0xd5, 0x57, 0x91, 0xc6, 0xca, 0x54, 0x7a, 0xa9, 0xe3, 0x5e, 0x83, 0xd0, 0x8a, 0x58, 0xa1, 0x90, 0xe5, 0x5d, 0x7e, 0x3f, 0x31, 0xc3, 0xd8, 0xad, 0x12, 0x3, 0xdd, 0xd6, 0x36, 0xf1, 0x52, 0x5d, 0x5d, 0x4a, 0x36},
	}
)

func TestSum(variant int) bool {
	run := func(hashSpecs []hashSpec) bool {
		for _, v := range hashSpecs {
			in, _ := hex.DecodeString(v.input)
			result := Sum(in, v.variant)
			if hex.EncodeToString(result) != v.output {
				return false
			}
		}
		return true
	}

	runbin := func(hashSpecs []hashSpecBin) bool {
		for _, v := range hashSpecs {
			result := Sum(v.input[0:76], v.variant)
			for j, _ := range result {
				if result[j] != v.output[j] {
					return false
				}
			}
		}
		return true
	}

	if variant == 0 {
		return run(hashSpecsV0) && runbin(hashSpecBinV0)
	}

	if variant == 1 {
		return run(hashSpecsV1)
	}

	if variant == 2 {
		return run(hashSpecsV2)
	}

	return false
}
