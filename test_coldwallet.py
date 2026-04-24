"""
test_coldwallet.py
==================
Test suite for the GB Cold Wallet BIP39 logic.

Verifies that the algorithm embedded in coldwallet.c is correct by
porting every layer to Python and testing against authoritative vectors.

Run with:  python test_coldwallet.py
"""

import hashlib
import hmac
import struct
import sys
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Load wordlist (same file used to generate bip39_words.h)
# ---------------------------------------------------------------------------

WORDLIST_PATH = Path(__file__).resolve().parent.parent.parent / "python" / "bip39_english.txt"
WORDS = [w.strip() for w in WORDLIST_PATH.open()]
assert len(WORDS) == 2048, f"Expected 2048 words, got {len(WORDS)}"

# ---------------------------------------------------------------------------
# Faithful Python port of the C SHA-256 (from coldwallet.c)
# Used to verify our implementation matches Python's hashlib.
# ---------------------------------------------------------------------------

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

MASK = 0xFFFFFFFF

def rotr32(x, n):
    return ((x >> n) | (x << (32 - n))) & MASK

def sha256_port(data: bytes) -> bytes:
    """Pure-Python SHA-256 matching the C implementation in coldwallet.c."""
    state = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]

    def compress(block: bytes):
        assert len(block) == 64
        w = list(struct.unpack(">16I", block))
        for i in range(16, 64):
            s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = rotr32(w[i- 2],17) ^ rotr32(w[i- 2], 19) ^ (w[i- 2] >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & MASK)
        a, b, c, d, e, f, g, h = state
        for i in range(64):
            S1  = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25)
            ch  = (e & f) ^ ((~e & MASK) & g)
            t1  = (h + S1 + ch + K[i] + w[i]) & MASK
            S0  = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2  = (S0 + maj) & MASK
            h, g, f, e = g, f, e, (d + t1) & MASK
            d, c, b, a = c, b, a, (t1 + t2) & MASK
        for idx, v in enumerate([a, b, c, d, e, f, g, h]):
            state[idx] = (state[idx] + v) & MASK

    # Padding
    msg = bytearray(data)
    bitlen = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack(">Q", bitlen)

    for i in range(0, len(msg), 64):
        compress(bytes(msg[i:i+64]))

    return struct.pack(">8I", *state)

# ---------------------------------------------------------------------------
# Faithful Python port of extract11 (from coldwallet.c)
# ---------------------------------------------------------------------------

def extract11(src: bytes, off: int) -> int:
    """Extract 11 bits at bit-offset `off` from `src` (big-endian)."""
    bo = off >> 3
    bi = off & 7
    v = (src[bo] << 16) | (src[bo+1] << 8) | src[bo+2]
    v >>= (24 - 11 - bi)
    return v & 0x7FF

# ---------------------------------------------------------------------------
# Faithful Python port of hmac_sha256 (from coldwallet.c)
# Implemented in terms of sha256_port so we test BOTH the C SHA core AND
# the C HMAC construction together.
# ---------------------------------------------------------------------------

def hmac_sha256_port(key: bytes, msg: bytes) -> bytes:
    """RFC 2104 HMAC-SHA256 using the C-ported SHA-256."""
    assert len(key) <= 64, "C version assumes klen < 64"
    block_pad = key + b"\x00" * (64 - len(key))
    ipad = bytes(b ^ 0x36 for b in block_pad)
    opad = bytes(b ^ 0x5c for b in block_pad)
    return sha256_port(opad + sha256_port(ipad + msg))

# ---------------------------------------------------------------------------
# Faithful Python port of pack_bits (from coldwallet.c)
# ---------------------------------------------------------------------------

def pack_bits(bits) -> bytes:
    """Pack a sequence of 0/1 ints (MSB-first) into bytes."""
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b & 1:
            out[i >> 3] |= 1 << (7 - (i & 7))
    return bytes(out)

# ---------------------------------------------------------------------------
# Domain-separator key (must match HMAC_KEY in coldwallet.c)
# ---------------------------------------------------------------------------

HMAC_KEY = b"GB-COLDWALLET-BIP39-entropy"

def derive_from_pool(pool: bytes) -> list:
    """Mirror the C make_mnemonic(): HMAC-SHA256(pool) -> 16-byte entropy -> mnemonic."""
    entropy = hmac_sha256_port(HMAC_KEY, pool)[:16]
    return make_mnemonic(entropy)

# ---------------------------------------------------------------------------
# Faithful Python port of make_mnemonic (from coldwallet.c)
# ---------------------------------------------------------------------------

def make_mnemonic(entropy: bytes) -> list:
    """Return 12-word list from 16-byte entropy, matching the C implementation."""
    assert len(entropy) == 16
    ent = bytearray(entropy)
    ent += bytes([sha256_port(entropy)[0]])   # 4-bit checksum nibble
    ent += b"\x00\x00\x00"                    # 3-byte read-ahead pad
    return [WORDS[extract11(bytes(ent), i * 11)] for i in range(12)]

# ===========================================================================
#  TEST SUITE
# ===========================================================================

class TestSHA256Port(unittest.TestCase):
    """Verify our C-ported SHA-256 matches hashlib (NIST test vectors)."""

    def _check(self, data: bytes):
        expected = hashlib.sha256(data).digest()
        got      = sha256_port(data)
        self.assertEqual(got, expected, f"SHA-256 mismatch for {data!r}")

    def test_empty(self):
        self._check(b"")

    def test_abc(self):
        self._check(b"abc")

    def test_448_bit(self):
        # NIST FIPS 180-4 example
        self._check(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")

    def test_one_million_a(self):
        # Requires multi-block compression path
        self._check(b"a" * 1_000_000)

    def test_55_bytes(self):
        # Exactly fills one block minus 1 before padding
        self._check(b"A" * 55)

    def test_56_bytes(self):
        # First byte that requires a second padding block
        self._check(b"A" * 56)

    def test_64_bytes(self):
        self._check(b"A" * 64)

    def test_known_digest(self):
        # "The quick brown fox jumps over the lazy dog"
        self.assertEqual(
            sha256_port(b"The quick brown fox jumps over the lazy dog").hex(),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        )


class TestExtract11(unittest.TestCase):
    """Verify bit extraction against hand-calculated values."""

    def test_first_11_bits(self):
        # 0b10000000 0b00000000 0b00000000 -> bits 0..10 = 0b10000000000 = 1024
        src = bytes([0x80, 0x00, 0x00])
        self.assertEqual(extract11(src, 0), 1024)

    def test_second_11_bits(self):
        # bits 11..21: need bytes at indices 1,2,3
        # 0x00 0xFF 0xFF 0xE0 -> bits 11..21 = 0b11111111111 = 2047
        src = bytes([0x00, 0xFF, 0xFF, 0xE0])
        self.assertEqual(extract11(src, 11), 2047)

    def test_all_zeros(self):
        src = bytes(20)
        for i in range(12):
            self.assertEqual(extract11(src, i * 11), 0)

    def test_all_ones(self):
        src = bytes([0xFF] * 20)
        for i in range(12):
            self.assertEqual(extract11(src, i * 11), 2047)

    def test_known_index(self):
        # With entropy = bytes(16), ent[16]=sha256(bytes(16))[0]=0x76, check word 11
        ent = bytearray(16) + bytes([sha256_port(bytes(16))[0]]) + b"\x00\x00\x00"
        # Word 11 of the zero vector must be index of "about" = 3
        idx = extract11(bytes(ent), 11 * 11)
        self.assertEqual(WORDS[idx], "about")


class TestBIP39OfficialVectors(unittest.TestCase):
    """
    Official BIP39 English test vectors for 128-bit (12-word) seeds.
    Source: https://github.com/trezor/python-mnemonic/blob/master/vectors.json
    """

    VECTORS = [
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        ),
        (
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
        ),
        (
            "9e885d952ad362caeb4efe34a8e91bd2",
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
        ),
    ]

    def _run(self, entropy_hex, expected_phrase):
        entropy = bytes.fromhex(entropy_hex)
        got = " ".join(make_mnemonic(entropy))
        self.assertEqual(got, expected_phrase,
            f"\nentropy : {entropy_hex}\nexpected: {expected_phrase}\ngot     : {got}")

    def test_all_zeros(self):
        self._run(*self.VECTORS[0])

    def test_7f(self):
        self._run(*self.VECTORS[1])

    def test_80(self):
        self._run(*self.VECTORS[2])

    def test_all_ff(self):
        self._run(*self.VECTORS[3])

    def test_random_known(self):
        self._run(*self.VECTORS[4])


class TestWordlistIntegrity(unittest.TestCase):
    """Sanity-check the loaded wordlist."""

    def test_length(self):
        self.assertEqual(len(WORDS), 2048)

    def test_no_duplicates(self):
        self.assertEqual(len(set(WORDS)), 2048)

    def test_sorted(self):
        self.assertEqual(WORDS, sorted(WORDS))

    def test_all_lowercase(self):
        for w in WORDS:
            self.assertEqual(w, w.lower(), f"Word not lowercase: {w!r}")

    def test_max_length(self):
        # BIP39 English words are at most 8 characters
        for w in WORDS:
            self.assertLessEqual(len(w), 8, f"Word too long: {w!r}")

    def test_known_positions(self):
        # Spot-check well-known positions from the spec
        self.assertEqual(WORDS[0],    "abandon")
        self.assertEqual(WORDS[1],    "ability")
        self.assertEqual(WORDS[2047], "zoo")


class TestChecksumValidation(unittest.TestCase):
    """Verify the 4-bit checksum is computed correctly."""

    def _checksum_nibble(self, entropy: bytes) -> int:
        """Return the top 4 bits of SHA-256(entropy)."""
        return sha256_port(entropy)[0] >> 4

    def test_zero_entropy_checksum(self):
        # Verify our port matches hashlib for the checksum byte
        ent = bytes(16)
        expected_nibble = hashlib.sha256(ent).digest()[0] >> 4
        got_nibble      = self._checksum_nibble(ent)
        self.assertEqual(got_nibble, expected_nibble)

    def test_ff_entropy_checksum(self):
        # Word 11 of the all-FF vector is "wrong" -- verify checksum nibble
        ent = bytes([0xFF] * 16)
        cs_byte = sha256_port(ent)[0]
        # The 12th word uses the 4-bit checksum; for all-FF it must produce "wrong"
        data = bytearray(ent) + bytes([cs_byte]) + b"\x00\x00\x00"
        idx  = extract11(bytes(data), 11 * 11)
        self.assertEqual(WORDS[idx], "wrong")

    def test_checksum_catches_bit_flip(self):
        # Flip one bit in entropy; last word should change
        ent_ok      = bytes.fromhex("9e885d952ad362caeb4efe34a8e91bd2")
        ent_flipped = bytearray(ent_ok)
        ent_flipped[15] ^= 0x01
        w_ok  = make_mnemonic(ent_ok)[-1]
        w_bad = make_mnemonic(bytes(ent_flipped))[-1]
        self.assertNotEqual(w_ok, w_bad,
            "A 1-bit entropy change should alter the mnemonic")


class TestHMACSha256(unittest.TestCase):
    """Verify our C-ported HMAC-SHA256 matches stdlib hmac for varied inputs."""

    def _check(self, key: bytes, msg: bytes):
        expected = hmac.new(key, msg, hashlib.sha256).digest()
        got      = hmac_sha256_port(key, msg)
        self.assertEqual(got, expected,
            f"HMAC mismatch\n key={key!r}\n msg={msg!r}")

    def test_rfc4231_case1(self):
        # RFC 4231 test case 1
        self._check(b"\x0b" * 20, b"Hi There")

    def test_rfc4231_case2(self):
        self._check(b"Jefe", b"what do ya want for nothing?")

    def test_empty_msg(self):
        self._check(b"key", b"")

    def test_empty_key(self):
        self._check(b"", b"data")

    def test_long_msg(self):
        self._check(b"some-key", b"A" * 200)

    def test_domain_separator(self):
        # The exact key used in production
        self._check(HMAC_KEY, b"the entropy pool")

    def test_block_size_msg(self):
        # Msg length forces multi-block compression in inner & outer hashes
        self._check(b"k", b"x" * 64)


class TestPackBits(unittest.TestCase):
    """Verify the bit-packing port matches the C implementation byte-for-byte."""

    def test_empty(self):
        self.assertEqual(pack_bits([]), b"")

    def test_one_bit_set(self):
        # Bit 0 is the MSB of the first output byte
        self.assertEqual(pack_bits([1]), b"\x80")
        self.assertEqual(pack_bits([0]), b"\x00")

    def test_eight_bits_high(self):
        self.assertEqual(pack_bits([1] * 8), b"\xff")

    def test_alternating(self):
        self.assertEqual(pack_bits([1, 0] * 8), b"\xaa\xaa")

    def test_partial_trailing_byte(self):
        # 11 bits: 11111111 111_____  ->  0xFF, 0xE0
        self.assertEqual(pack_bits([1] * 11), b"\xff\xe0")

    def test_128_bits(self):
        # 128 alternating bits -> 16 bytes of 0xAA
        self.assertEqual(pack_bits([1, 0] * 64), b"\xaa" * 16)

    def test_only_low_bit_used(self):
        # The C version masks input with `& 1`:
        # 0xFF&1=1, 0x02&1=0, 0x01&1=1, 0x00&1=0  ->  bits 1010 1010 1010 1010
        self.assertEqual(pack_bits([0xFF, 0x02, 0x01, 0x00] * 2), b"\xaa")


class TestPoolDerivation(unittest.TestCase):
    """
    Verify the pool->mnemonic pipeline (HMAC-SHA256 whitening + BIP39).
    These are the exact bytes the on-cart C code will produce for a given pool.
    """

    def test_empty_pool_known_mnemonic(self):
        # Computed with hmac.new(HMAC_KEY, b"", sha256).digest()[:16]
        # Then BIP39-encoded.  This pins the exact derivation behaviour.
        expected_entropy = hmac.new(HMAC_KEY, b"", hashlib.sha256).digest()[:16]
        expected_mnemonic = make_mnemonic(expected_entropy)
        self.assertEqual(derive_from_pool(b""), expected_mnemonic)

    def test_one_byte_pool(self):
        for b in (0x00, 0x55, 0xAA, 0xFF):
            with self.subTest(byte=b):
                expected_entropy = hmac.new(HMAC_KEY, bytes([b]),
                                            hashlib.sha256).digest()[:16]
                self.assertEqual(
                    derive_from_pool(bytes([b])),
                    make_mnemonic(expected_entropy),
                )

    def test_coin_flip_pool(self):
        # Simulate 128 coin flips of all 1s -> 16 bytes of 0xFF
        flips = [1] * 128
        packed = pack_bits(flips)
        self.assertEqual(packed, b"\xff" * 16)
        mn = derive_from_pool(packed)
        self.assertEqual(len(mn), 12)
        for w in mn:
            self.assertIn(w, set(WORDS))

    def test_pool_change_avalanches(self):
        a = derive_from_pool(b"\x00" * 16)
        b = derive_from_pool(b"\x00" * 15 + b"\x01")
        # Single-bit pool change must change every word
        diffs = sum(1 for x, y in zip(a, b) if x != y)
        self.assertGreaterEqual(diffs, 11,
            f"HMAC avalanche too weak: only {diffs}/12 words changed")

    def test_hmac_not_bare_sha(self):
        # Whitening must NOT equal a bare sha256(pool) prefix --
        # otherwise the domain separator key isn't actually being used.
        pool = b"my pool data"
        whitened     = hmac_sha256_port(HMAC_KEY, pool)[:16]
        bare_sha     = sha256_port(pool)[:16]
        self.assertNotEqual(whitened, bare_sha)


class TestMnemonicProperties(unittest.TestCase):
    """Higher-level properties that must hold for any valid mnemonic."""

    def test_always_12_words(self):
        import os
        for _ in range(50):
            mn = make_mnemonic(os.urandom(16))
            self.assertEqual(len(mn), 12)

    def test_all_words_in_wordlist(self):
        import os
        word_set = set(WORDS)
        for _ in range(50):
            mn = make_mnemonic(os.urandom(16))
            for w in mn:
                self.assertIn(w, word_set, f"Unknown word: {w!r}")

    def test_deterministic(self):
        ent = bytes.fromhex("9e885d952ad362caeb4efe34a8e91bd2")
        self.assertEqual(make_mnemonic(ent), make_mnemonic(ent))

    def test_different_entropy_different_mnemonic(self):
        a = make_mnemonic(bytes(16))
        b = make_mnemonic(bytes([0xFF] * 16))
        self.assertNotEqual(a, b)


if __name__ == "__main__":
    result = unittest.main(verbosity=2, exit=False)
    sys.exit(0 if result.result.wasSuccessful() else 1)
