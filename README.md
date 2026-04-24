# GB Cold Wallet

> **Generate a real Bitcoin BIP39 seed phrase on a 1989 Game Boy.**
> No network. No storage. No radio. No batteries (well, four AAs).
> The world's most air-gapped Bitcoin seed generator.

![ROM size](https://img.shields.io/badge/ROM-32%20KB-informational)
![Tests](https://img.shields.io/badge/tests-50%20passing-brightgreen)
![BIP39](https://img.shields.io/badge/BIP39-RFC%204231%20HMAC--SHA256-blue)
![Toolchain](https://img.shields.io/badge/built%20with-GBDK--2020-yellow)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Why

Modern hardware wallets are black boxes. They have firmware update channels,
USB stacks, secure elements with vendor blobs, and supply chains you cannot
audit. A grey 1989 plastic brick has none of those things — and you can read
the *entire* schematic on Wikipedia.

This ROM is a Bitcoin BIP39 seed phrase generator. It runs on a real Game Boy.
You read the 12 words off the screen, write them on paper, and pull the
cartridge. The seed never touches a CPU made after the Berlin Wall came down.

The output is a standards-compliant BIP39 mnemonic — drop the 12 words into
[Electrum](https://electrum.org/), [Sparrow](https://sparrowwallet.com/),
[Trezor Suite](https://trezor.io/trezor-suite), or any other wallet and you
have a fundable Bitcoin address.

## Quick start

1. Grab [`coldwallet.gb`](coldwallet.gb) (32 KB, MBC-less).
2. Either:
   - Open it in any GB emulator (BGB, SameBoy, mGBA, RetroArch, Anbernic
     handhelds, ...), or
   - Flash it to a real cartridge (e.g. EverDrive GB).
3. On the title screen, choose your entropy source:
   - **A** — 100 button-press timing samples, or
   - **SELECT** — 128 D-pad coin flips (`Up` = 1, `Down` = 0, `B` = undo).
4. Read the 12 words. Write them on paper. Power off.

## How it works

```
entropy pool  (DIV + TIMA + LY + pad samples,  OR  128 packed coin flips)
   |
   |  HMAC-SHA256(key = "GB-COLDWALLET-BIP39-entropy", msg = pool)
   v
first 16 bytes  =  128-bit BIP39 entropy
   |
   |  SHA-256(entropy)[0] >> 4
   v
4-bit BIP39 checksum  ->  132 bits  ->  12 x 11-bit indices  ->  12 BIP39 words
```

Two completely independent entropy modes:

| Mode | Source | Bits | Notes |
|---|---|---|---|
| **Button** | DIV_REG, TIMA_REG, LY_REG and pad bitmask sampled at every press edge in a tight polling loop | 100 presses x 4 byte samples | Press timing resolved to ~16 CPU cycles (~1 us), not the 17 ms vblank quantum. Three orthogonal hardware counters per press. |
| **Coin flip** | User D-pad input, 1 bit per press | 128 directly observable bits | No timing assumptions at all. Use a real coin or dice for a paper-wallet-grade workflow. |

The pool is whitened through **HMAC-SHA256** (RFC 2104) with a fixed
domain-separator key. HMAC — not bare SHA-256 — protects against
length-extension and ensures the output is uniform even when the raw pool
has biases.

The SHA-256 implementation is written from the FIPS 180-4 specification.
There is no third-party crypto code in the ROM.

## Security model

- **No networking, no storage, no radio.** Entropy never leaves the chip.
- **No firmware update channel.** What you flash is what you get.
- **Tight-loop sampling** of `DIV_REG` resolves press timing to ~16 CPU
  cycles, gaining ~8 extra bits of timing entropy per press over a naive
  vblank-quantised sampler.
- **TIMA_REG** is enabled at 262 144 Hz at boot and sampled at every press
  edge as an independent timing source.
- **`LY_REG`** (current scanline, ~9.2 kHz) is mixed in as a third
  orthogonal hardware counter per press.
- **HMAC-SHA256 whitening** with a domain-separator key prevents
  length-extension and ensures uniform output even from a biased pool.
- **Coin-flip mode** removes all timing assumptions: 128 user-chosen bits
  go straight into the pool.
- **2048-word BIP39 English wordlist** is embedded read-only in ROM.

> The Game Boy has no side-channel countermeasures. This is a fun,
> auditable seed generator. Generate funded keys at your own risk and
> use a real cold-storage workflow (write phrase on paper, never type it).

## Controls

### Title screen
| Button | Action |
|---|---|
| **A** | Button-timing entropy mode (100 presses) |
| **SELECT** | Coin-flip entropy mode (128 D-pad flips) |

### Coin-flip mode
| Button | Action |
|---|---|
| **Up** | Flip = 1 |
| **Down** | Flip = 0 |
| **B** | Undo last flip |

### Seed display
| Button | Action |
|---|---|
| **SELECT** | Generate a new seed (returns to title) |
| **START** | Show info / algorithm details |

## Tests

```bash
python test_coldwallet.py
# Ran 50 tests in ~4s -- OK
```

The test suite covers:

- Full SHA-256 (FIPS 180-4) against the standard vectors.
- HMAC-SHA256 against all five [RFC 4231](https://datatracker.ietf.org/doc/html/rfc4231) vectors.
- The C `extract11` and `pack_bits` bit-twiddling primitives.
- The complete pool -> mnemonic pipeline (the same key the ROM uses).
- All five official [BIP39 test vectors](https://github.com/trezor/python-mnemonic/blob/master/vectors.json) (12-word entries).

## Files

| File | Description |
|---|---|
| [`coldwallet.c`](coldwallet.c) | Full ROM source: SHA-256, HMAC-SHA256, BIP39, two entropy modes, UI |
| [`bip39_words.h`](bip39_words.h) | 2048-word English wordlist, generated from the official BIP39 list |
| [`coldwallet.gb`](coldwallet.gb) | Pre-built ROM (32 KB) |
| [`test_coldwallet.py`](test_coldwallet.py) | Python test suite (50 tests) |

## Build from source

Requires [GBDK-2020](https://github.com/gbdk-2020/gbdk-2020) v4.3+.

```bash
# from the parent gameboy/ directory
./build.sh coldwallet

# or directly
lcc -DMSYS -DCPU_GB -o coldwallet.gb coldwallet.c
```

## Toolchain

| Tool | Version |
|---|---|
| GBDK-2020 | 4.5.0 |
| Tested hardware | Anbernic RG35XX H, BGB, SameBoy |
| ROM size | 32 KB (MBC-less) |

## License

MIT. Use it, audit it, fork it, mirror it.

## Disclaimer

This is a hobby project. The author makes no guarantees about the
suitability of the generated seeds for storing real value. If you do use
this for real Bitcoin, follow normal cold-storage hygiene: generate offline,
write the phrase on paper, verify the phrase imports cleanly into a known
wallet **using a small test deposit first**, store the paper securely, and
wipe the cartridge.
