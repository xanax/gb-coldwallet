# GB Cold Wallet (BTC)

A Bitcoin BIP39 seed phrase generator that runs on a real Game Boy — the world's most air-gapped seed generator.

Built with [GBDK-2020](https://github.com/gbdk-2020/gbdk-2020), tested on an Anbernic RG35XX H.

## What it does

1. **Entropy collection** — you mash buttons 64 times. Each press is mixed with the hardware `DIV` timer register and the system tick counter, creating a pool of unpredictable bytes that no software can observe or reproduce.
2. **Key derivation** — SHA-256 (full textbook implementation, no external library) finalises the entropy pool and produces a 4-bit BIP39 checksum.
3. **Mnemonic display** — 12 BIP39 English words are shown across two columns. The complete 2048-word wordlist is burned into the ROM itself.

The resulting phrase is a valid BIP39 128-bit seed compatible with any standard wallet (Electrum, Trezor, Ledger, Sparrow, etc.).

## Controls

| Button | Action |
|---|---|
| Any button | Contribute entropy during collection phase |
| **SELECT** | Generate a new seed (from the seed display screen) |
| **START** | Show info / algorithm details |
| **A** | Advance / confirm |

## Security model

- The ROM has no networking, no storage, no radio. Entropy never leaves the chip.
- The hardware `DIV` register is an 8-bit counter clocked at ~16 kHz, unrelated to your button timing, providing high-quality mixing entropy.
- SHA-256 is implemented from the FIPS 180-4 specification — no third-party code.
- The BIP39 wordlist is embedded read-only in ROM.

## Algorithm

```
128 bits entropy
  └─ SHA-256(entropy)[0] >> 4  →  4-bit checksum
       └─ 132 bits total  →  12 × 11-bit indices  →  12 BIP39 words
```

Verified against all official [BIP39 test vectors](https://github.com/trezor/python-mnemonic/blob/master/vectors.json) — see `test_coldwallet.py`.

## Files

| File | Description |
|---|---|
| `coldwallet.c` | Full ROM source (SHA-256, BIP39, UI) |
| `bip39_words.h` | 2048-word English wordlist, generated from the official BIP39 list |
| `coldwallet.gb` | Pre-built ROM (32 KB) — load into any GB emulator or flash to cart |
| `test_coldwallet.py` | Python test suite: 31 tests covering SHA-256, `extract11`, all 5 official BIP39 vectors |

## Build

Requires GBDK-2020 v4.3+ at `$GBDK` (default: `/e/Games/gbdk/gbdk`).

```bash
# from the parent gameboy/ directory
./build.sh coldwallet

# or directly
lcc -DMSYS -DCPU_GB -o coldwallet.gb coldwallet.c
```

## Tests

```bash
python test_coldwallet.py
# Ran 31 tests in ~4s — OK
```

## Wordlist generation

If you need to regenerate `bip39_words.h` from the raw wordlist:

```python
# python/bip39_words.py  (in the parent EverythingApp project)
```

## Toolchain

| Tool | Version |
|---|---|
| GBDK-2020 | 4.5.0 |
| Target hardware | Anbernic RG35XX H |
| ROM size | 32 KB (MBC-less) |
