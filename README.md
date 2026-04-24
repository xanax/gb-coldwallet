# GB Cold Wallet (BTC)

A Bitcoin BIP39 seed phrase generator that runs on a real Game Boy — the world's most air-gapped seed generator.

Built with [GBDK-2020](https://github.com/gbdk-2020/gbdk-2020), tested on an Anbernic RG35XX H.

## What it does

1. **Entropy collection** — choose one of two modes on the title screen:
   - **Button mode** (`A`) — 100 button presses. At every press edge, sampled inside a *tight polling loop* (no `wait_vbl_done`), we mix in `DIV_REG`, `TIMA_REG`, `LY_REG` and the pad bitmask. Press timing is resolved to ~16 CPU cycles, not the 17 ms vblank quantum.
   - **Coin-flip mode** (`SELECT`) — 128 D-pad flips (Up = 1, Down = 0, B = undo). 128 directly-observable hardware-RNG-free entropy bits, packed straight into the pool. Use a real coin or dice for the gold-standard paper-wallet workflow.
2. **Whitening** — the entropy pool is run through **HMAC-SHA256** (RFC 2104) with the fixed domain-separator key `GB-COLDWALLET-v2-BIP39-entropy`. The first 16 bytes become the 128-bit BIP39 entropy. HMAC — not bare SHA-256 — guards against length-extension and is standard practice.
3. **Key derivation** — full FIPS 180-4 SHA-256 (no library) computes the 4-bit BIP39 checksum.
4. **Mnemonic display** — 12 BIP39 English words shown across two columns. The complete 2048-word wordlist is burned into the ROM itself.

The resulting phrase is a valid BIP39 128-bit seed compatible with any standard wallet (Electrum, Trezor, Ledger, Sparrow, etc.).

## Controls

### Title screen

| Button | Action |
|---|---|
| **A** | Start button-timing entropy mode (100 presses) |
| **SELECT** | Start coin-flip entropy mode (128 D-pad flips) |

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

## Security model

- The ROM has no networking, no storage, no radio. Entropy never leaves the chip.
- **Tight-loop sampling** of `DIV_REG` resolves press timing to ~16 CPU cycles (~1 µs) rather than the 17 ms frame quantum, gaining ~8 extra bits per press over the v1 design.
- **TIMA_REG** is enabled at 262 144 Hz at boot and sampled at every press edge as an independent timing source.
- **`LY_REG`** (current scanline, ~9.2 kHz) is also mixed in — three orthogonal hardware counters per press.
- **HMAC-SHA256 whitening** with a domain-separator key prevents length-extension and ensures the output is uniform even when the raw pool has biases.
- **Coin-flip mode** removes all timing assumptions: 128 user-chosen bits go straight into the pool.
- SHA-256 is implemented from the FIPS 180-4 specification — no third-party code.
- The BIP39 wordlist is embedded read-only in ROM.

## Algorithm

```
entropy pool (DIV+TIMA+LY+pad samples, OR 128 packed coin flips)
  └─ HMAC-SHA256(key="GB-COLDWALLET-v2-BIP39-entropy", msg=pool)
       └─ first 16 bytes  →  128 bits BIP39 entropy
            └─ SHA-256(entropy)[0] >> 4  →  4-bit checksum
                 └─ 132 bits  →  12 × 11-bit indices  →  12 BIP39 words
```

Verified against all official [BIP39 test vectors](https://github.com/trezor/python-mnemonic/blob/master/vectors.json) and [RFC 4231 HMAC-SHA256 test vectors](https://datatracker.ietf.org/doc/html/rfc4231) — see [test_coldwallet.py](test_coldwallet.py).

## Files

| File | Description |
|---|---|
| `coldwallet.c` | Full ROM source (SHA-256, HMAC-SHA256, BIP39, two entropy modes, UI) |
| `bip39_words.h` | 2048-word English wordlist, generated from the official BIP39 list |
| `coldwallet.gb` | Pre-built ROM (32 KB) — load into any GB emulator or flash to cart |
| `test_coldwallet.py` | Python test suite: 50 tests covering SHA-256, HMAC-SHA256 (RFC 4231), `extract11`, `pack_bits`, the pool→mnemonic pipeline, and all 5 official BIP39 vectors |

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
# Ran 50 tests in ~4s — OK
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
