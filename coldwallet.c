/*
 * GB COLD WALLET
 *
 *   A Bitcoin BIP39 12-word seed generator that runs on a real Game Boy.
 *   The world's most air-gapped (and slowest) crypto seed generator.
 *
 *   Built with GBDK-2020 4.5.0.
 *
 *   ENTROPY SOURCES
 *   ---------------
 *   Two independent collection modes are offered:
 *
 *     BUTTON MODE (A on title)
 *       100 button presses.  At every press edge -- detected in a tight
 *       polling loop, NOT a vblank wait -- we sample:
 *           DIV_REG   (8-bit, increments at 16384 Hz)
 *           TIMA_REG  (8-bit, configured at 262144 Hz)
 *           LY_REG    (8-bit scanline counter, ~9.2 kHz)
 *           the pad bitmask
 *       Press timing is therefore resolved to ~16 CPU cycles, not the
 *       17 ms vblank quantum.
 *
 *     COIN MODE (SELECT on title)
 *       128 D-pad flips (Up = 1, Down = 0).  Provides 128 directly
 *       observable, hardware-RNG-free entropy bits independent of any
 *       timing assumptions -- the gold standard for paper wallets.
 *
 *   WHITENING
 *   ---------
 *   The pool is run through HMAC-SHA256 with a fixed domain-separator
 *   key ("GB-COLDWALLET-BIP39-entropy"), and the first 16 bytes are
 *   used as 128-bit BIP39 entropy.  HMAC -- not bare SHA-256 -- guards
 *   against length-extension and is standard practice (RFC 5869 style).
 *
 *   THIS IS A NOVELTY. DO NOT FUND THE GENERATED SEED.
 *   The GB has no side-channel protection.
 */

#include <gb/gb.h>
#include <gbdk/console.h>
#include <stdio.h>
#include <string.h>

#include "bip39_words.h"  /* defines BIP39_SLOT and bip39_words[] */

/* ====================================================================
 *  SHA-256
 * ==================================================================== */

typedef struct {
    uint32_t state[8];
    uint32_t bitlen;
    uint8_t  buf[64];
    uint8_t  buflen;
} sha_ctx;

static const uint32_t K[64] = {
    0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,
    0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
    0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,
    0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
    0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,
    0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
    0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,
    0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
    0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,
    0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
    0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,
    0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
    0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,
    0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
    0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,
    0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

static uint32_t rotr32(uint32_t x, uint8_t n) {
    return (x >> n) | (x << (32 - n));
}

static void sha_compress(sha_ctx *c) {
    uint32_t w[64];
    uint32_t a, b, cc, d, e, f, g, h;
    uint32_t t1, t2, s0, s1, ch, mj;
    uint8_t i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)c->buf[i*4    ] << 24) |
               ((uint32_t)c->buf[i*4 + 1] << 16) |
               ((uint32_t)c->buf[i*4 + 2] <<  8) |
               ((uint32_t)c->buf[i*4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        s0 = rotr32(w[i-15], 7) ^ rotr32(w[i-15], 18) ^ (w[i-15] >> 3);
        s1 = rotr32(w[i- 2],17) ^ rotr32(w[i- 2], 19) ^ (w[i- 2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    a = c->state[0]; b = c->state[1]; cc = c->state[2]; d = c->state[3];
    e = c->state[4]; f = c->state[5]; g  = c->state[6]; h = c->state[7];

    for (i = 0; i < 64; i++) {
        s1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        ch = (e & f) ^ ((~e) & g);
        t1 = h + s1 + ch + K[i] + w[i];
        s0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        mj = (a & b) ^ (a & cc) ^ (b & cc);
        t2 = s0 + mj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }

    c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
    c->state[4] += e; c->state[5] += f; c->state[6] += g;  c->state[7] += h;
}

void sha_init(sha_ctx *c) {
    c->state[0] = 0x6a09e667UL; c->state[1] = 0xbb67ae85UL;
    c->state[2] = 0x3c6ef372UL; c->state[3] = 0xa54ff53aUL;
    c->state[4] = 0x510e527fUL; c->state[5] = 0x9b05688cUL;
    c->state[6] = 0x1f83d9abUL; c->state[7] = 0x5be0cd19UL;
    c->bitlen = 0;
    c->buflen = 0;
}

void sha_update(sha_ctx *c, const uint8_t *data, uint16_t len) {
    uint16_t i;
    for (i = 0; i < len; i++) {
        c->buf[c->buflen++] = data[i];
        if (c->buflen == 64) {
            sha_compress(c);
            c->bitlen += 512;
            c->buflen = 0;
        }
    }
}

void sha_final(sha_ctx *c, uint8_t *out) {
    uint8_t i;
    uint32_t bits;

    c->bitlen += (uint32_t)c->buflen * 8;
    c->buf[c->buflen++] = 0x80;

    if (c->buflen > 56) {
        while (c->buflen < 64) c->buf[c->buflen++] = 0;
        sha_compress(c);
        c->buflen = 0;
    }
    while (c->buflen < 56) c->buf[c->buflen++] = 0;

    bits = c->bitlen;
    c->buf[56] = 0; c->buf[57] = 0; c->buf[58] = 0; c->buf[59] = 0;
    c->buf[60] = (uint8_t)(bits >> 24);
    c->buf[61] = (uint8_t)(bits >> 16);
    c->buf[62] = (uint8_t)(bits >>  8);
    c->buf[63] = (uint8_t)(bits);
    sha_compress(c);

    for (i = 0; i < 8; i++) {
        out[i*4    ] = (uint8_t)(c->state[i] >> 24);
        out[i*4 + 1] = (uint8_t)(c->state[i] >> 16);
        out[i*4 + 2] = (uint8_t)(c->state[i] >>  8);
        out[i*4 + 3] = (uint8_t)(c->state[i]);
    }
}

/* ====================================================================
 *  HMAC-SHA256  (RFC 2104)
 *
 *  Block size = 64 bytes.  Key must be shorter than 64 bytes; the only
 *  caller passes a fixed compile-time string.
 * ==================================================================== */

void hmac_sha256(const uint8_t *key, uint8_t klen,
                 const uint8_t *msg, uint16_t mlen,
                 uint8_t *out)
{
    uint8_t block[64];
    uint8_t inner[32];
    sha_ctx c;
    uint8_t i;

    /* ipad */
    for (i = 0; i < 64; i++) block[i] = 0x36;
    for (i = 0; i < klen; i++) block[i] ^= key[i];

    sha_init(&c);
    sha_update(&c, block, 64);
    sha_update(&c, msg, mlen);
    sha_final(&c, inner);

    /* opad */
    for (i = 0; i < 64; i++) block[i] = 0x5c;
    for (i = 0; i < klen; i++) block[i] ^= key[i];

    sha_init(&c);
    sha_update(&c, block, 64);
    sha_update(&c, inner, 32);
    sha_final(&c, out);
}

/* Domain-separator key for HMAC-SHA256 pool whitening. */
static const uint8_t HMAC_KEY[] = "GB-COLDWALLET-BIP39-entropy";
#define HMAC_KEY_LEN (sizeof(HMAC_KEY) - 1)

/* ====================================================================
 *  ENTROPY POOL
 * ==================================================================== */

uint8_t pool[64];
uint8_t pool_len;

void pool_reset(void) { pool_len = 0; }

void pool_byte(uint8_t b) {
    if (pool_len >= sizeof pool) {
        sha_ctx c;
        uint8_t out[32];
        uint8_t i;
        sha_init(&c);
        sha_update(&c, pool, pool_len);
        sha_update(&c, &b, 1);
        sha_final(&c, out);
        for (i = 0; i < 32; i++) pool[i] = out[i];
        pool_len = 32;
    } else {
        pool[pool_len++] = b;
    }
}

/* Sample every available cheap entropy source.  Called at the exact
   moment a press edge is observed, inside the tight polling loop. */
void mix_press(uint8_t evt) {
    pool_byte(DIV_REG);
    pool_byte(TIMA_REG);
    pool_byte(LY_REG);
    pool_byte(evt);
}

/* ====================================================================
 *  BIP39
 *
 *   - 128 bits entropy (16 bytes)
 *   - checksum = first 4 bits of SHA-256(entropy)
 *   - 132 bits total -> 12 words of 11 bits each
 *   - lookup in 2048-word English wordlist
 * ==================================================================== */

uint16_t mnemonic[12];

/* Extract 11 bits at bit offset off from src (big-endian bit order). */
uint16_t extract11(const uint8_t *src, uint16_t off) {
    uint16_t byte_off = off >> 3;
    uint8_t  bit_off  = (uint8_t)(off & 7);
    uint32_t v = ((uint32_t)src[byte_off]     << 16) |
                 ((uint32_t)src[byte_off + 1] <<  8) |
                  (uint32_t)src[byte_off + 2];
    v >>= (24 - 11 - bit_off);
    return (uint16_t)(v & 0x7FF);
}

/* Pack nbits 0/1 input bytes (MSB first) into ceil(nbits/8) output bytes. */
void pack_bits(const uint8_t *bits, uint16_t nbits, uint8_t *out) {
    uint16_t i;
    uint8_t  acc = 0;
    uint8_t  n   = 0;
    uint16_t o   = 0;
    for (i = 0; i < nbits; i++) {
        acc = (uint8_t)((acc << 1) | (bits[i] & 1));
        n++;
        if (n == 8) { out[o++] = acc; acc = 0; n = 0; }
    }
    if (n) out[o] = (uint8_t)(acc << (8 - n));
}

/* Build the 12-word mnemonic from the current `pool` via HMAC-SHA256. */
void make_mnemonic(void) {
    uint8_t ent[20];   /* 16 entropy + 1 checksum + 3 byte read-ahead pad */
    uint8_t hash[32];
    uint8_t cs[32];
    sha_ctx c;
    uint8_t i;

    for (i = 0; i < 20; i++) ent[i] = 0;

    /* Whiten the pool with HMAC-SHA256 keyed by the domain separator. */
    hmac_sha256(HMAC_KEY, HMAC_KEY_LEN, pool, pool_len, hash);
    for (i = 0; i < 16; i++) ent[i] = hash[i];

    /* checksum = top 4 bits of SHA-256(entropy) */
    sha_init(&c);
    sha_update(&c, ent, 16);
    sha_final(&c, cs);
    ent[16] = cs[0];

    for (i = 0; i < 12; i++) {
        mnemonic[i] = extract11(ent, (uint16_t)i * 11);
    }
}

const char *word_at(uint16_t idx) {
    return &bip39_words[idx * BIP39_SLOT];
}

/* ====================================================================
 *  UI
 * ==================================================================== */

#define BTN_PRESSES 100
#define COIN_FLIPS  128

void clrscr(void) {
    uint8_t y;
    for (y = 0; y < 17; y++) { gotoxy(0, y); printf("                    "); }
    gotoxy(0, 17); printf("                   ");
    gotoxy(0, 0);
}

void wait_for(uint8_t mask) {
    waitpadup();
    while (!(joypad() & mask)) wait_vbl_done();
    waitpadup();
}

/* Returns the chosen mode: J_A (button) or J_SELECT (coin). */
uint8_t title_screen(void) {
    uint8_t pad;
    clrscr();
    gotoxy(2, 1);  printf("GB COLD WALLET");
    gotoxy(2, 2);  printf("BITCOIN  SEED");
    gotoxy(0, 4);  printf("12-word seed,");
    gotoxy(0, 5);  printf("HMAC-SHA256");
    gotoxy(0, 6);  printf("whitened entropy.");
    gotoxy(0, 8);  printf("A   = button");
    gotoxy(0, 9);  printf("      timing");
    gotoxy(0, 10); printf("      (100x)");
    gotoxy(0, 12); printf("SEL = coin flip");
    gotoxy(0, 13); printf("      Up=1 Dn=0");
    gotoxy(0, 14); printf("      (128x)");
    gotoxy(0, 17); printf(" CHOOSE A MODE");

    waitpadup();
    while (1) {
        pad = joypad();
        if (pad & J_A)      { waitpadup(); return J_A; }
        if (pad & J_SELECT) { waitpadup(); return J_SELECT; }
        wait_vbl_done();
    }
}

/* Button-timing entropy: tight polling loop, samples DIV/TIMA/LY at the
   exact moment of each press edge -- no vblank quantisation. */
void entropy_button(void) {
    uint16_t taps = 0;
    uint8_t  pad, prev = 0xFF;
    uint8_t  bar, i;

    pool_reset();
    /* Boot-time noise (weak; HMAC will whiten regardless). */
    for (i = 0; i < 8; i++) {
        pool_byte(DIV_REG);
        pool_byte(TIMA_REG);
    }

    clrscr();
    gotoxy(0, 0); printf(" GATHERING ENTROPY");
    gotoxy(0, 2); printf("Mash any button.");
    gotoxy(0, 3); printf("100 presses needed");
    gotoxy(0, 5); printf("DIV+TIMA+LY are");
    gotoxy(0, 6); printf("sampled at every");
    gotoxy(0, 7); printf("press edge inside");
    gotoxy(0, 8); printf("a tight poll loop.");
    gotoxy(0, 14); printf("[                  ]");

    /* TIGHT LOOP -- no wait_vbl_done: every iteration touches DIV
       so the sampled byte is unpredictable to ~16 CPU cycles. */
    while (taps < BTN_PRESSES) {
        pad = joypad();
        if (pad && pad != prev) {
            mix_press(pad);
            taps++;
            bar = (uint8_t)((taps * 18) / BTN_PRESSES);
            gotoxy(1, 14);
            for (i = 0; i < 18; i++) printf("%c", i < bar ? '*' : ' ');
            gotoxy(0, 16); printf("Presses: %u/%u   ",
                                  taps, (uint16_t)BTN_PRESSES);
        }
        prev = pad;
        /* Spin-sample DIV: this is the entire point of the tight loop. */
        pool_byte(DIV_REG);
    }
    gotoxy(0, 17); printf(" HASHING...        ");
}

/* Coin-flip entropy: D-pad Up=1, Down=0.  128 bits packed directly. */
void entropy_coin(void) {
    uint8_t  bits[COIN_FLIPS];
    uint8_t  packed[16];
    uint16_t got = 0;
    uint8_t  pad, prev = 0xFF;
    uint8_t  bar, i;

    clrscr();
    gotoxy(0, 0); printf("  COIN-FLIP MODE");
    gotoxy(0, 2); printf("D-pad UP   = 1");
    gotoxy(0, 3); printf("D-pad DOWN = 0");
    gotoxy(0, 4); printf("B = undo last");
    gotoxy(0, 6); printf("Use a real coin");
    gotoxy(0, 7); printf("or dice for true");
    gotoxy(0, 8); printf("128-bit entropy.");
    gotoxy(0, 14); printf("[                  ]");

    while (got < COIN_FLIPS) {
        pad = joypad();
        if (pad && pad != prev) {
            if (pad & J_UP)                  { bits[got++] = 1; }
            else if (pad & J_DOWN)           { bits[got++] = 0; }
            else if ((pad & J_B) && got > 0) { got--; }

            bar = (uint8_t)((got * 18) / COIN_FLIPS);
            gotoxy(1, 14);
            for (i = 0; i < 18; i++) printf("%c", i < bar ? '*' : ' ');
            gotoxy(0, 16); printf("Flips: %u/%u    ",
                                  got, (uint16_t)COIN_FLIPS);
            gotoxy(0, 17); printf(" LAST: %c          ",
                                  got ? (bits[got-1] ? '1' : '0') : ' ');
        }
        prev = pad;
        wait_vbl_done();
    }

    /* Pack 128 bits into 16 bytes; load directly into the pool so the
       HMAC step still runs and gives uniform domain-separated output. */
    pack_bits(bits, COIN_FLIPS, packed);
    pool_reset();
    for (i = 0; i < 16; i++) pool_byte(packed[i]);
    gotoxy(0, 17); printf(" HASHING...        ");
}

void show_seed(void) {
    uint8_t i;

    clrscr();
    gotoxy(2, 0); printf("YOUR 12-WORD SEED");

    for (i = 0; i < 6; i++) {
        gotoxy(0, 2 + i);
        printf("%u.%s", (uint16_t)(i + 1), word_at(mnemonic[i]));

        gotoxy(10, 2 + i);
        printf("%u.%s", (uint16_t)(i + 7), word_at(mnemonic[i + 6]));
    }

    gotoxy(0, 10); printf("Write these down");
    gotoxy(0, 11); printf("on PAPER. Order");
    gotoxy(0, 12); printf("matters. Spelling");
    gotoxy(0, 13); printf("matters. Never");
    gotoxy(0, 14); printf("type them online.");

    gotoxy(0, 16); printf("SEL=NEW STRT=info");
}

void info_screen(void) {
    clrscr();
    gotoxy(4, 0); printf("== INFO ==");
    gotoxy(0, 2); printf("BIP39 mnemonic:");
    gotoxy(0, 3); printf("128b entropy + 4b");
    gotoxy(0, 4); printf("SHA-256 checksum");
    gotoxy(0, 5); printf("= 132b / 11 = 12");
    gotoxy(0, 6); printf("words from 2048-");
    gotoxy(0, 7); printf("word English list.");
    gotoxy(0, 9); printf("Pool whitened by");
    gotoxy(0, 10); printf("HMAC-SHA256, key:");
    gotoxy(0, 11); printf("GB-COLDWALLET");
    gotoxy(0, 13); printf("Compatible with:");
    gotoxy(0, 14); printf("Electrum, Trezor,");
    gotoxy(0, 15); printf("Sparrow, Ledger.");
    gotoxy(0, 17); printf(" PRESS B TO RETURN");
    wait_for(J_B);
}

/* ====================================================================
 *  MAIN
 * ==================================================================== */

void main(void) {
    DISPLAY_ON;
    SHOW_BKG;

    /* Enable TIMA hardware timer at 262144 Hz.
       TAC bits: 0b101 = enable + clock-select 01 (262144 Hz on DMG). */
    TMA_REG = 0;
    TAC_REG = 0x05;

    while (1) {
        uint8_t mode = title_screen();
        if (mode == J_A) entropy_button();
        else             entropy_coin();

        make_mnemonic();
        show_seed();

        while (1) {
            uint8_t pad;
            waitpadup();
            while (!(pad = joypad())) wait_vbl_done();
            if (pad & J_SELECT) { waitpadup(); break; }
            if (pad & J_START)  { info_screen(); show_seed(); }
        }
    }
}
