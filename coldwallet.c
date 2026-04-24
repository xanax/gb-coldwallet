/*
 * GB COLD WALLET  --  BIP39 12-word edition
 *
 *   The world's most air-gapped (and slowest) crypto seed generator.
 *
 *   Built with GBDK-2020 4.5.0.
 *
 *   - Harvests entropy from joypad input timings + DIV register + sys_time
 *   - Runs real SHA-256 on the Game Boy CPU (DMG, ~4 MHz)
 *   - Produces a valid BIP39 12-word English mnemonic seed
 *     (128 bits entropy + 4-bit SHA-256 checksum)
 *
 *   THIS IS A NOVELTY. DO NOT FUND THE GENERATED SEED.
 *   The GB has weak entropy and zero side-channel protection.
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
 *  ENTROPY POOL
 *
 *  Mix 64 user button-press events with DIV + sys_time, hashed
 *  through SHA-256.  Output: 16-byte (128-bit) entropy.
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

void mix_tick(uint8_t evt) {
    pool_byte(DIV_REG);
    pool_byte((uint8_t)sys_time);
    pool_byte((uint8_t)(sys_time >> 8));
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
    /* 24 bits in v; we want bits [bit_off .. bit_off+10] from the top. */
    v >>= (24 - 11 - bit_off);
    return (uint16_t)(v & 0x7FF);
}

void make_mnemonic(void) {
    uint8_t ent[20];   /* 16 entropy + 1 checksum + 3 byte read-ahead pad */
    uint8_t hash[32];
    uint8_t cs[32];
    sha_ctx c;
    uint8_t i;

    for (i = 0; i < 20; i++) ent[i] = 0;

    /* finalize entropy pool -> 32-byte hash, take first 16 as entropy */
    sha_init(&c);
    sha_update(&c, pool, pool_len);
    sha_final(&c, hash);
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

void title_screen(void) {
    clrscr();
    gotoxy(2, 1);  printf("GB COLD WALLET");
    gotoxy(3, 2);  printf("BIP39  EDITION");
    gotoxy(0, 4);  printf("12-word seed");
    gotoxy(0, 5);  printf("phrase generator");
    gotoxy(0, 6);  printf("on a Game Boy.");
    gotoxy(0, 8);  printf("128 bits entropy");
    gotoxy(0, 9);  printf("+ SHA-256 csum,");
    gotoxy(0, 10); printf("English wordlist");
    gotoxy(0, 11); printf("burned into ROM.");
    gotoxy(0, 17); printf(" PRESS A TO BEGIN");
    wait_for(J_A);
}

void entropy_screen(void) {
    uint8_t taps = 0;
    uint8_t pad, prev = 0xFF;
    uint8_t bar, i;

    pool_reset();
    for (i = 0; i < 8; i++) {
        pool_byte(DIV_REG);
        pool_byte((uint8_t)sys_time);
    }

    clrscr();
    gotoxy(0, 0); printf(" GATHERING ENTROPY");
    gotoxy(0, 2); printf("Mash any button.");
    gotoxy(0, 3); printf("64 presses needed.");
    gotoxy(0, 5); printf("Each press samples");
    gotoxy(0, 6); printf("the DIV timer for");
    gotoxy(0, 7); printf("randomness.");
    gotoxy(0, 14); printf("[                  ]");

    while (taps < 64) {
        pad = joypad();
        if (pad && pad != prev) {
            mix_tick(pad);
            taps++;
            bar = (uint8_t)((uint16_t)taps * 18 / 64);
            gotoxy(1, 14);
            for (i = 0; i < 18; i++) printf("%c", i < bar ? '*' : ' ');
            gotoxy(0, 16); printf("Presses: %u/64   ", taps);
        }
        prev = pad;
        wait_vbl_done();
    }
    gotoxy(0, 17); printf(" HASHING...        ");
    for (i = 0; i < 16; i++) mix_tick(i ^ taps);
}

void show_seed(void) {
    uint8_t i;

    clrscr();
    gotoxy(2, 0); printf("YOUR 12-WORD SEED");

    /* Two columns of 6 words.  Use gotoxy per column; no width specifiers
       (GBDK's minimal printf does not support %-Ns for strings). */
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
    gotoxy(0, 6); printf("words from the");
    gotoxy(0, 7); printf("standard 2048-");
    gotoxy(0, 8); printf("word English list.");
    gotoxy(0, 10); printf("Import into any");
    gotoxy(0, 11); printf("BIP39 wallet:");
    gotoxy(0, 12); printf("Electrum, Trezor,");
    gotoxy(0, 13); printf("Sparrow, etc.");
    gotoxy(0, 15); printf("It will work, but");
    gotoxy(0, 16); printf("entropy is weak.");
    gotoxy(0, 17); printf(" PRESS B TO RETURN");
    wait_for(J_B);
}

/* ====================================================================
 *  MAIN
 * ==================================================================== */

void main(void) {
    DISPLAY_ON;
    SHOW_BKG;

    title_screen();

    while (1) {
        entropy_screen();
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
