#include <stdint.h>
#include <string.h>
#include <array>
#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <chrono>

#if defined(_MSC_VER)
#include <intrin.h>
#include <immintrin.h>
#endif

// CPU 能力探测
struct CPUCaps {
    bool pclmul = false; // CLMUL (属于 AES-NI 家族)
    bool aesni = false; 
    bool avx2 = false;
    bool avx512 = false;
    bool avx512vl = false;
    bool vprold = false; // 通过 AVX-512VL 的 _mm_rol_epi32
};

static void cpuid_ex(unsigned leaf, unsigned subleaf, unsigned regs[4]) {
#if defined(_MSC_VER)
    int r[4]; __cpuidex(r, (int)leaf, (int)subleaf);
    regs[0] = (unsigned)r[0]; regs[1] = (unsigned)r[1]; regs[2] = (unsigned)r[2]; regs[3] = (unsigned)r[3];
#else
    (void)leaf; (void)subleaf; regs[0] = regs[1] = regs[2] = regs[3] = 0;
#endif
}

static CPUCaps detect_caps() {
    CPUCaps c;
    unsigned r[4] = { 0,0,0,0 };
    cpuid_ex(1, 0, r);
    c.pclmul = (r[2] & (1u << 1)) != 0;     // PCLMULQDQ
    c.aesni = (r[2] & (1u << 25)) != 0;    // AES
    cpuid_ex(7, 0, r);
    c.avx2 = (r[1] & (1u << 5)) != 0;
    bool avx512f = (r[1] & (1u << 16)) != 0;
    c.avx512 = avx512f;
    c.avx512vl = (r[1] & (1u << 31)) != 0;
    // VPROLD: 有 AVX512F+VL 即可用 _mm_rol_epi32
    c.vprold = (c.avx512 && c.avx512vl);
    return c;
}

// 工具函数
static inline uint32_t rotl32_scalar(uint32_t x, unsigned n) { return (x << n) | (x >> (32u - n)); }

#if defined(__AVX512VL__) || defined(__AVX512F__)
static inline uint32_t rotl32_vprold(uint32_t x, unsigned n) {
    __m128i vx = _mm_set1_epi32((int)x);
    __m128i vr = _mm_rol_epi32(vx, (int)n); // VPROLD
    return (uint32_t)_mm_cvtsi128_si32(vr);
}
#endif

static inline uint32_t rotl32_opt(uint32_t x, unsigned n, bool use_vprold) {
#if defined(__AVX512VL__) || defined(__AVX512F__)
    if (use_vprold) return rotl32_vprold(x, n);
#endif
    return rotl32_scalar(x, n);
}

static inline uint32_t load_u32_be(const uint8_t b[4]) {
    return (uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16) | (uint32_t(b[2]) << 8) | uint32_t(b[3]);
}
static inline void store_u32_be(uint8_t b[4], uint32_t w) {
    b[0] = uint8_t((w >> 24) & 0xff); b[1] = uint8_t((w >> 16) & 0xff);
    b[2] = uint8_t((w >> 8) & 0xff);  b[3] = uint8_t(w & 0xff);
}

// 常量
static const uint32_t SM4_FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
static const uint32_t SM4_CK[32] = {
0x00070e15,0x1c232a31,0x383f464d,0x545b6269,0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,0x10171e25,0x2c333a41,0x484f565d,0x646b7279 };

static const uint8_t SM4_SBOX[256] = {
0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

// 变换
static inline uint32_t tau_S(uint32_t x) {
    uint8_t b[4]; store_u32_be(b, x);
    b[0] = SM4_SBOX[b[0]]; b[1] = SM4_SBOX[b[1]];
    b[2] = SM4_SBOX[b[2]]; b[3] = SM4_SBOX[b[3]];
    return load_u32_be(b);
}
static inline uint32_t L_enc(uint32_t B, bool use_vprold) {
    // F(x)=B ^ (B<<<2)^(B<<<10)^(B<<<18)^(B<<<24)
    return B
        ^ rotl32_opt(B, 2, use_vprold)
        ^ rotl32_opt(B, 10, use_vprold)
        ^ rotl32_opt(B, 18, use_vprold)
        ^ rotl32_opt(B, 24, use_vprold);
}
static inline uint32_t L_key(uint32_t B) {
    // L' for key schedule: B ^ (B<<<13) ^ (B<<<23)
    return B ^ rotl32_scalar(B, 13) ^ rotl32_scalar(B, 23);
}

// T-table
static uint32_t T0_[256], T1_[256], T2_[256], T3_[256];
static bool T_ready = false;

static inline uint32_t L_on_word_scalar(uint32_t w) {
    return w
        ^ rotl32_scalar(w, 2)
        ^ rotl32_scalar(w, 10)
        ^ rotl32_scalar(w, 18)
        ^ rotl32_scalar(w, 24);
}
static void Ttables_init() {
    if (T_ready) return;
    for (int i = 0; i < 256; i++) {
        uint8_t s = SM4_SBOX[i];
        uint32_t w = uint32_t(s) << 24;
        uint32_t t = L_on_word_scalar(w);
        T0_[i] = t;
        T1_[i] = (t >> 8) | (t << 24);
        T2_[i] = (t >> 16) | (t << 16);
        T3_[i] = (t >> 24) | (t << 8);
    }
    T_ready = true;
}
static inline uint32_t Ttau(uint32_t x) {
    uint8_t b[4]; store_u32_be(b, x);
    return T0_[b[0]] ^ T1_[b[1]] ^ T2_[b[2]] ^ T3_[b[3]];
}

//  密钥扩展
struct SM4Key { uint32_t rk[32]; uint32_t rk_dec[32]; };
enum class Path { Base = 0, TTable = 1 };

static void sm4_key_schedule(const uint8_t key[16], SM4Key& sk) {
    uint32_t MK[4] = { load_u32_be(key), load_u32_be(key + 4), load_u32_be(key + 8), load_u32_be(key + 12) };
    uint32_t K[4] = { MK[0] ^ SM4_FK[0], MK[1] ^ SM4_FK[1], MK[2] ^ SM4_FK[2], MK[3] ^ SM4_FK[3] };
    for (int i = 0; i < 32; i++) {
        uint32_t t = K[1] ^ K[2] ^ K[3] ^ SM4_CK[i];
        uint32_t B = tau_S(t);
        uint32_t rk = K[0] ^ L_key(B);
        sk.rk[i] = rk;
        K[0] = K[1]; K[1] = K[2]; K[2] = K[3]; K[3] = rk;
    }
    for (int i = 0; i < 32; i++) sk.rk_dec[i] = sk.rk[31 - i];
}

//  单块加/解密（Base / T-table）
static void sm4_encrypt_block_base(const SM4Key& sk, const uint8_t in[16], uint8_t out[16], bool use_vprold) {
    uint32_t X0 = load_u32_be(in), X1 = load_u32_be(in + 4), X2 = load_u32_be(in + 8), X3 = load_u32_be(in + 12);
    for (int i = 0; i < 32; i++) {
        uint32_t t = X1 ^ X2 ^ X3 ^ sk.rk[i];
        uint32_t B = tau_S(t);
        uint32_t nx = X0 ^ L_enc(B, use_vprold);
        X0 = X1; X1 = X2; X2 = X3; X3 = nx;
    }
    store_u32_be(out, X3);
    store_u32_be(out + 4, X2);
    store_u32_be(out + 8, X1);
    store_u32_be(out + 12, X0);
}
static void sm4_decrypt_block_base(const SM4Key& sk, const uint8_t in[16], uint8_t out[16], bool use_vprold) {
    uint32_t X0 = load_u32_be(in), X1 = load_u32_be(in + 4), X2 = load_u32_be(in + 8), X3 = load_u32_be(in + 12);
    for (int i = 0; i < 32; i++) {
        uint32_t t = X1 ^ X2 ^ X3 ^ sk.rk_dec[i];
        uint32_t B = tau_S(t);
        uint32_t nx = X0 ^ L_enc(B, use_vprold);
        X0 = X1; X1 = X2; X2 = X3; X3 = nx;
    }
    store_u32_be(out, X3);
    store_u32_be(out + 4, X2);
    store_u32_be(out + 8, X1);
    store_u32_be(out + 12, X0);
}

static void sm4_encrypt_block_ttab(const SM4Key& sk, const uint8_t in[16], uint8_t out[16]) {
    uint32_t X0 = load_u32_be(in), X1 = load_u32_be(in + 4), X2 = load_u32_be(in + 8), X3 = load_u32_be(in + 12);
    for (int i = 0; i < 32; i++) {
        uint32_t t = X1 ^ X2 ^ X3 ^ sk.rk[i];
        uint32_t f = Ttau(t);
        uint32_t nx = X0 ^ f;
        X0 = X1; X1 = X2; X2 = X3; X3 = nx;
    }
    store_u32_be(out, X3);
    store_u32_be(out + 4, X2);
    store_u32_be(out + 8, X1);
    store_u32_be(out + 12, X0);
}
static void sm4_decrypt_block_ttab(const SM4Key& sk, const uint8_t in[16], uint8_t out[16]) {
    uint32_t X0 = load_u32_be(in), X1 = load_u32_be(in + 4), X2 = load_u32_be(in + 8), X3 = load_u32_be(in + 12);
    for (int i = 0; i < 32; i++) {
        uint32_t t = X1 ^ X2 ^ X3 ^ sk.rk_dec[i];
        uint32_t f = Ttau(t);
        uint32_t nx = X0 ^ f;
        X0 = X1; X1 = X2; X2 = X3; X3 = nx;
    }
    store_u32_be(out, X3);
    store_u32_be(out + 4, X2);
    store_u32_be(out + 8, X1);
    store_u32_be(out + 12, X0);
}

//  CTR 
static void incr32_be(uint8_t counter[16]) {
    uint32_t c = (uint32_t(counter[12]) << 24) | (uint32_t(counter[13]) << 16) | (uint32_t(counter[14]) << 8) | counter[15];
    c += 1;
    counter[12] = uint8_t((c >> 24) & 0xff);
    counter[13] = uint8_t((c >> 16) & 0xff);
    counter[14] = uint8_t((c >> 8) & 0xff);
    counter[15] = uint8_t(c & 0xff);
}
static void sm4_ctr_encrypt(const SM4Key& sk, bool use_ttab, bool use_vprold,
    const uint8_t iv[12], uint32_t ictr,
    const uint8_t* in, uint8_t* out, size_t len)
{
    uint8_t ctr[16]{ 0 };
    memcpy(ctr, iv, 12);
    ctr[12] = uint8_t((ictr >> 24) & 0xff);
    ctr[13] = uint8_t((ictr >> 16) & 0xff);
    ctr[14] = uint8_t((ictr >> 8) & 0xff);
    ctr[15] = uint8_t(ictr & 0xff);

    uint8_t ks[16];
    while (len >= 16) {
        if (use_ttab) sm4_encrypt_block_ttab(sk, ctr, ks);
        else          sm4_encrypt_block_base(sk, ctr, ks, use_vprold);
        for (int i = 0; i < 16; i++) out[i] = in[i] ^ ks[i];
        in += 16; out += 16; len -= 16;
        incr32_be(ctr);
    }
    if (len) {
        if (use_ttab) sm4_encrypt_block_ttab(sk, ctr, ks);
        else          sm4_encrypt_block_base(sk, ctr, ks, use_vprold);
        for (size_t i = 0; i < len; i++) out[i] = in[i] ^ ks[i];
    }
}

// GHASH
struct GHashKey { uint64_t Hh, Hl; };

static inline void be_bytes_to_u128(const uint8_t x[16], uint64_t& hi, uint64_t& lo) {
    hi = (uint64_t(x[0]) << 56) | (uint64_t(x[1]) << 48) | (uint64_t(x[2]) << 40) | (uint64_t(x[3]) << 32) |
        (uint64_t(x[4]) << 24) | (uint64_t(x[5]) << 16) | (uint64_t(x[6]) << 8) | uint64_t(x[7]);
    lo = (uint64_t(x[8]) << 56) | (uint64_t(x[9]) << 48) | (uint64_t(x[10]) << 40) | (uint64_t(x[11]) << 32) |
        (uint64_t(x[12]) << 24) | (uint64_t(x[13]) << 16) | (uint64_t(x[14]) << 8) | uint64_t(x[15]);
}
static inline void u128_to_be_bytes(uint8_t x[16], uint64_t hi, uint64_t lo) {
    x[0] = uint8_t((hi >> 56) & 0xff); x[1] = uint8_t((hi >> 48) & 0xff); x[2] = uint8_t((hi >> 40) & 0xff); x[3] = uint8_t((hi >> 32) & 0xff);
    x[4] = uint8_t((hi >> 24) & 0xff); x[5] = uint8_t((hi >> 16) & 0xff); x[6] = uint8_t((hi >> 8) & 0xff);  x[7] = uint8_t(hi & 0xff);
    x[8] = uint8_t((lo >> 56) & 0xff); x[9] = uint8_t((lo >> 48) & 0xff); x[10] = uint8_t((lo >> 40) & 0xff); x[11] = uint8_t((lo >> 32) & 0xff);
    x[12] = uint8_t((lo >> 24) & 0xff); x[13] = uint8_t((lo >> 16) & 0xff); x[14] = uint8_t((lo >> 8) & 0xff);  x[15] = uint8_t(lo & 0xff);
}

// 纯软件：逐位乘 + 约简 (多项式 x^128 + x^7 + x^2 + x + 1)
static void ghash_mul_sw(uint64_t& Xh, uint64_t& Xl, uint64_t Hh, uint64_t Hl) {
    uint64_t Zh = 0, Zl = 0;
    uint64_t Vh = Hh, Vl = Hl;
    for (int i = 0; i < 128; i++) {
        uint64_t mask = (i < 64) ? (1ULL << (63 - i)) : (1ULL << (127 - i));
        bool bit = (i < 64) ? ((Xh & mask) != 0) : ((Xl & mask) != 0);
        if (bit) { Zh ^= Vh; Zl ^= Vl; }
        bool msb = (Vh & 0x8000000000000000ULL) != 0;
        Vh = (Vh << 1) | (Vl >> 63);
        Vl = (Vl << 1);
        if (msb) { Vl ^= 0x87ULL; }
    }
    Xh = Zh; Xl = Zl;
}


