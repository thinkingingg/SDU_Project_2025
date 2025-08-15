#define _CRT_SECURE_NO_WARNINGS
#include <cstdint>
#include <cstring>
#include <iostream>
#include <immintrin.h>
#include <stdint.h>
#include <chrono>
#include <vector>
#include <numeric>
#include <iomanip>
#include <cstdio>
#include <string>
#include <random>

using namespace std;

/* SM3算法实现与优化 */

// 初始向量IV
const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// 常量Tj
const uint32_t T[64] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
};

/* 基础工具函数 */

// 循环左移
uint32_t rotate_left(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// SIMD循环左移
__m256i simd_rotate_left(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
}

// 布尔函数FF
uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

// 布尔函数GG
uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (~x & z));
}

// SIMD布尔函数FF
__m256i simd_FF(__m256i x, __m256i y, __m256i z, int j) {
    if (j < 16) return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
    return _mm256_or_si256(_mm256_or_si256(_mm256_and_si256(x, y),
        _mm256_and_si256(x, z)),
        _mm256_and_si256(y, z));
}

// SIMD布尔函数GG
__m256i simd_GG(__m256i x, __m256i y, __m256i z, int j) {
    if (j < 16) return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
    return _mm256_or_si256(_mm256_and_si256(x, y),
        _mm256_and_si256(_mm256_andnot_si256(x, _mm256_set1_epi32(0xFFFFFFFF)), z));
}

// 置换函数P0
uint32_t P0(uint32_t x) {
    return x ^ rotate_left(x, 9) ^ rotate_left(x, 17);
}

// 置换函数P1
uint32_t P1(uint32_t x) {
    return x ^ rotate_left(x, 15) ^ rotate_left(x, 23);
}

// SIMD置换函数P0
__m256i simd_P0(__m256i X) {
    __m256i x1 = _mm256_or_si256(_mm256_slli_epi32(X, 9), _mm256_srli_epi32(X, 23));
    __m256i x2 = _mm256_or_si256(_mm256_slli_epi32(X, 17), _mm256_srli_epi32(X, 15));
    return _mm256_xor_si256(X, _mm256_xor_si256(x1, x2));
}

// SIMD置换函数P1
__m256i simd_P1(__m256i X) {
    __m256i x1 = _mm256_or_si256(_mm256_slli_epi32(X, 15), _mm256_srli_epi32(X, 17));
    __m256i x2 = _mm256_or_si256(_mm256_slli_epi32(X, 23), _mm256_srli_epi32(X, 9));
    return _mm256_xor_si256(X, _mm256_xor_si256(x1, x2));
}

/* 消息处理函数 */

// 将4字节数组转换为32位整数
uint32_t bytes_to_uint32(const uint8_t* b) {
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
}

// 将32位整数转换为4字节数组
void uint32_to_bytes(uint32_t n, uint8_t* b) {
    b[0] = (n >> 24) & 0xFF;
    b[1] = (n >> 16) & 0xFF;
    b[2] = (n >> 8) & 0xFF;
    b[3] = n & 0xFF;
}

// 消息填充函数
vector<uint8_t> pad_message(const vector<uint8_t>& msg) {
    uint64_t bit_len = msg.size() * 8;
    vector<uint8_t> padded = msg;

    // 添加填充位
    padded.push_back(0x80);

    // 填充0直到长度满足mod 512 = 448
    while ((padded.size() * 8 + 64) % 512 != 0) {
        padded.push_back(0x00);
    }

    // 添加消息长度
    for (int i = 7; i >= 0; i--) {
        padded.push_back((bit_len >> (i * 8)) & 0xFF);
    }

    return padded;
}

/* SM3核心算法 */

// 压缩函数
void CF(uint32_t V[8], const uint8_t* block) {
    uint32_t W[68], W1[64];

    // 消息扩展
    for (int i = 0; i < 16; i++) {
        W[i] = bytes_to_uint32(block + i * 4);
    }
    for (int i = 16; i < 68; i++) {
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ rotate_left(W[i - 3], 15))
            ^ rotate_left(W[i - 13], 7) ^ W[i - 6];
    }
    for (int i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i + 4];
    }

    // 压缩函数主循环
    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = rotate_left(rotate_left(A, 12) + E + rotate_left(T[j], j), 7);
        uint32_t SS2 = SS1 ^ rotate_left(A, 12);
        uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];

        D = C;
        C = rotate_left(B, 9);
        B = A;
        A = TT1;

        H = G;
        G = rotate_left(F, 19);
        F = E;
        E = P0(TT2);
    }

    // 更新向量
    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

// SIMD压缩函数(8个消息块并行处理)
void simd_CF(__m256i V[8], const uint8_t* blocks) {
    __m256i W[68], W1[64];

    // 消息扩展
    for (int i = 0; i < 16; i++) {
        uint32_t temp[8];
        for (int j = 0; j < 8; j++) {
            temp[j] = bytes_to_uint32(blocks + j * 64 + i * 4);
        }
        W[i] = _mm256_loadu_si256((__m256i*)temp);
    }

    for (int i = 16; i < 68; i++) {
        __m256i temp = _mm256_xor_si256(
            _mm256_xor_si256(W[i - 16], W[i - 9]),
            simd_rotate_left(W[i - 3], 15));
        W[i] = _mm256_xor_si256(
            _mm256_xor_si256(simd_P1(temp), simd_rotate_left(W[i - 13], 7)),
            W[i - 6]);
    }

    for (int i = 0; i < 64; i++) {
        W1[i] = _mm256_xor_si256(W[i], W[i + 4]);
    }

    // 初始化寄存器
    __m256i A = V[0], B = V[1], C = V[2], D = V[3];
    __m256i E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; j++) {
        __m256i SS1 = simd_rotate_left(
            _mm256_add_epi32(
                _mm256_add_epi32(simd_rotate_left(A, 12), E),
                simd_rotate_left(_mm256_set1_epi32(T[j]), j)), 7);

        __m256i SS2 = _mm256_xor_si256(SS1, simd_rotate_left(A, 12));
        __m256i TT1 = _mm256_add_epi32(
            _mm256_add_epi32(
                _mm256_add_epi32(simd_FF(A, B, C, j), D),
                SS2), W1[j]);

        __m256i TT2 = _mm256_add_epi32(
            _mm256_add_epi32(
                _mm256_add_epi32(simd_GG(E, F, G, j), H),
                SS1), W[j]);

        D = C;
        C = simd_rotate_left(B, 9);
        B = A;
        A = TT1;

        H = G;
        G = simd_rotate_left(F, 19);
        F = E;
        E = simd_P0(TT2);
    }

    // 更新向量
    V[0] = _mm256_xor_si256(V[0], A);
    V[1] = _mm256_xor_si256(V[1], B);
    V[2] = _mm256_xor_si256(V[2], C);
    V[3] = _mm256_xor_si256(V[3], D);
    V[4] = _mm256_xor_si256(V[4], E);
    V[5] = _mm256_xor_si256(V[5], F);
    V[6] = _mm256_xor_si256(V[6], G);
    V[7] = _mm256_xor_si256(V[7], H);
}

/* SM3哈希函数 */

// 基本SM3哈希函数
void sm3_hash(const vector<uint8_t>& message, vector<uint8_t>& hash) {
    vector<uint8_t> padded = pad_message(message);
    uint32_t V[8];
    memcpy(V, IV, sizeof(V));

    size_t blocks = padded.size() / 64;
    for (size_t i = 0; i < blocks; i++) {
        CF(V, &padded[i * 64]);
    }

    hash.resize(32);
    for (int i = 0; i < 8; i++) {
        uint32_to_bytes(V[i], &hash[i * 4]);
    }
}

