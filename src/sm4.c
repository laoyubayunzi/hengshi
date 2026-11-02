/* sm4.c - 真 SM4（S-box / FK / CK 取自 GmSSL，Apache-2.0）
 *
 * 自检：标准测试向量
 *   key = 0123456789abcdeffedcba9876543210
 *   pt  = 0123456789abcdeffedcba9876543210
 *   ct  = 681edf34d206965e86b3e94f536e4246
 */
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include "sm4.h"
#include "timing.h"

const uint8_t SM4_S[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};

static const uint32_t FK[4] = { 0xa3b1bac6u, 0x56aa3350u, 0x677d9197u, 0xb27022dcu };

static const uint32_t CK[32] = {
    0x00070e15u,0x1c232a31u,0x383f464du,0x545b6269u,0x70777e85u,0x8c939aa1u,0xa8afb6bdu,0xc4cbd2d9u,
    0xe0e7eef5u,0xfc030a11u,0x181f262du,0x343b4249u,0x50575e65u,0x6c737a81u,0x888f969du,0xa4abb2b9u,
    0xc0c7ced5u,0xdce3eaf1u,0xf8ff060du,0x141b2229u,0x30373e45u,0x4c535a61u,0x686f767du,0x848b9299u,
    0xa0a7aeb5u,0xbcc3cad1u,0xd8dfe6edu,0xf4fb0209u,0x10171e25u,0x2c333a41u,0x484f565du,0x646b7279u,
};

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
/* 加密轮线性变换 L */
static inline uint32_t L32(uint32_t x) {
    return x ^ ROL(x, 2) ^ ROL(x, 10) ^ ROL(x, 18) ^ ROL(x, 24);
}
/* 密钥扩展线性变换 L' */
static inline uint32_t L32_(uint32_t x) {
    return x ^ ROL(x, 13) ^ ROL(x, 23);
}

/* ---------- T-table 管理 ---------- */
static uint32_t* g_t[4] = {0, 0, 0, 0};
static size_t    g_stride = 4;
static size_t    g_entries = 256;

size_t sm4_table_stride(void) { return g_stride; }
uint32_t* sm4_table(int i) { return g_t[i]; }
size_t sm4_table_bytes(void) { return g_stride * 256; }

int sm4_tables_alloc(size_t stride_bytes) {
    sm4_tables_free();
    if (stride_bytes < 4) stride_bytes = 4;
    g_stride = stride_bytes;
    for (int i = 0; i < 4; i++) {
        g_t[i] = (uint32_t*)_aligned_malloc(g_stride * 256, 64);
        if (!g_t[i]) { sm4_tables_free(); return -1; }
        memset(g_t[i], 0, g_stride * 256);
        for (size_t j = 0; j < 256; j++) {
            uint32_t s = SM4_S[j];
            uint32_t v = 0;
            switch (i) {
            case 0: v = L32(s << 24); break;
            case 1: v = L32(s << 16); break;
            case 2: v = L32(s << 8);  break;
            default: v = L32(s);      break;
            }
            g_t[i][j * (g_stride / 4)] = v;
        }
    }
    return 0;
}

void sm4_tables_free(void) {
    for (int i = 0; i < 4; i++) { if (g_t[i]) { _aligned_free(g_t[i]); g_t[i] = 0; } }
}

void sm4_tables_flush(void) {
    for (int i = 0; i < 4; i++) flush_block(g_t[i], g_stride * 256);
}

/* 合成变换 T(t) = L32(S32(t)) */
uint32_t sm4_T(uint32_t t) {
    uint32_t s = ((uint32_t)SM4_S[(t >> 24) & 0xff] << 24) |
                 ((uint32_t)SM4_S[(t >> 16) & 0xff] << 16) |
                 ((uint32_t)SM4_S[(t >> 8)  & 0xff] << 8)  |
                 ((uint32_t)SM4_S[ t        & 0xff]);
    return L32(s);
}

/* ---------- 密钥扩展 ---------- */
void sm4_set_enc_key(const uint8_t user_key[16], sm4_key* k) {
    uint32_t X0 = ((uint32_t)user_key[0] << 24) | ((uint32_t)user_key[1] << 16) |
                  ((uint32_t)user_key[2] << 8)  |  (uint32_t)user_key[3];
    uint32_t X1 = ((uint32_t)user_key[4] << 24) | ((uint32_t)user_key[5] << 16) |
                  ((uint32_t)user_key[6] << 8)  |  (uint32_t)user_key[7];
    uint32_t X2 = ((uint32_t)user_key[8] << 24) | ((uint32_t)user_key[9] << 16) |
                  ((uint32_t)user_key[10] << 8) |  (uint32_t)user_key[11];
    uint32_t X3 = ((uint32_t)user_key[12] << 24) | ((uint32_t)user_key[13] << 16) |
                  ((uint32_t)user_key[14] << 8) |  (uint32_t)user_key[15];
    X0 ^= FK[0]; X1 ^= FK[1]; X2 ^= FK[2]; X3 ^= FK[3];
    for (int i = 0; i < 32; i++) {
        uint32_t t = X1 ^ X2 ^ X3 ^ CK[i];
        /* S32(t) */
        uint32_t s = ((uint32_t)SM4_S[(t >> 24) & 0xff] << 24) |
                     ((uint32_t)SM4_S[(t >> 16) & 0xff] << 16) |
                     ((uint32_t)SM4_S[(t >> 8)  & 0xff] << 8)  |
                     ((uint32_t)SM4_S[ t        & 0xff]);
        uint32_t X4 = X0 ^ L32_(s);
        k->rk[i] = X4;
        X0 = X1; X1 = X2; X2 = X3; X3 = X4;
    }
}

/* ---------- T-table 加密（泄漏版） ---------- */
static inline uint32_t tt_round(uint32_t x1, uint32_t x2, uint32_t x3, uint32_t x0, uint32_t rk) {
    uint32_t t = x1 ^ x2 ^ x3 ^ rk;
    uint32_t s = g_t[0][((t >> 24) & 0xff) * (g_stride / 4)]
               ^ g_t[1][((t >> 16) & 0xff) * (g_stride / 4)]
               ^ g_t[2][((t >> 8)  & 0xff) * (g_stride / 4)]
               ^ g_t[3][( t        & 0xff) * (g_stride / 4)];
    return x0 ^ s;
}

void sm4_tt_rounds(const sm4_key* k, const uint8_t in[16], uint8_t out[16], int rounds) {
    uint32_t X[4];
    for (int i = 0; i < 4; i++)
        X[i] = ((uint32_t)in[i*4] << 24) | ((uint32_t)in[i*4+1] << 16) |
               ((uint32_t)in[i*4+2] << 8) | (uint32_t)in[i*4+3];

    uint32_t buf[36];
    for (int i = 0; i < 4; i++) buf[i] = X[i];
    for (int r = 0; r < rounds; r++)
        buf[r + 4] = tt_round(buf[r+1], buf[r+2], buf[r+3], buf[r], k->rk[r]);

    /* 输出为倒序 */
    uint32_t o[4];
    for (int i = 0; i < 4; i++) o[i] = buf[rounds + 3 - i];
    for (int i = 0; i < 4; i++) {
        out[i*4]   = (uint8_t)(o[i] >> 24);
        out[i*4+1] = (uint8_t)(o[i] >> 16);
        out[i*4+2] = (uint8_t)(o[i] >> 8);
        out[i*4+3] = (uint8_t)(o[i]);
    }
}

void sm4_tt(const sm4_key* k, const uint8_t in[16], uint8_t out[16]) {
    sm4_tt_rounds(k, in, out, 32);
}

/* ---------- 常量时间加密 ---------- */
static inline uint32_t ct_sbox32(uint32_t t) {
    uint32_t r = 0;
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t e0 = (uint32_t)(((t >> 24) & 0xff) == i);
        uint32_t e1 = (uint32_t)(((t >> 16) & 0xff) == i);
        uint32_t e2 = (uint32_t)(((t >> 8)  & 0xff) == i);
        uint32_t e3 = (uint32_t)(( t        & 0xff) == i);
        uint32_t v  = SM4_S[i];
        r |= (v << 24) & ((uint32_t)0 - e0);
        r |= (v << 16) & ((uint32_t)0 - e1);
        r |= (v << 8)  & ((uint32_t)0 - e2);
        r |=  v        & ((uint32_t)0 - e3);
    }
    return r;
}

void sm4_ct(const sm4_key* k, const uint8_t in[16], uint8_t out[16]) {
    uint32_t buf[36];
    for (int i = 0; i < 4; i++)
        buf[i] = ((uint32_t)in[i*4] << 24) | ((uint32_t)in[i*4+1] << 16) |
                 ((uint32_t)in[i*4+2] << 8) | (uint32_t)in[i*4+3];

    for (int r = 0; r < 32; r++) {
        uint32_t t = buf[r+1] ^ buf[r+2] ^ buf[r+3] ^ k->rk[r];
        buf[r+4] = buf[r] ^ L32(ct_sbox32(t));
    }
    uint32_t o[4];
    for (int i = 0; i < 4; i++) o[i] = buf[32 + 3 - i];
    for (int i = 0; i < 4; i++) {
        out[i*4]   = (uint8_t)(o[i] >> 24);
        out[i*4+1] = (uint8_t)(o[i] >> 16);
        out[i*4+2] = (uint8_t)(o[i] >> 8);
        out[i*4+3] = (uint8_t)(o[i]);
    }
}

/* ---------- 常量时间加密：反向扫描 ----------
 * 与 sm4_ct 的唯一差别是遍历顺序。地址集合完全相同，
 * 用来验证"干净判定与遍历顺序无关，只看地址是否依赖数据"。
 */
static inline uint32_t ct_sbox32_rev(uint32_t t) {
    uint32_t r = 0;
    for (int i = 255; i >= 0; i--) {
        uint32_t e0 = (uint32_t)(((t >> 24) & 0xff) == (uint32_t)i);
        uint32_t e1 = (uint32_t)(((t >> 16) & 0xff) == (uint32_t)i);
        uint32_t e2 = (uint32_t)(((t >> 8)  & 0xff) == (uint32_t)i);
        uint32_t e3 = (uint32_t)(( t        & 0xff) == (uint32_t)i);
        uint32_t v  = SM4_S[i];
        r |= (v << 24) & ((uint32_t)0 - e0);
        r |= (v << 16) & ((uint32_t)0 - e1);
        r |= (v << 8)  & ((uint32_t)0 - e2);
        r |=  v        & ((uint32_t)0 - e3);
    }
    return r;
}

void sm4_ct_rev(const sm4_key* k, const uint8_t in[16], uint8_t out[16]) {
    uint32_t buf[36];
    for (int i = 0; i < 4; i++)
        buf[i] = ((uint32_t)in[i*4] << 24) | ((uint32_t)in[i*4+1] << 16) |
                 ((uint32_t)in[i*4+2] << 8) | (uint32_t)in[i*4+3];

    for (int r = 0; r < 32; r++) {
        uint32_t t = buf[r+1] ^ buf[r+2] ^ buf[r+3] ^ k->rk[r];
        buf[r+4] = buf[r] ^ L32(ct_sbox32_rev(t));
    }
    uint32_t o[4];
    for (int i = 0; i < 4; i++) o[i] = buf[32 + 3 - i];
    for (int i = 0; i < 4; i++) {
        out[i*4]   = (uint8_t)(o[i] >> 24);
        out[i*4+1] = (uint8_t)(o[i] >> 16);
        out[i*4+2] = (uint8_t)(o[i] >> 8);
        out[i*4+3] = (uint8_t)(o[i]);
    }
}

/* ---------- 由 rk[0..3] 反推主密钥 ----------
 * K[i+4] = K[i] ^ T'(K[i+1]^K[i+2]^K[i+3]^CK[i])
 * 已知 K[4..7] 时，依次反推 K[3],K[2],K[1],K[0]
 * 再 MK[i] = K[i] ^ FK[i]
 */
void sm4_master_from_round_keys(const uint32_t rk[32], uint8_t mk[16]) {
    uint32_t K[8];
    K[4] = rk[0]; K[5] = rk[1]; K[6] = rk[2]; K[7] = rk[3];
    for (int i = 3; i >= 0; i--) {
        uint32_t t = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i];
        uint32_t s = ((uint32_t)SM4_S[(t >> 24) & 0xff] << 24) |
                     ((uint32_t)SM4_S[(t >> 16) & 0xff] << 16) |
                     ((uint32_t)SM4_S[(t >> 8)  & 0xff] << 8)  |
                     ((uint32_t)SM4_S[ t        & 0xff]);
        K[i] = K[i+4] ^ L32_(s);
    }
    for (int i = 0; i < 4; i++) {
        uint32_t v = K[i] ^ FK[i];
        mk[i*4]   = (uint8_t)(v >> 24);
        mk[i*4+1] = (uint8_t)(v >> 16);
        mk[i*4+2] = (uint8_t)(v >> 8);
        mk[i*4+3] = (uint8_t)v;
    }
}
