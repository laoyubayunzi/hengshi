/* gmssl/sm4.h - 最小兼容头，用于把 GmSSL 的 sm4.c 独立编译
 * 目的：直接测 GmSSL 的真实实现，而不是我们重写的版本。
 */
#ifndef GMSSL_SM4_H
#define GMSSL_SM4_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SM4_BLOCK_SIZE 16
#define SM4_KEY_SIZE   16

typedef struct { uint32_t rk[32]; } SM4_KEY;

void sm4_set_encrypt_key(SM4_KEY* key, const uint8_t user_key[16]);
void sm4_set_decrypt_key(SM4_KEY* key, const uint8_t user_key[16]);
void sm4_encrypt(const SM4_KEY* key, const unsigned char in[16], unsigned char out[16]);
void sm4_encrypt_blocks(const SM4_KEY* key, const uint8_t* in, size_t nblocks, uint8_t* out);
void sm4_cbc_encrypt_blocks(const SM4_KEY* key, uint8_t iv[16], const uint8_t* in, size_t nblocks, uint8_t* out);
void sm4_cbc_decrypt_blocks(const SM4_KEY* key, uint8_t iv[16], const uint8_t* in, size_t nblocks, uint8_t* out);
void sm4_ctr_encrypt_blocks(const SM4_KEY* key, uint8_t ctr[16], const uint8_t* in, size_t nblocks, uint8_t* out);
void sm4_ctr32_encrypt_blocks(const SM4_KEY* key, uint8_t ctr[16], const uint8_t* in, size_t nblocks, uint8_t* out);

/* GmSSL 的 T-table，extern 出来供缓存观测使用 */
extern const uint32_t T0[256];
extern const uint32_t T1[256];
extern const uint32_t T2[256];
extern const uint32_t T3[256];

#ifdef __cplusplus
}
#endif

#endif
