/* tongsuo/crypto/sm4.h - 最小兼容头（只保留本工具需要的接口） */
#ifndef TONSUO_SM4_H
#define TONSUO_SM4_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define SM4_BLOCK_SIZE   16
#define SM4_KEY_SCHEDULE 32

typedef struct { uint32_t rk[SM4_KEY_SCHEDULE]; } SM4_KEY;

int  ossl_sm4_set_key(const uint8_t *key, SM4_KEY *ks);
void ossl_sm4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);
void ossl_sm4_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);

#endif
