/* gmssl/endian.h - 最小兼容头（大端读写 + 循环移位） */
#ifndef GMSSL_ENDIAN_H
#define GMSSL_ENDIAN_H

#include <stdint.h>

#define GETU32(p) (((uint32_t)(p)[0] << 24) | ((uint32_t)(p)[1] << 16) | \
                   ((uint32_t)(p)[2] << 8)  | ((uint32_t)(p)[3]))

#define PUTU32(p, v) do { \
    (p)[0] = (uint8_t)((v) >> 24); (p)[1] = (uint8_t)((v) >> 16); \
    (p)[2] = (uint8_t)((v) >> 8);  (p)[3] = (uint8_t)(v); } while (0)

#define GETU64(p) (((uint64_t)GETU32(p) << 32) | GETU32((const uint8_t*)(p) + 4))

#define PUTU64(p, v) do { \
    PUTU32(p, (uint32_t)((v) >> 32)); PUTU32((uint8_t*)(p) + 4, (uint32_t)(v)); } while (0)

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#endif
