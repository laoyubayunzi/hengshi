/* sm4.h - 衡时 / SM4 内核接口
 *
 * 两种实现并存：
 *   sm4_tt()  T-table 查表版 —— 与 GmSSL / OpenSSL 的主流写法同构，快，但访存地址依赖密钥
 *   sm4_ct()  常量时间版 —— S-box 全表扫描 + 掩码选择，访存地址与密钥无关
 *
 * 表布局可配置（stride）。这不是玩具参数：
 *   自然布局（16 项/缓存行）= 泄漏 4 bit/字节
 *   行对齐布局（1 项/缓存行）= 泄漏 8 bit/字节
 * 这个差别本身就是一条安全结论。
 */
#ifndef SM4_H
#define SM4_H

#include <stdint.h>
#include <stddef.h>

typedef struct { uint32_t rk[32]; } sm4_key;

extern const uint8_t SM4_S[256];

/* 分配 T-table。stride_bytes = 4 为自然布局，64 为行对齐布局。 */
int  sm4_tables_alloc(size_t stride_bytes);
void sm4_tables_free(void);
size_t sm4_table_stride(void);
uint32_t* sm4_table(int i);            /* i = 0..3 */
size_t sm4_table_bytes(void);          /* 单张表的字节数 */
void sm4_tables_flush(void);

void sm4_set_enc_key(const uint8_t user_key[16], sm4_key* k);
void sm4_tt(const sm4_key* k, const uint8_t in[16], uint8_t out[16]);   /* 泄漏版 */
void sm4_ct(const sm4_key* k, const uint8_t in[16], uint8_t out[16]);   /* 常量时间版 */
/* 同上，但扫描顺序反向 —— 用来验证「顺序无关、只要地址恒定就算干净」 */
void sm4_ct_rev(const sm4_key* k, const uint8_t in[16], uint8_t out[16]);

/* 只跑前 rounds 轮，用于演示泄漏定位（rounds = 32 即完整加密） */
void sm4_tt_rounds(const sm4_key* k, const uint8_t in[16], uint8_t out[16], int rounds);

/* 合成变换 T(t) = L(S32(t))，用于推进轮状态 */
uint32_t sm4_T(uint32_t t);

/* 从 rk[0..3] 反推主密钥，用于验证"密钥确实被恢复" */
void sm4_master_from_round_keys(const uint32_t rk[32], uint8_t mk[16]);

#endif /* SM4_H */
