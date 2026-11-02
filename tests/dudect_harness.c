/* tests/dudect_harness.c - 用上游 dudect.h 测量本项目关心的四个实现
 *
 * 上游：oreparaz/dudect  src/dudect.h
 *       commit dc269651fb2567e46755cfb2a13d3875592968b5
 *       sha256 3fb3b2bd7f9e17ae34b7c92518c1311c67342c56facc80da925d85f121b649da
 * 许可证：MIT
 *
 * 这里只做"喂数据 + 计时"两件事，统计全部交给 dudect 自己：
 *   1 次未裁剪 t 检验 + 100 个上尾裁剪百分位检验 + 1 次二阶检验 = 102 个检验，
 *   取其中最大的 |t| 作为依据。
 *
 * 用法：dudect_harness.exe <impl> <measurements>
 *   impl: ours_tt | ours_ct | gmssl | tongsuo
 */
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* 上游 dudect.h 自带的 randombytes/randombit 依赖 /dev/urandom。
 * 做法：定义 DUDECT_IMPLEMENTATION 前把这些名字重命名，让上游那份成为
 * dudect_posix_*（永远不被调用），文件本身不改一个字节；
 * 之后 #undef 回来，由本文件提供 Windows 实现。 */
#define randombytes dudect_posix_randombytes
#define randombit   dudect_posix_randombit
#define DUDECT_IMPLEMENTATION
#include "../src/thirdparty/dudect.h"
#undef randombytes
#undef randombit

#include "../src/sm4.h"

typedef struct { uint32_t rk[32]; } gmssl_sm4_key;
typedef struct { uint32_t rk[32]; } tongsuo_sm4_key;
extern void sm4_set_encrypt_key(gmssl_sm4_key* key, const uint8_t user_key[16]);
extern void sm4_encrypt(const gmssl_sm4_key* key, const unsigned char in[16], unsigned char out[16]);
extern int  ossl_sm4_set_key(const uint8_t *key, void *ks);

/* 被攻击实现的表地址（用于测量前刷出缓存）。
 * 上游 dudect 不刷表：表常驻 L1 时一阶信号消失，四个实现都会被判干净。
 * 这里把"共享主机上表可能被协程挤掉"这一威胁模型显式化。 */
extern const uint32_t T0[256], T1[256], T2[256], T3[256];              /* GmSSL */
extern const uint32_t SM4_SBOX_T0[256], SM4_SBOX_T1[256];             /* Tongsuo（/Dstatic= 构建） */
extern const uint32_t SM4_SBOX_T2[256], SM4_SBOX_T3[256];

static void flush_range(const void *p, size_t bytes) {
    const char *q = (const char*)p;
    for (size_t i = 0; i < bytes; i += 64) _mm_clflush((const void*)(q + i));
    _mm_mfence();
}
extern void ossl_sm4_encrypt(const uint8_t *in, uint8_t *out, const void *ks);

static int g_impl = 0;
static const uint8_t g_key[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                                  0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

static sm4_key g_kours;
static gmssl_sm4_key g_ktt;
static tongsuo_sm4_key g_kts;

/* 随机源：Windows 用 BCryptGenRandom。
 * dudect 自带的 randombytes 读 /dev/urandom，编译时已用 -Drandombytes=... 重命名，
 * 因此这里提供的是真正被调用的实现，而 dudect.h 内容保持上游原样。 */
void randombytes(uint8_t *x, size_t how_much) {
    if (BCryptGenRandom(NULL, x, (ULONG)how_much, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) {
        /* 兜底：不该发生；实在拿不到就用确定性序列，保证测量能继续 */
        static uint32_t s = 0x12345678u;
        for (size_t i = 0; i < how_much; i++) { s = s * 1664525u + 1013904223u; x[i] = (uint8_t)(s >> 24); }
    }
}

uint8_t randombit(void) {
    uint8_t ret = 0;
    randombytes(&ret, 1);
    return (uint8_t)(ret & 1);
}

void prepare_inputs(dudect_config_t *c, uint8_t *input_data, uint8_t *classes) {
    randombytes(input_data, c->number_measurements * c->chunk_size);
    for (size_t i = 0; i < c->number_measurements; i++) {
        classes[i] = randombit();
        if (classes[i] == 0) {
            memset(input_data + i * c->chunk_size, 0x00, c->chunk_size);
        }
    }
}

uint8_t do_one_computation(uint8_t *data) {
    uint8_t out[16];
    /* 测量前刷表：这是"共享主机"威胁模型下的合理假设 */
    switch (g_impl) {
        case 0: case 1:
            flush_range(sm4_table(0), 1024); flush_range(sm4_table(1), 1024);
            flush_range(sm4_table(2), 1024); flush_range(sm4_table(3), 1024);
            break;
        case 2:
            flush_range(T0, 1024); flush_range(T1, 1024);
            flush_range(T2, 1024); flush_range(T3, 1024);
            break;
        default:
            flush_range(SM4_SBOX_T0, 1024); flush_range(SM4_SBOX_T1, 1024);
            flush_range(SM4_SBOX_T2, 1024); flush_range(SM4_SBOX_T3, 1024);
            break;
    }
    switch (g_impl) {
        case 0: sm4_tt(&g_kours, data, out); break;
        case 1: sm4_ct(&g_kours, data, out); break;
        case 2: sm4_encrypt(&g_ktt, data, out); break;
        default: ossl_sm4_encrypt(data, out, &g_kts); break;
    }
    return out[0];
}

int main(int argc, char **argv) {
    const char *name = (argc > 1) ? argv[1] : "ours_tt";
    long total_target = (argc > 2) ? atol(argv[2]) : 1000000;
    long batch = (argc > 3) ? atol(argv[3]) : 10000;

    if (!strcmp(name, "ours_tt")) g_impl = 0;
    else if (!strcmp(name, "ours_ct")) g_impl = 1;
    else if (!strcmp(name, "gmssl")) g_impl = 2;
    else g_impl = 3;

    if (sm4_tables_alloc(4) != 0) { printf("alloc failed\n"); return 2; }
    sm4_set_enc_key(g_key, &g_kours);
    sm4_set_encrypt_key(&g_ktt, g_key);
    ossl_sm4_set_key(g_key, &g_kts);

    dudect_config_t cfg;
    cfg.chunk_size = 16;
    cfg.number_measurements = (size_t)batch;

    dudect_ctx_t ctx;
    if (dudect_init(&ctx, &cfg) != 0) { printf("dudect_init failed\n"); return 2; }

    /* dudect_main 一次只处理一个批次：第一个批次用于预热百分位，
     * 之后每次都会 update_statistics + report。所以必须由调用方循环。 */
    long samples = 0;
    dudect_state_t st = DUDECT_NO_LEAKAGE_EVIDENCE_YET;
    while (samples < total_target) {
        st = dudect_main(&ctx);
        samples += batch;
        if (st == DUDECT_LEAKAGE_FOUND) break;
    }

    printf("DUDECT impl=%s samples=%ld state=%s\n", name, samples,
           st == DUDECT_LEAKAGE_FOUND ? "LEAK" : "clean");

    dudect_free(&ctx);
    sm4_tables_free();
    return 0;
}
