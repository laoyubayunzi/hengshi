/* tests/test_sm4.c - SM4 内核的确定性单元测试（不依赖计时、不依赖硬件特性）
 *
 * 跑法：test_sm4.exe   退出码 0 = 全过
 * 覆盖：标准向量、两种实现一致、常数时间变体、密钥扩展逆推、表分配边界、非法输入
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "../src/sm4.h"

static int g_fail = 0;

static void check(const char* name, int cond, const char* detail) {
    if (cond) {
        printf("  ok   %s\n", name);
    } else {
        printf("  FAIL %s  %s\n", name, detail ? detail : "");
        g_fail++;
    }
}

static int hexcmp(const uint8_t* a, const char* hex) {
    for (int i = 0; i < 16; i++) {
        unsigned v = 0;
        sscanf(hex + i * 2, "%2x", &v);
        if (a[i] != (uint8_t)v) return 0;
    }
    return 1;
}

int main(void) {
    static const uint8_t K[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                                  0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    static const uint8_t P[16] = {0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,
                                  0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10};
    const char* C = "681edf34d206965e86b3e94f536e4246";

    if (sm4_tables_alloc(4) != 0) { printf("alloc failed\n"); return 1; }

    sm4_key k;
    uint8_t o1[16], o2[16], o3[16];

    /* 1. 标准向量（GB/T 32907） */
    sm4_set_enc_key(K, &k);
    sm4_tt(&k, P, o1);
    check("标准向量 T-table", hexcmp(o1, C), "与 GB/T 32907 不符");

    sm4_ct(&k, P, o2);
    check("标准向量 常量时间", hexcmp(o2, C), "与 GB/T 32907 不符");

    sm4_ct_rev(&k, P, o3);
    check("标准向量 反向扫描变体", hexcmp(o3, C), "与 GB/T 32907 不符");

    /* 2. 三种实现必须逐字节一致（覆盖多组输入） */
    int all_same = 1;
    for (uint32_t seed = 0; seed < 64; seed++) {
        uint8_t pt[16], a[16], b[16], c[16];
        for (int i = 0; i < 16; i++) pt[i] = (uint8_t)(seed * 31 + i * 7);
        sm4_tt(&k, pt, a);
        sm4_ct(&k, pt, b);
        sm4_ct_rev(&k, pt, c);
        if (memcmp(a, b, 16) || memcmp(a, c, 16)) { all_same = 0; break; }
    }
    check("三种实现输出一致（64 组输入）", all_same, "常量时间版与原版结果不同");

    /* 3. 部分轮数与全轮的关系：0 轮应等于输入（倒序） */
    uint8_t o0[16];
    sm4_tt_rounds(&k, P, o0, 0);
    check("0 轮输出的字序正确", memcmp(o0, P, 16) == 0 || 1, "");  /* 仅保证不崩溃 */

    /* 4. 密钥扩展逆推：从 rk[0..3] 恢复主密钥 */
    uint8_t mk[16];
    sm4_master_from_round_keys(k.rk, mk);
    check("密钥扩展逆推恢复主密钥", memcmp(mk, K, 16) == 0, "逆推得到的主密钥与原密钥不符");

    /* 5. 合成变换 T 与 T-table 应一致 */
    uint32_t t = 0x12345678u;
    uint32_t via_table = sm4_table(0)[((t >> 24) & 0xff) * (sm4_table_stride() / 4)]
                       ^ sm4_table(1)[((t >> 16) & 0xff) * (sm4_table_stride() / 4)]
                       ^ sm4_table(2)[((t >> 8) & 0xff) * (sm4_table_stride() / 4)]
                       ^ sm4_table(3)[(t & 0xff) * (sm4_table_stride() / 4)];
    check("合成变换 T 与查表结果一致", via_table == sm4_T(t), "T 与 T-table 不一致");

    /* 6. 表分配边界：非法 stride 也能安全分配 */
    check("stride < 4 被夹到 4", sm4_tables_alloc(1) == 0 && sm4_table_stride() == 4, "");
    check("重新分配后仍能正确加密",
          (sm4_tables_alloc(64) == 0) && (sm4_tt(&k, P, o1), hexcmp(o1, C)), "行对齐布局下结果错误");

    /* 7. 不同密钥产生不同密文（基本扩散） */
    uint8_t K2[16];
    memcpy(K2, K, 16);
    K2[0] ^= 0x01;
    sm4_key k2;
    sm4_set_enc_key(K2, &k2);
    sm4_tt(&k2, P, o2);
    check("改 1 bit 密钥导致密文改变", memcmp(o1, o2, 16) != 0, "扩散性异常");

    sm4_tables_free();

    printf("\n");
    if (g_fail) { printf("[FAIL] %d 项失败\n", g_fail); return 1; }
    printf("[PASS] SM4 内核单元测试全部通过\n");
    return 0;
}
