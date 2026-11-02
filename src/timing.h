/* timing.h - 计时与缓存操作的唯一入口
 *
 * 两个指令决定这个作品能不能做：
 *   rdtscp   : 读时间戳计数器，单位是 CPU 周期（不是纳秒）
 *   clflush  : 把一条缓存行从所有缓存层级踢出去
 *
 * 为什么必须用 rdtscp 而不是 clock()：
 *   clock()/QPC 的精度在微秒级，而一次缓存命中/未命中差几十个周期。
 *   尺子刻度过粗，就看不见要测的东西。
 *
 * 为什么前后要加 lfence：
 *   CPU 会乱序执行。不加栅栏，rdtscp 可能被挪到被测函数执行之前，
 *   测出来的数字毫无意义。
 */
#ifndef TIMING_H
#define TIMING_H

#include <stdint.h>
#include <stddef.h>

#if defined(_MSC_VER)
#  include <intrin.h>
#  include <immintrin.h>
#else
#  include <x86intrin.h>
#endif

/* 读时间戳。aux 返回处理器 ID，这里用不到，但 rdtscp 的签名要求它。 */
static inline uint64_t now_cycles(void) {
    unsigned int aux;
    return (uint64_t)__rdtscp(&aux);
}

/* 串行化屏障：保证屏障之前的指令全部执行完，才继续取时间戳 */
static inline void fence_all(void) {
    _mm_lfence();   /* 读操作串行化，足够用于测量前 */
    _mm_mfence();   /* 写操作串行化 */
}

/* 把包含地址 p 的缓存行踢出缓存 */
static inline void flush_line(const void* p) {
    _mm_clflush(p);
}

/* 把一段内存里所有缓存行踢掉。len 不需要是 64 的倍数。 */
static inline void flush_block(const void* p, size_t len) {
    /* 起点向下对齐到 64 字节、终点向上对齐：
     * 表首地址不保证 64 字节对齐，若按 p+0/64/128... 刷，
     * 会漏掉表尾所在的最后一条缓存行。 */
    uintptr_t addr = (uintptr_t)p;
    uintptr_t begin = addr & ~(uintptr_t)63;
    uintptr_t last  = (addr + len - 1) & ~(uintptr_t)63;
    for (uintptr_t a = begin; a <= last; a += 64) {
        flush_line((const void*)a);
    }
    _mm_mfence();
}

#endif /* TIMING_H */
