/* x86intrin.h - 最小兼容头（本项目原创，非上游文件）
 *
 * 上游 dudect.h 在 x86 上 #include <x86intrin.h>，该头是 GCC/Clang 提供的；
 * MSVC 没有同名头，但有等价的 intrinsics（放在 <intrin.h>）。
 *
 * 这里只补 dudect.h 实际用到的两个：
 *   _mm_mfence()  -> MSVC 的 _mm_mfence（同样来自 <intrin.h>）
 *   __rdtsc()     -> MSVC 的 __rdtsc
 *
 * 不改变任何语义：两者都是"全屏障 + 读时间戳计数器"。
 */
#ifndef HENGSHI_X86INTRIN_SHIM_H
#define HENGSHI_X86INTRIN_SHIM_H

#include <intrin.h>

#endif /* HENGSHI_X86INTRIN_SHIM_H */
