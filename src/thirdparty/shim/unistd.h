/* unistd.h - 最小兼容头（本项目原创，非上游文件）
 *
 * 上游 dudect.h 包含 <unistd.h> 并用 open/read/sleep/close 读 /dev/urandom。
 * MSVC 没有该头，也不存在 /dev/urandom。
 *
 * 处理方式：这里只提供能通过编译的映射；真正的随机源由 tests/dudect_harness.c
 * 用 BCryptGenRandom 提供（编译时把 dudect 自带的 randombytes/randombit 重命名，
 * 使这段 POSIX 代码成为死代码，dudect.h 本身一个字节都不改）。
 */
#ifndef HENGSHI_UNISTD_SHIM_H
#define HENGSHI_UNISTD_SHIM_H

#include <io.h>
#include <fcntl.h>
#include <windows.h>

#ifndef ssize_t
typedef long ssize_t;
#endif

#define open  _open
#define read  _read
#define close _close

#ifndef O_RDONLY
#define O_RDONLY _O_RDONLY
#endif

#ifdef sleep
#undef sleep
#endif
#define sleep(seconds) Sleep((DWORD)((seconds) * 1000))

#endif /* HENGSHI_UNISTD_SHIM_H */
