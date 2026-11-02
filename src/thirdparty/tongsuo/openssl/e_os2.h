/* tongsuo/openssl/e_os2.h - 最小兼容头 */
#ifndef TONSUO_E_OS2_H
#define TONSUO_E_OS2_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifndef ossl_inline
#  define ossl_inline inline
#endif
#ifndef OSSL_NELEM
#  define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))
#endif

#endif
