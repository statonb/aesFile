#ifndef _STRLCPY_H_
#define _STRLCPY_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t strlcpy(char *dst, const char *src, size_t dst_sz);

#ifdef __cplusplus
}
#endif

#endif // _STRLCPY_H_

