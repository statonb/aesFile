#ifndef _STRLCAT_H_
#define _STRLCAT_H_

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t strlcat(char *dst, const char *src, size_t dst_sz);

#ifdef __cplusplus
}
#endif

#endif // _STRLCAT_H_

