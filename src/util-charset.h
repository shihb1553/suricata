#ifndef __UTIL_CHARSET_H__
#define __UTIL_CHARSET_H__

#include "suricata-common.h"

int CharsetMemoryConvert(const char *from, const char *to, const char *input, size_t in_len, char **output, size_t *out_len);

void UtilCharsetTests(void);

#endif /* __UTIL_CHARSET_H__ */
