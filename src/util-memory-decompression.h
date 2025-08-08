#ifndef __UTIL_MEMORY_DECOMPRESSION_H__
#define __UTIL_MEMORY_DECOMPRESSION_H__

#include "suricata-common.h"

#include <zlib.h>

#define WINDOW_BITS             15      // GZIP窗口大小
#define GZIP_ENCODING           16      // 启用GZIP头部检测


// based on util-file-swf-decompression.h
int MemoryDecompress(int flag, const Bytef *src, uLong srcLen, Bytef **dst, uLong *dstLen);

#endif /* __UTIL_MEMORY_DECOMPRESSION_H__ */
