#include "util-memory-decompression.h"


int MemoryDecompress(int flag, const Bytef *src, uLong srcLen, Bytef **dst, uLong *dstLen) {
    z_stream strm;
    *dst = NULL;
    *dstLen = 0;

    // 初始化流
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = srcLen;
    strm.next_in = (Bytef*)src;

    if (inflateInit2(&strm, flag) != Z_OK)
        return -1;

    // 分配初始输出缓冲区
    uLong outSize = srcLen * 4; // 初始猜测大小
    *dst = (Bytef*)malloc(outSize);
    if (!*dst) {
        inflateEnd(&strm);
        return Z_MEM_ERROR;
    }

    int ret;
    do {
        strm.avail_out = outSize - *dstLen;
        strm.next_out = *dst + *dstLen;

        ret = inflate(&strm, Z_FINISH);

        if (ret == Z_BUF_ERROR || ret == Z_OK) {
            // 需要更多输出空间
            outSize *= 2;
            Bytef *newDst = realloc(*dst, outSize);
            if (!newDst) {
                free(*dst);
                inflateEnd(&strm);
                return Z_MEM_ERROR;
            }
            *dst = newDst;
            strm.avail_out = outSize - *dstLen;
            strm.next_out = *dst + *dstLen;
        }

        *dstLen = strm.total_out;
    } while (ret == Z_BUF_ERROR || ret == Z_OK);

    inflateEnd(&strm);

    if (ret != Z_STREAM_END) {
        free(*dst);
        *dst = NULL;
        return ret;
    }

    return Z_OK;
}
