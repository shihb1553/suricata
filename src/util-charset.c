#include "util-charset.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <iconv.h>
#include <errno.h>
#include <locale.h>


int CharsetMemoryConvert(const char *from, const char *to, const char *input, size_t in_len, char **output, size_t *out_len)
{
    // 创建转换描述符
    iconv_t cd = iconv_open(to, from);
    if (cd == (iconv_t)-1) {
        return -1;
    }

    // 计算输入长度并分配输出缓冲区
    *out_len = in_len * 4 + 1; // 保守估计：UTF-8最多4字节/字符
    *output = malloc(*out_len);
    if (!*output) {
        iconv_close(cd);
        return -1;
    }

    // 设置输入/输出指针
    char *in_ptr = (char *)input;
    char *out_ptr = *output;
    size_t out_bytes_left = *out_len;

    // 执行转换
    size_t result = iconv(cd, &in_ptr, &in_len, &out_ptr, &out_bytes_left);
    // 检查转换结果
    if (result == (size_t)-1) {
        iconv_close(cd);
        free(*output);
        *output = NULL;
        return errno;
    }
    // 关闭转换描述符
    iconv_close(cd);

    *out_len = *out_len - out_bytes_left;

    return 0;
}

#ifdef UNITTESTS

static int CharsetMemoryConvertTest01(void)
{
    char input[] = {0xE4, 0xB8, 0xAD, 0xE5, 0x9B, 0xBD}; // "中国"的UTF-8编码
    char *output = NULL;
    size_t out_len = 0;

    int ret = CharsetMemoryConvert("UTF-8", "GBK", input, sizeof(input), &output, &out_len);
    FAIL_IF(ret != 0);

    char output_expected[] = {0xD6, 0xD0, 0xB9, 0xFA}; // "中国"的GBK编码
    FAIL_IF(memcmp(output, output_expected, out_len) != 0);

    free(output);
    PASS;
}

#endif /* UNITTESTS */

void UtilCharsetTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("CharsetMemoryConvertTest01", CharsetMemoryConvertTest01);
#endif /* UNITTESTS */
}
