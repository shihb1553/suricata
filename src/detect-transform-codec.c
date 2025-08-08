#include "suricata-common.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-alert.h"
#include "detect-engine-build.h"
#include "detect-parse.h"
#include "detect-transform-codec.h"

#include "util-memory-decompression.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-print.h"


// typedef struct DetectTransformZipData {
//     uint8_t *key;
//     // limit the key length
//     uint8_t length;
// } DetectTransformZipData;

static int DetectTransformZipSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    SCEnter();

    int r = DetectSignatureAddTransform(s, DETECT_TRANSFORM_ZIP, NULL);

    SCReturnInt(r);
}

static void DetectTransformZip(InspectionBuffer *buffer, void *options)
{
    const uint8_t *input = buffer->inspect;
    const uint32_t input_len = buffer->inspect_len;
    if (input_len == 0) {
        return;
    }

    // PrintRawDataFp(stdout, input, input_len);

    // 计算压缩后最大长度
    uLong compressed_size = compressBound(input_len);

    uint8_t *output = InspectionBufferCheckAndExpand(buffer, (uint32_t)compressed_size);
    if (output == NULL) {
        return;
    }

    // 压缩数据
    int ret = compress((Bytef *)output, &compressed_size, (const Bytef *)input, input_len);
    if (ret != Z_OK) {
        return;
    }
    // PrintRawDataFp(stdout, output, compressed_size);

    InspectionBufferTruncate(buffer, (uint32_t)compressed_size);
}


#ifdef UNITTESTS

static int DetectTransformZipParseTest01(void)
{
    const char rule[] = "alert http any any -> any any (msg:\"HTTP with zip\"; http.request_line; zip; content:\"|4F C9 2F CF CB C9 4F 4C D1 CB 28 C9 CD 51 F0 08 09 09 D0 37 D4 33|\"; sid:1;)";
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    Signature *s = DetectEngineAppendSig(de_ctx, rule);
    FAIL_IF_NULL(s);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static void DetectTransformZipRegisterTests(void)
{
    UtRegisterTest("DetectTransformZipParseTest01", DetectTransformZipParseTest01);
}
#endif

void DetectTransformCodecRegister(void)
{
    sigmatch_table[DETECT_TRANSFORM_ZIP].name = "zip";
    sigmatch_table[DETECT_TRANSFORM_ZIP].desc = "modify buffer via zip encoding before inspection";
    sigmatch_table[DETECT_TRANSFORM_ZIP].Transform = DetectTransformZip;
    sigmatch_table[DETECT_TRANSFORM_ZIP].Setup = DetectTransformZipSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TRANSFORM_ZIP].RegisterTests = DetectTransformZipRegisterTests;
#endif
    sigmatch_table[DETECT_TRANSFORM_ZIP].flags |= SIGMATCH_NOOPT;
}
