#include "suricata-common.h"
#include "suricata-plugin.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-engine-alert.h"
#include "detect-engine-build.h"
#include "detect-engine-mpm.h"
#include "detect-engine-uint.h"
#include "detect-engine-helper.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#define MODULE_NAME         "detect-time"


static int g_detect_time_id = 0;

static void DetectTimeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU64Free(ptr);
}

static int DetectTimeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU64Data *du64 = DetectU64Parse(rawstr);
    if (du64 == NULL)
        return -1;

    SCTime_t current_time = TimeGet();
    if (DetectU64Match((uint64_t)current_time.secs, du64) == 0) {
        SCLogInfo("Signature is timeout");
        DetectTimeFree(de_ctx, du64);
        return -5;
    }

    SCSigMatchAppendSMToList(de_ctx, s, g_detect_time_id, (SigMatchCtx *)du64, DETECT_SM_LIST_MATCH);
    return 0;
}

static int DetectTimeMatch(DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    SCLogDebug("Matching time %lu", (uint64_t)TimeGet().secs);
    return DetectU64Match((uint64_t)TimeGet().secs, (DetectU64Data *)ctx);
}

#ifdef UNITTESTS
static void DetectTimeRegisterTests(void);
#endif

void TimeInit(void)
{
    SCLogDebug("Initializing Time plugin");

    /* SCSigTableAppLiteElmt and SCDetectHelperKeywordRegister don't yet
     * support all the fields required to register the time keywords,
     * missing the (packet) Match callback,
     * so we'll just register with an empty keyword specifier to get
     * the ID, then fill in the ID. */
    g_detect_time_id = SCDetectHelperNewKeywordId();
    SCLogDebug("Registered new detect time keyword with ID %" PRIu32, g_detect_time_id);

    sigmatch_table[g_detect_time_id].name = "time";
    sigmatch_table[g_detect_time_id].desc = "rule timeout keyword";
    sigmatch_table[g_detect_time_id].Match = DetectTimeMatch;
    sigmatch_table[g_detect_time_id].Setup = DetectTimeSetup;
    sigmatch_table[g_detect_time_id].Free = DetectTimeFree;
#ifdef UNITTESTS
    sigmatch_table[g_detect_time_id].RegisterTests = DetectTimeRegisterTests;
#endif
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = MODULE_NAME,
    .author = "shihb1553",
    .license = "GPLv3",
    .Init = TimeInit,
};

const SCPlugin *SCPluginRegister()
{
    return &PluginRegistration;
}

#ifdef UNITTESTS

static int DetectTimeTest01(void)
{
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint16_t buf_len = strlen((char *)buf);

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    StorageInit();
    StorageFinalize();

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Packet *p = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);

    SCTime_t current_time = TimeGet();

    const char *sigs[1];
    char sig[128] = {0};
    snprintf(sig, sizeof(sig),
        "alert tcp any any -> any any (msg:\"Testing time 1\"; content:\"Hi all\"; time:<%ld; sid:1;)",
        (uint64_t)(current_time.secs + 3));
    sigs[0] = sig;
    FAIL_IF(UTHAppendSigs(de_ctx, sigs, 1) == 0);

    SCLogDebug("Testing time 1, %lu, %s", (uint64_t)current_time.secs, sig);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->ts = TimeGet();
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1) == 0);
    SCLogDebug("Testing time 2, %lu", (uint64_t)p->ts.secs);

    TimeSetIncrementTime(4);

    p->ts = TimeGet();
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1) != 0);
    SCLogDebug("Testing time 3, %lu", (uint64_t)p->ts.secs);

    UTHFreePackets(&p, 1);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StorageCleanup();

    PASS;
}

/**
 * \brief this function registers unit tests for DetectTime
 */
void DetectTimeRegisterTests(void)
{
    UtRegisterTest("DetectTimeTest01", DetectTimeTest01);
}
#endif /* UNITTESTS */
