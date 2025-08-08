#include "suricata-common.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-engine-alert.h"
#include "detect-engine-build.h"
#include "detect-engine-mpm.h"
#include "detect-engine-uint.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-time.h"


static void DetectTimeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_u64_free(ptr);
}

static int DetectTimeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU64Data *du64 = DetectU64Parse(rawstr);
    if (du64 == NULL)
        return -1;

    SCTime_t current_time = TimeGet();
    if (DetectU64Match((uint64_t)current_time.secs, du64) == FALSE) {
        SCLogInfo("Signature is timeout");
        DetectTimeFree(de_ctx, du64);
        return -5;
    }

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectTimeFree(de_ctx, du64);
        return -1;
    }

    sm->type = DETECT_TIME;
    sm->ctx = (SigMatchCtx *)du64;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
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

void DetectTimeRegister(void)
{
    sigmatch_table[DETECT_TIME].name = "time";
    sigmatch_table[DETECT_TIME].desc = "rule timeout keyword";
    sigmatch_table[DETECT_TIME].Setup = DetectTimeSetup;
    sigmatch_table[DETECT_TIME].Match = DetectTimeMatch;
    sigmatch_table[DETECT_TIME].Free = DetectTimeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_TIME].RegisterTests = DetectTimeRegisterTests;
#endif
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
