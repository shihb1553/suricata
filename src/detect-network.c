#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-alert.h"
#include "detect-engine-build.h"
#include "detect-engine-register.h"
#include "decode.h"

#include "util-byte.h"
#include "util-ip.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

#include "detect-network.h"

/* format: network: <network>, <mask> */
#define PARSE_REGEX  "^\\s*(((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3})\\s*,\\s*((0x)?[0-9|a-f|A-F]{8})\\s*$"
static DetectParseRegex parse_regex;

static DetectNetworkData *DetectNetworkParse(const char *rawstr)
{
    DetectNetworkData *nd = SCCalloc(1, sizeof(DetectNetworkData));
    if (unlikely(nd == NULL))
        return NULL;

    pcre2_match_data *match = NULL;
    int ret = DetectParsePcreExec(&parse_regex, &match, rawstr, 0, 0);
    if (ret < 1) {
        SCLogError("parse error, ret %" PRId32 ", string %s", ret, rawstr);
        goto error;
    }
    SCLogDebug("parse success, ret %d", ret);

    size_t pcre2_len;
    const char *str_ptr = NULL;
    int res = pcre2_substring_get_bynumber(match, 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0 || str_ptr == NULL) {
        SCLogError("pcre2_substring_get_bynumber 1 failed");
        goto error;
    }
    struct in_addr *ipv4_addr = NULL;
    struct in6_addr *ipv6_addr = NULL;
    SCLogDebug("network: %s", str_ptr);
    if (strchr(str_ptr, ':') == NULL) {
        if ((ipv4_addr = ValidateIPV4Address(str_ptr)) == NULL) {
            SCLogError("Invalid argument for network. Must be a valid IPv4 address (%s)",
                    rawstr);
            goto error;
        }
        nd->network.addr_data32[0] = ipv4_addr->s_addr;
    } else {
        if ((ipv6_addr = ValidateIPV6Address(str_ptr)) == NULL) {
            SCLogError("Invalid argument for network. Must be a valid IPv6 address (%s)",
                    rawstr);
            goto error;
        }
        nd->network.addr_data32[0] = ipv6_addr->s6_addr32[0];
        nd->network.addr_data32[1] = ipv6_addr->s6_addr32[1];
        nd->network.addr_data32[2] = ipv6_addr->s6_addr32[2];
        nd->network.addr_data32[3] = ipv6_addr->s6_addr32[3];
    }
    pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
    str_ptr = NULL;

    res = pcre2_substring_get_bynumber(match, 9, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0 || str_ptr == NULL) {
        SCLogError("pcre2_substring_get_bynumber 2 failed");
        goto error;
    }
    SCLogDebug("mask: %s", str_ptr);
    if (StringParseUint32(&nd->mask.addr_data32[0], 16, strlen(str_ptr),
                str_ptr) <= 0) {
        SCLogError("Invalid argument for packets. Must be a value in the range of 0 to %" PRIu32
                    " (%s)",
                UINT32_MAX, rawstr);
        goto error;
    }
    nd->mask.addr_data32[0] = htonl(nd->mask.addr_data32[0]);
    SCLogDebug("mask: 0x%x", nd->mask.addr_data32[0]);
    pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
    str_ptr = NULL;

    pcre2_match_data_free(match);
    return nd;

error:
    if (match) {
        pcre2_match_data_free(match);
    }
    if (str_ptr != NULL)
        pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
    if (nd != NULL)
        SCFree(nd);
    return NULL;
}

static int DetectNetworkSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectBufferGetActiveList(de_ctx, s) == -1) {
        SCLogError("datasets are only supported for sticky buffers");
        SCReturnInt(-1);
    }

    int list = s->init_data->list;
    if (list == DETECT_SM_LIST_NOTSET) {
        SCLogError("datasets are only supported for sticky buffers");
        SCReturnInt(-1);
    }
    SCLogDebug("list: %d", list);
    const DetectBufferType *bt = DetectEngineBufferTypeGetById(de_ctx, list);
    if (bt) {
        SCLogDebug("bt: %s", bt->name);
    }

    DetectNetworkData *nd = DetectNetworkParse(rawstr);
    if (nd == NULL)
        SCReturnInt(-1);

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_NETWORK;
    sm->ctx = (SigMatchCtx *)nd;
    SigMatchAppendSMToList(s, sm, list);
    SCReturnInt(0);

error:
    if (nd != NULL)
        SCFree(nd);
    if (sm != NULL)
        SCFree(sm);
    SCReturnInt(-1);
}

static void DetectNetworkFree (DetectEngineCtx *de_ctx, void *ptr)
{
    DetectNetworkData *nd = (DetectNetworkData *)ptr;
    if (nd == NULL)
        return;

    SCFree(nd);
}

/*
    1 match
    0 no match
    -1 can't match
 */
int DetectNetworkBufferMatch(DetectEngineThreadCtx *det_ctx,
    const DetectNetworkData *nd,
    const uint8_t *data, const uint32_t data_len)
{
    SCLogDebug("network: 0x%x, mask: 0x%x", nd->network.addr_data32[0], nd->mask.addr_data32[0]);
    if (data_len == 4) {
        uint32_t addr = *(uint32_t *)data;
        return (addr & nd->mask.addr_data32[0]) == nd->network.addr_data32[0];
    }
    return 0;
}


#ifdef UNITTESTS

static int DetectNetworkParseTest01(void)
{
    int result = 0;
    DetectNetworkData *nd = NULL;
    nd = DetectNetworkParse(" 11.24.0.10, 0xFFFF00FF ");
    if (nd != NULL && nd->network.addr_data32[0] == htonl(0x0b18000a)
        && nd->mask.addr_data32[0] == htonl(0xffff00ff)) {
        DetectNetworkFree(NULL, nd);
        result = 1;
    }

    return result;
}

static int DetectNetworkMatchTest02(void)
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

    const char *sigs[1];
    char sig[] = "alert tcp any any -> any any (msg:\"Testing network 1\"; ip.dst; network: 192.168.1.0, 0xFFFFFF00; sid:1;)";
    sigs[0] = sig;
    FAIL_IF(UTHAppendSigs(de_ctx, sigs, 1) == 0);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->ts = TimeGet();
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1) == 0);

    UTHFreePackets(&p, 1);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    FlowShutdown();
    StorageCleanup();

    PASS;
}

static void DetectNetworkRegisterTests(void)
{
    UtRegisterTest("DetectNetworkParseTest01", DetectNetworkParseTest01);
    UtRegisterTest("DetectNetworkMatchTest02", DetectNetworkMatchTest02);
}
#endif

void DetectNetworkRegister(void)
{
    sigmatch_table[DETECT_NETWORK].name = "network";
    sigmatch_table[DETECT_NETWORK].desc = "match ip.addr's network";
    sigmatch_table[DETECT_NETWORK].Setup = DetectNetworkSetup;
    sigmatch_table[DETECT_NETWORK].Free  = DetectNetworkFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_NETWORK].RegisterTests = DetectNetworkRegisterTests;
#endif

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}
