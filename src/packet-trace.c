#include "suricata-common.h"
#include "ray-plugin-ext.h"
#include "util-mem.h"
#include "util-debug.h"
#include "util-print.h"
#include "util-file.h"
#include "stream-tcp.h"
#include "detect.h"

#define PLUGIN_NAME     "packet-trace"
#define OUTPUT_LEN      1024
#define TEST_PORT       8080


typedef struct PluginResult_ {
    uint64_t tm;
    int len;
    char buffer[OUTPUT_LEN];
} PluginResult;

static int g_plugin_id;

// CPPFLAGS=-I$HOME/usr/include make -f Makefile.packet-trace

static void PluginFuncDecode(ThreadVars *tv, Packet *p)
{
    if (unlikely(p == NULL)) {
        return ;
    }
    if (p->datalink != LINKTYPE_ETHERNET || p->ip4h == NULL) {
        return ;
    }
    if (p->proto != IPPROTO_TCP || (p->sp != TEST_PORT && p->dp != TEST_PORT)) {
        return ;
    }

    PluginResult *result = calloc(1, sizeof(PluginResult));
    if (unlikely(result == NULL)) {
        return ;
    }

    char s[16], d[16];
    PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), s, sizeof(s));
    PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), d, sizeof(d));
    result->len += snprintf(&result->buffer[result->len], OUTPUT_LEN-result->len,
            "%s pcap_cnt: %lu, flow_hash: %u, timestamp: %lu\n"
            "\thook-%d(%s): %s/%hu -> %s/%hu PROTO: tcp\n",
            PLUGIN_NAME, p->pcap_cnt, p->flow_hash, SCTIME_MSECS(p->ts),
            SC_RAY_PLUGIN_HOOK_DECODE, SCRayPluginGetHookName(SC_RAY_PLUGIN_HOOK_DECODE),
            s, GET_TCP_SRC_PORT(p), d, GET_TCP_DST_PORT(p));

    if (SCRayPluginSetStorageInfo(p, SC_RAY_PLUGIN_PVT_PACKET, g_plugin_id, result)) {
        free(result);
    }
}

static void PluginFuncFlowWorker(ThreadVars *tv, Packet *p)
{
    if (unlikely(p == NULL)) {
        return ;
    }

    PluginResult *result = SCRayPluginGetStorageInfo(p, SC_RAY_PLUGIN_PVT_PACKET, g_plugin_id);
    if (result == NULL) {
        return ;
    }
    result->len += snprintf(&result->buffer[result->len], OUTPUT_LEN-result->len,
            "\thook-%d(%s): match flow: %p\n",
            SC_RAY_PLUGIN_HOOK_FLOW_WORKER, SCRayPluginGetHookName(SC_RAY_PLUGIN_HOOK_FLOW_WORKER),
            p->flow);
    return ;
}

static void PluginFuncStreamState(ThreadVars *tv, Packet *p)
{
    if (unlikely(p == NULL || p->flow == NULL)) {
        return ;
    }

    TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    if (ssn == NULL) {
        return ;
    }

    PluginResult *result = SCRayPluginGetStorageInfo(p, SC_RAY_PLUGIN_PVT_PACKET, g_plugin_id);
    if (result == NULL) {
        return ;
    }
    result->len += snprintf(&result->buffer[result->len], OUTPUT_LEN-result->len,
            "\thook-%d(%s): stream state change: %s\n",
            SC_RAY_PLUGIN_HOOK_STREAM_STATE, SCRayPluginGetHookName(SC_RAY_PLUGIN_HOOK_STREAM_STATE),
            StreamTcpStateAsString(ssn->state));
    return ;
}

static void PluginFuncAppDetectEnd(ThreadVars *tv, Packet *p)
{
    if (unlikely(p == NULL || p->flow == NULL)) {
        return ;
    }

    PluginResult *result = SCRayPluginGetStorageInfo(p, SC_RAY_PLUGIN_PVT_PACKET, g_plugin_id);
    if (result == NULL) {
        return ;
    }
    result->len += snprintf(&result->buffer[result->len], OUTPUT_LEN-result->len,
            "\thook-%d(%s): alproto-%hu, alproto_ts-%hu, approto_tc-%hu, alproto_orig-%hu, alproto_expect-%hu\n",
            SC_RAY_PLUGIN_HOOK_APP_DETECT_END, SCRayPluginGetHookName(SC_RAY_PLUGIN_HOOK_APP_DETECT_END),
            p->flow->alproto, p->flow->alproto_ts, p->flow->alproto_tc, p->flow->alproto_orig, p->flow->alproto_expect);
    return ;
}

static void PluginFuncAppParse(ThreadVars *tv, Packet *p)
{
    if (unlikely(p == NULL)) {
        return ;
    }

    PluginResult *result = SCRayPluginGetStorageInfo(p, SC_RAY_PLUGIN_PVT_PACKET, g_plugin_id);
    if (result == NULL) {
        return ;
    }
    return ;
}

static void PluginFuncDetectNone(ThreadVars *tv, Packet *p)
{
    if (unlikely(p == NULL)) {
        return ;
    }

    PluginResult *result = SCRayPluginGetStorageInfo(p, SC_RAY_PLUGIN_PVT_PACKET, g_plugin_id);
    if (result == NULL) {
        return ;
    }
    result->len += snprintf(&result->buffer[result->len], OUTPUT_LEN-result->len,
            "\thook-%d(%s): detect is none\n",
            SC_RAY_PLUGIN_HOOK_DETECT_NONE, SCRayPluginGetHookName(SC_RAY_PLUGIN_HOOK_DETECT_NONE));
    return ;
}

static void PluginFuncDetectSgh(ThreadVars *tv, Packet *p, void *data)
{
    if (unlikely(p == NULL || data == NULL)) {
        return ;
    }

    SigGroupHead *sgh = (SigGroupHead *)data;
    PluginResult *result = SCRayPluginGetStorageInfo(p, SC_RAY_PLUGIN_PVT_PACKET, g_plugin_id);
    if (result == NULL) {
        return ;
    }
    result->len += snprintf(&result->buffer[result->len], OUTPUT_LEN-result->len,
            "\thook-%d(%s): sgh flags-0x%x, filestore_cnt-%hu\n",
            SC_RAY_PLUGIN_HOOK_DETECT_SGH, SCRayPluginGetHookName(SC_RAY_PLUGIN_HOOK_DETECT_SGH),
            sgh->flags, sgh->filestore_cnt);
    return ;
}

static void PluginFuncDetectEnd(ThreadVars *tv, Packet *p)
{
    if (unlikely(p == NULL)) {
        return ;
    }

    PluginResult *result = SCRayPluginGetStorageInfo(p, SC_RAY_PLUGIN_PVT_PACKET, g_plugin_id);
    if (result == NULL) {
        return ;
    }
    result->len += snprintf(&result->buffer[result->len], OUTPUT_LEN-result->len,
            "\thook-%d(%s): match alert count: %hu\n",
            SC_RAY_PLUGIN_HOOK_DETECT_END, SCRayPluginGetHookName(SC_RAY_PLUGIN_HOOK_DETECT_END),
            p->alerts.cnt);
    return ;
}

static void PluginFuncOutputFileData(ThreadVars *tv, Packet *p, void *data)
{
    if (unlikely(p == NULL || data == NULL)) {
        return ;
    }

    File *f = (File *)data;
    PluginResult *result = SCRayPluginGetStorageInfo(p, SC_RAY_PLUGIN_PVT_PACKET, g_plugin_id);
    if (result == NULL) {
        return ;
    }
    result->len += snprintf(&result->buffer[result->len], OUTPUT_LEN-result->len,
            "\thook-%d(%s): file flags-0x%x, state-%d\n",
            SC_RAY_PLUGIN_HOOK_OUTPUT_FILEDATA, SCRayPluginGetHookName(SC_RAY_PLUGIN_HOOK_OUTPUT_FILEDATA),
            f->flags, f->state);
    return ;
}

static void PluginFuncOutput(ThreadVars *tv, Packet *p)
{
    if (unlikely(p == NULL)) {
        return ;
    }

    PluginResult *result = SCRayPluginGetStorageInfo(p, SC_RAY_PLUGIN_PVT_PACKET, g_plugin_id);
    if (result == NULL) {
        return ;
    }
    printf("%s\n", result->buffer);
    return ;
}

static void PluginFree(void *ptr)
{
    SCLogDebug("Ready to free data: %p", ptr);

    if (ptr)
        free(ptr);
}

static int PluginInit(void)
{
    SCLogNotice("%s module init", PLUGIN_NAME);
    return 0;
}

static void PluginFini(void)
{
    SCLogNotice("%s module finish", PLUGIN_NAME);
    return ;
}

const SCRayPlugin Plugin = {
    .plugin_name = PLUGIN_NAME,
    .profiling = 1,
    .priority = RAY_PLUGIN_PRIORITY_MAX,
    .Init = PluginInit,
    .Free[SC_RAY_PLUGIN_PVT_PACKET] = PluginFree,
    .Func = {
        PluginFuncDecode,
        PluginFuncFlowWorker,
        PluginFuncStreamState,
        PluginFuncAppDetectEnd,
        PluginFuncAppParse,
        PluginFuncDetectNone,
        PluginFuncDetectSgh,
        PluginFuncDetectEnd,
        PluginFuncOutputFileData,
        PluginFuncOutput,
    },
    .Fini = PluginFini
};

void __attribute__((constructor))__init(void)
{
    int ret = SCRayPluginRegister(&Plugin, &g_plugin_id);
    if (ret != 0) {
        FatalError("Init error");
    }
}

void __attribute__((destructor))__fini(void)
{
    SCLogNotice("%s module exiting", PLUGIN_NAME);
    return ;
}
