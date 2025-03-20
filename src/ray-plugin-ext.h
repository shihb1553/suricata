#ifndef __RAY_PLUGIN_EXT_H__
#define __RAY_PLUGIN_EXT_H__

#include "conf.h"
#include "decode.h"
#include "flow.h"
#include "util-storage.h"

#define RAY_PLUGIN_PRIORITY_MIN     0
#define RAY_PLUGIN_PRIORITY_MAX     99


/* Hook node id */
enum SCRayPluginHook {
    SC_RAY_PLUGIN_HOOK_DECODE,
    SC_RAY_PLUGIN_HOOK_FLOW_WORKER,
    SC_RAY_PLUGIN_HOOK_STREAM_STATE,
    SC_RAY_PLUGIN_HOOK_APP_DETECT_END,
    SC_RAY_PLUGIN_HOOK_APP_PARSE,
    SC_RAY_PLUGIN_HOOK_DETECT_NONE,
    SC_RAY_PLUGIN_HOOK_DETECT_SGH,
    SC_RAY_PLUGIN_HOOK_DETECT_END,
    SC_RAY_PLUGIN_HOOK_OUTPUT_FILEDATA,
    SC_RAY_PLUGIN_HOOK_OUTPUT,
    SC_RAY_PLUGIN_HOOK_MAX
};

/* Private saved data type */
enum SCRayPluginPVT {
    SC_RAY_PLUGIN_PVT_HOST = STORAGE_HOST,
    SC_RAY_PLUGIN_PVT_FLOW = STORAGE_FLOW,
    SC_RAY_PLUGIN_PVT_IPPAIR = STORAGE_IPPAIR,
    SC_RAY_PLUGIN_PVT_DEVICE = STORAGE_DEVICE,

    SC_RAY_PLUGIN_PVT_PACKET = STORAGE_PACKET,

    SC_RAY_PLUGIN_PVT_GLOBAL = STORAGE_MAX,
    SC_RAY_PLUGIN_PVT_THREAD,
    SC_RAY_PLUGIN_PVT_MAX
};

typedef int (*RayPluginCallPointInitFunc)(void);
typedef void (*RayPluginCallPointFiniFunc)(void);

typedef void (*RayPluginCallPointFuncBase)(ThreadVars *, Packet *);
typedef void (*RayPluginCallPointFuncWithData)(ThreadVars *, Packet *, void *);


/**
 * Structure to define a Suricata Ray plugin.
 */
typedef struct SCRayPlugin_ {
    const char *plugin_name;
    int profiling;
    int priority;

    void *Free[SC_RAY_PLUGIN_PVT_MAX];

    void *Init;
    void *Func[SC_RAY_PLUGIN_HOOK_MAX];
    void *Fini;
} SCRayPlugin;

int SCRayPluginRegister(const SCRayPlugin *plugin, int *plugin_id);

int SCRayPluginSetStorageInfo(void *ptr, enum SCRayPluginPVT type, int plugin_id, void *data);
void *SCRayPluginGetStorageInfo(void *ptr, enum SCRayPluginPVT type, int plugin_id);
void *SCRayPluginGetSymbol(const char *sym);
const char *SCRayPluginGetHookName(enum SCRayPluginHook hook);

#endif /* __RAY_PLUGIN_EXT_H__ */
