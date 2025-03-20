#include "suricata-common.h"
#include "suricata.h"
#include "runmodes.h"
#include "ray-plugin.h"
#include "util-debug.h"
#include "util-cpu.h"
#include "host-storage.h"
#include "flow-storage.h"
#include "ippair-storage.h"
#include "device-storage.h"
#include "packet-storage.h"

#ifdef HAVE_RAY_PLUGIN

#include <dlfcn.h>

#define RAY_PLUGIN_MODULE_NAME      "ray-plugin"
#define RAY_PLUGIN_NUM_MAX          128

// https://github.com/jasonish/suricata-example-plugins/blob/main/c-flow-logger/flowlogger.c

typedef struct RayPluginListNode_ {
    int plugin_id;
    int total_call;
    uint64_t total_time;

    const SCRayPlugin *plugin;

    int16_t storage_id[SC_RAY_PLUGIN_PVT_MAX];

    TAILQ_ENTRY(RayPluginListNode_) next;
    TAILQ_ENTRY(RayPluginListNode_) next_hook[SC_RAY_PLUGIN_HOOK_MAX];
} RayPluginListNode;

/**
 * The list of loaded plugins.
 *
 * Currently only used as a place to stash the pointer returned from
 * dlopen, but could have other uses, such as a plugin unload destructor.
 */
static TAILQ_HEAD(, RayPluginListNode_) g_ray_plugin_total_list;
static TAILQ_HEAD(, RayPluginListNode_) g_ray_plugin_hook_array[SC_RAY_PLUGIN_HOOK_MAX];

static int g_ray_plugin_cnt;

static void *g_ray_plugin_lib_handles[RAY_PLUGIN_NUM_MAX];

static void *g_ray_plugin_global_data[RAY_PLUGIN_NUM_MAX];
static thread_local void *g_ray_plugin_thread_data[RAY_PLUGIN_NUM_MAX];

typedef struct RayPluginStorageConf_ {
    int cnt;
    int mapping[RAY_PLUGIN_NUM_MAX];
} RayPluginStorageConf;

static RayPluginStorageConf g_ray_plugin_storage_conf[SC_RAY_PLUGIN_PVT_MAX];

#define RAYPLUGIN_PROFILE_START(plugin_entry) \
    uint64_t ray_plugin_profile_ticks = 0; \
    if (plugin_entry->plugin->profiling) { \
        ray_plugin_profile_ticks = UtilCpuGetTicks(); \
    }

#define RAYPLUGIN_PROFILE_END(plugin_entry) \
    if (plugin_entry->plugin->profiling) { \
        plugin_entry->total_time += (UtilCpuGetTicks() - ray_plugin_profile_ticks); \
        plugin_entry->total_call++; \
    }


static void RayPluginCallPointBase(ThreadVars *tv, Packet *p, enum SCRayPluginHook hook)
{
    RayPluginListNode *plugin_entry;

    plugin_entry = TAILQ_FIRST(&g_ray_plugin_hook_array[hook]);
    while (plugin_entry) {
        RAYPLUGIN_PROFILE_START(plugin_entry);

        ((RayPluginCallPointFuncBase)(plugin_entry->plugin->Func[hook]))(tv, p);

        RAYPLUGIN_PROFILE_END(plugin_entry);

        plugin_entry = TAILQ_NEXT(plugin_entry, next_hook[hook]);
    }

    return ;
}

static void RayPluginCallPointWithData(ThreadVars *tv, Packet *p, enum SCRayPluginHook hook, void *data)
{
    RayPluginListNode *plugin_entry;

    plugin_entry = TAILQ_FIRST(&g_ray_plugin_hook_array[hook]);
    while (plugin_entry) {
        RAYPLUGIN_PROFILE_START(plugin_entry);

        ((RayPluginCallPointFuncWithData)(plugin_entry->plugin->Func[hook]))(tv, p, data);

        RAYPLUGIN_PROFILE_END(plugin_entry);

        plugin_entry = TAILQ_NEXT(plugin_entry, next_hook[hook]);
    }

    return ;
}

void RayPluginCallPointDecode(ThreadVars *tv, Packet *p)
{
    RayPluginCallPointBase(tv, p, SC_RAY_PLUGIN_HOOK_DECODE);
}

void RayPluginCallPointFlowWorker(ThreadVars *tv, Packet *p)
{
    RayPluginCallPointBase(tv, p, SC_RAY_PLUGIN_HOOK_FLOW_WORKER);
}

void RayPluginCallPointStreamState(ThreadVars *tv, Packet *p)
{
    RayPluginCallPointBase(tv, p, SC_RAY_PLUGIN_HOOK_STREAM_STATE);
}

void RayPluginCallPointAppDetectEnd(ThreadVars *tv, Packet *p)
{
    RayPluginCallPointBase(tv, p, SC_RAY_PLUGIN_HOOK_APP_DETECT_END);
}

void RayPluginCallPointAppParse(ThreadVars *tv, Packet *p)
{
    RayPluginCallPointBase(tv, p, SC_RAY_PLUGIN_HOOK_APP_PARSE);
}

void RayPluginCallPointDetectNone(ThreadVars *tv, Packet *p)
{
    RayPluginCallPointBase(tv, p, SC_RAY_PLUGIN_HOOK_DETECT_NONE);
}

void RayPluginCallPointDetectSgh(ThreadVars *tv, Packet *p, void *data)
{
    RayPluginCallPointWithData(tv, p, SC_RAY_PLUGIN_HOOK_DETECT_SGH, data);
}

void RayPluginCallPointDetectEnd(ThreadVars *tv, Packet *p)
{
    RayPluginCallPointBase(tv, p, SC_RAY_PLUGIN_HOOK_DETECT_END);
}

void RayPluginCallPointOutputFileData(ThreadVars *tv, Packet *p, void *data)
{
    RayPluginCallPointWithData(tv, p, SC_RAY_PLUGIN_HOOK_OUTPUT_FILEDATA, data);
}

void RayPluginCallPointOutput(ThreadVars *tv, Packet *p)
{
    RayPluginCallPointBase(tv, p, SC_RAY_PLUGIN_HOOK_OUTPUT);
}

void RayPluginLoad(void)
{
    int plugin_num = 0;

    TAILQ_INIT(&g_ray_plugin_total_list);
    for (int i = 0; i < SC_RAY_PLUGIN_HOOK_MAX; i++) {
        TAILQ_INIT(&g_ray_plugin_hook_array[i]);
    }

    const char *plugin_dir = NULL;
    if (ConfGet("ray-plugin.dir", &plugin_dir) != 1) {
        return ;
    }

    if (plugin_dir == NULL) {
        SCLogError("Plugin dir is NULL");
        return ;
    }

    DIR *dir = opendir(plugin_dir);
    if (dir == NULL) {
        SCLogError("Failed to open plugin directory %s: %s", plugin_dir, strerror(errno));
        return ;
    }
    closedir(dir);

    g_ray_plugin_lib_handles[plugin_num] = dlopen(NULL, RTLD_NOW|RTLD_GLOBAL);
    if (g_ray_plugin_lib_handles[plugin_num] == NULL) {
        SCLogError("Failed to open global symbol: %s", dlerror());
    }
    plugin_num++;

    ConfNode *plugins = ConfGetNode("ray-plugin.plugins");
    if (plugins == NULL) {
        return ;
    }

    ConfNode *seq_plugin, *plugin;
    TAILQ_FOREACH(seq_plugin, &plugins->head, next) {
        int dlmode = RTLD_NOW;
        plugin = ConfNodeLookupChild(seq_plugin, seq_plugin->val);
        if (plugin == NULL)
            continue;

        /* By default an plugin is enabled */
        const char *value_str = ConfNodeLookupChildValue(plugin, "enabled");
        if (value_str != NULL && ConfValIsFalse(value_str))
            continue;

        if (plugin_num >= RAY_PLUGIN_NUM_MAX) {
            SCLogError("Plugin num exceed %d", RAY_PLUGIN_NUM_MAX);
            break;
        }

        value_str = ConfNodeLookupChildValue(plugin, "global");
        if (value_str != NULL && ConfValIsTrue(value_str)) {
            dlmode |= RTLD_GLOBAL;
        }

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s.so", plugin_dir, plugin->name);
        g_ray_plugin_lib_handles[plugin_num] = dlopen(path, dlmode);
        if (g_ray_plugin_lib_handles[plugin_num] == NULL) {
            SCLogNotice("Failed to open %s as a plugin: %s", path, dlerror());
        } else {
            plugin_num++;
        }
    }
}

void RayPluginInit(void)
{
    int ret = 0;

    //init func

    RayPluginListNode *node;
    TAILQ_FOREACH(node, &g_ray_plugin_total_list, next) {
        const SCRayPlugin *plugin = node->plugin;
        ret = ((RayPluginCallPointInitFunc)(plugin->Init))();
        if (ret) {
            SCLogError("Failed to init for plugin %s", plugin->plugin_name);
        }
    }
}

void RayPluginDestroy(void)
{
    RayPluginListNode *node, *tmp_node;

    TAILQ_FOREACH_SAFE(node, &g_ray_plugin_total_list, next, tmp_node) {
        const SCRayPlugin *plugin = node->plugin;
        ((RayPluginCallPointFiniFunc)(plugin->Fini))();

        SCFree(node);
    }

    for (int i = 0; i < g_ray_plugin_cnt; i++) {
        if (g_ray_plugin_lib_handles[i]) {
            dlclose(g_ray_plugin_lib_handles[i]);
        }
    }
}


/*
 * for external call
 */
static int SCRayPluginStorageRegister(const enum SCRayPluginPVT type, const char *plugin_name, int plugin_id, void (*Free)(void *))
{
    switch (type) {
        case SC_RAY_PLUGIN_PVT_HOST: {
            HostStorageId host = HostStorageRegister(plugin_name, sizeof(void *), NULL, Free);
            return host.id;
        }
        case SC_RAY_PLUGIN_PVT_FLOW: {
            FlowStorageId flow = FlowStorageRegister(plugin_name, sizeof(void *), NULL, Free);
            return flow.id;
        }
        case SC_RAY_PLUGIN_PVT_IPPAIR: {
            IPPairStorageId ippair = IPPairStorageRegister(plugin_name, sizeof(void *), NULL, Free);
            return ippair.id;
        }
        case SC_RAY_PLUGIN_PVT_DEVICE: {
            LiveDevStorageId device = LiveDevStorageRegister(plugin_name, sizeof(void *), NULL, Free);
            return device.id;
        }
        case SC_RAY_PLUGIN_PVT_PACKET: {
            PacketStorageId packet = PacketStorageRegister(plugin_name, sizeof(void *), NULL, Free);
            return packet.id;
        }
        case SC_RAY_PLUGIN_PVT_GLOBAL:
        case SC_RAY_PLUGIN_PVT_THREAD:
            return plugin_id;
        default:
            return -1;
    }
}

static int SCRayPluginSetStorageBuffer(void *ptr, enum SCRayPluginPVT type, int storage_id, void *data)
{
    switch (type) {
        case SC_RAY_PLUGIN_PVT_HOST: {
            HostStorageId host = {.id = storage_id};
            return HostSetStorageById((Host *)ptr, host, data);
        }
        case SC_RAY_PLUGIN_PVT_FLOW: {
            FlowStorageId flow = {.id = storage_id};
            return FlowSetStorageById((Flow *)ptr, flow, data);
        }
        case SC_RAY_PLUGIN_PVT_IPPAIR: {
            IPPairStorageId ippair = {.id = storage_id};
            return IPPairSetStorageById((IPPair *)ptr, ippair, data);
        }
        case SC_RAY_PLUGIN_PVT_DEVICE: {
            LiveDevStorageId device = {.id = storage_id};
            return LiveDevSetStorageById((LiveDevice *)ptr, device, data);
        }
        case SC_RAY_PLUGIN_PVT_PACKET: {
            PacketStorageId packet = {.id = storage_id};
            return PacketSetStorageById((Packet *)ptr, packet, data);
        }
        case SC_RAY_PLUGIN_PVT_GLOBAL: {
            g_ray_plugin_global_data[storage_id] = data;
            return 0;
        }
        case SC_RAY_PLUGIN_PVT_THREAD: {
            g_ray_plugin_thread_data[storage_id] = data;
            return 0;
        }
        default:
            return -1;
    }
}

static void *SCRayPluginGetStorageBuffer(void *ptr, enum SCRayPluginPVT type, int storage_id)
{
    switch (type) {
        case SC_RAY_PLUGIN_PVT_HOST: {
            HostStorageId host = {.id = storage_id};
            return HostGetStorageById((Host *)ptr, host);
        }
        case SC_RAY_PLUGIN_PVT_FLOW: {
            FlowStorageId flow = {.id = storage_id};
            return FlowGetStorageById((Flow *)ptr, flow);
        }
        case SC_RAY_PLUGIN_PVT_IPPAIR: {
            IPPairStorageId ippair = {.id = storage_id};
            return IPPairGetStorageById((IPPair *)ptr, ippair);
        }
        case SC_RAY_PLUGIN_PVT_DEVICE: {
            LiveDevStorageId device = {.id = storage_id};
            return LiveDevGetStorageById((LiveDevice *)ptr, device);
        }
        case SC_RAY_PLUGIN_PVT_PACKET: {
            PacketStorageId packet = {.id = storage_id};
            return PacketGetStorageById((Packet *)ptr, packet);
        }
        case SC_RAY_PLUGIN_PVT_GLOBAL: {
            return g_ray_plugin_global_data[storage_id];
        }
        case SC_RAY_PLUGIN_PVT_THREAD: {
            return g_ray_plugin_thread_data[storage_id];
        }
        default:
            return NULL;
    }
}

int SCRayPluginSetStorageInfo(void *ptr, enum SCRayPluginPVT type, int plugin_id, void *data)
{
    if (unlikely(ptr == NULL)) {
        return -1;
    }

    if (unlikely(plugin_id >= g_ray_plugin_cnt)) {
        return -1;
    }

    int storage_id = g_ray_plugin_storage_conf[type].mapping[plugin_id];
    void *buffer = SCRayPluginGetStorageBuffer(ptr, type, storage_id);
    if (unlikely(buffer)) {
        return -1;
    }

    return SCRayPluginSetStorageBuffer(ptr, type, storage_id, data);
}

void *SCRayPluginGetStorageInfo(void *ptr, enum SCRayPluginPVT type, int plugin_id)
{
    if (unlikely(ptr == NULL)) {
        return NULL;
    }

    if (unlikely(plugin_id >= g_ray_plugin_cnt)) {
        return NULL;
    }

    int storage_id = g_ray_plugin_storage_conf[type].mapping[plugin_id];
    return SCRayPluginGetStorageBuffer(ptr, type, storage_id);
}

int SCRayPluginRegister(const SCRayPlugin *plugin, int *plugin_id)
{
    RayPluginListNode *node;

    if (unlikely(plugin == NULL || plugin_id == NULL)) {
        SCLogError("Invalid function pointer");
        return -1;
    }

    if (g_ray_plugin_cnt >= RAY_PLUGIN_NUM_MAX) {
        SCLogError("Plugin num exceed %d", RAY_PLUGIN_NUM_MAX);
        return -1;
    }

    TAILQ_FOREACH(node, &g_ray_plugin_total_list, next) {
        if (!strcmp(plugin->plugin_name, node->plugin->plugin_name)) {
            SCLogError("Plugin %s exist", plugin->plugin_name);
            return -1;
        }
    }

    if (plugin->Init == NULL || plugin->Func == NULL || plugin->Fini == NULL) {
        SCLogError("Invalid function pointer");
        return -1;
    }

    node = SCCalloc(1, sizeof(*node));
    if (node == NULL) {
        SCLogError("Failed to allocate memory for plugin %s", plugin->plugin_name);
        return -1;
    }

    node->plugin = plugin;
    node->plugin_id = g_ray_plugin_cnt++;

    for (int i = 0; i < SC_RAY_PLUGIN_PVT_MAX; i++) {
        if (plugin->Free[i] == NULL) {
            continue;
        }
        RayPluginStorageConf *conf = &g_ray_plugin_storage_conf[i];
        node->storage_id[i] = SCRayPluginStorageRegister(i, plugin->plugin_name, node->plugin_id, plugin->Free[i]);
        conf->mapping[conf->cnt++] = node->storage_id[i];
    }

    TAILQ_INSERT_TAIL(&g_ray_plugin_total_list, node, next);
    for (int i = 0; i < SC_RAY_PLUGIN_HOOK_MAX; i++) {
        RayPluginListNode *prev= NULL, *tmp = NULL;
        if (plugin->Func[i] == NULL) {
            continue;
        }
        tmp = TAILQ_FIRST(&g_ray_plugin_hook_array[i]);
        while (tmp) {
            if (plugin->priority <= tmp->plugin->priority) {
                break;
            }
            prev = tmp;
            tmp = TAILQ_NEXT(tmp, next_hook[i]);
        }
        if (prev) {
            TAILQ_INSERT_AFTER(&g_ray_plugin_hook_array[i], prev, node, next_hook[i]);
        } else {
            TAILQ_INSERT_HEAD(&g_ray_plugin_hook_array[i], node, next_hook[i]);
        }
    }

    SCLogNotice("Initializing ray-plugin %s", plugin->plugin_name);

    *plugin_id = node->plugin_id;
    return 0;
}

void *SCRayPluginGetSymbol(const char *sym)
{
    dlerror();

    void *result = dlsym(g_ray_plugin_lib_handles[0], sym);

    char *error = dlerror();
    if (error != NULL) {
        SCLogError("No symbol %s", sym);
        return NULL;
    }
    return result;
}

const char *SCRayPluginGetHookName(enum SCRayPluginHook hook)
{
    static const char *plugin_hook_name[] = {
        "decode",
        "flow-worker",
        "stream-state",
        "app-detect-end",
        "app-parse",
        "detect-none",
        "detect-sgh",
        "detect-end",
        "output-filedata",
        "output",
        "unknown"
    };

    return plugin_hook_name[hook];
}

#endif
