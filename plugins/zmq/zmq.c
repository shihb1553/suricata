#include <czmq.h>

#include "suricata-common.h"
#include "suricata-plugin.h"
#include "output-eve.h"
#include "util-mem.h"
#include "util-debug.h"

#define PLUGIN_NAME "zmq"

/**
 * Per thread context data for each logging thread.
 */
typedef struct ThreadData_ {
    uint32_t thread_id;

    zsock_t *writer;

    /** The number of records logged on this thread. */
    uint64_t err_alloc;
    uint64_t err_add;
    uint64_t err_send;
    uint64_t success;
} ThreadData;

/**
 * A context object for each eve logger using this output.
 */
typedef struct Context_ {
    /** Verbose, or print to stdout. */
    int verbose;
    int start_port;
    const char *address;
} Context;

SC_ATOMIC_DECLARE(uint32_t, zmq_thread_cnt);

/**
 * This function is called to initialize the output, it can be somewhat thought
 * of like opening a file.
 *
 * \param conf The EVE configuration node using this output.
 *
 * \param threaded If true the EVE subsystem is running in threaded mode.
 *
 * \param data A pointer where context data can be stored relevant to this
 *      output.
 *
 * Eve output plugins need to be thread aware as the threading happens
 * at a lower level than the EVE output, so a flag is provided here to
 * notify the plugin if threading is enabled or not.
 *
 * If the plugin does not work with threads disabled, or enabled, this function
 * should return -1.
 *
 * Note for upgrading a plugin from 6.0 to 7.0: The ConfNode in 7.0 is the
 * configuration for the eve instance, not just a node named after the plugin.
 * This allows the plugin to get more context about what it is logging.
 */
static int ZmqInit(const SCConfNode *conf, const bool threaded, void **data)
{
    Context *context = SCCalloc(1, sizeof(Context));
    if (context == NULL) {
        return -1;
    }

    if (conf == NULL || (conf = SCConfNodeLookupChild(conf, "zmq")) == NULL) {
        goto failed;
    }

    context->verbose = 1;
    context->start_port = 55000;
    SCConfGetChildValueBool(conf, "verbose", &context->verbose);
    SCConfGetChildValueInt(conf, "start-port", (intmax_t *)&context->start_port);
    if (SCConfGetChildValue(conf, "address", &context->address) < 0) {
        goto failed;
    }

    zsys_handler_set(NULL);

    *data = context;
    return 0;

failed:
    if (context) {
        SCFree(context);
    }
    return -1;
}

/**
 * This function is called when the output is closed.
 *
 * This will be called after ThreadDeinit is called for each thread.
 *
 * \param data The data allocated in ZmqInit. It should be cleaned up and
 *      deallocated here.
 */
static void ZmqDeinit(void *data)
{
    Context *ctx = data;
    if (ctx != NULL) {
        SCFree(ctx);
    }
}

/**
 * Initialize per thread context.
 *
 * \param ctx The context created in TemplateInitOutput.
 *
 * \param thread_id An identifier for this thread.
 *
 * \param thread_data Pointer where thread specific context can be stored.
 *
 * When the EVE output is running in threaded mode this will be called once for
 * each output thread with a unique thread_id. For regular file logging in
 * threaded mode Suricata uses the thread_id to construct the files in the form
 * of "eve.<thread_id>.json". This plugin may want to do similar, or open
 * multiple connections to whatever the final logging location might be.
 *
 * In the case of non-threaded EVE logging this function is called
 * once with a thread_id of 0.
 */
static int ZmqThreadInit(const void *ctx, const ThreadId thread_id, void **thread_data)
{
    const Context *context = ctx;
    ThreadData *tdata = SCCalloc(1, sizeof(ThreadData));
    if (tdata == NULL) {
        SCLogError("Failed to allocate thread data");
        return -1;
    }

    tdata->thread_id = SC_ATOMIC_ADD(zmq_thread_cnt, 1);

    char endpoint[128];
    snprintf(endpoint, sizeof(endpoint), "%s:%d", context->address, context->start_port + tdata->thread_id);
    tdata->writer = zsock_new_push(endpoint);
    if (tdata->writer == NULL) {
        SCLogError("Failed to create ZMQ socket");
        SCFree(tdata);
        return -1;
    }

    SCLogDebug("max_msg_size: %d", zsock_maxmsgsize(tdata->writer));
    SCLogDebug("in_batch_size: %d", zsock_in_batch_size(tdata->writer));
    SCLogDebug("zsock_out_batch_size: %d", zsock_out_batch_size(tdata->writer));
    SCLogDebug("zsock_sndbuf: %d", zsock_sndbuf(tdata->writer));
    SCLogDebug("zsock_sndhwm: %d", zsock_sndhwm(tdata->writer));
    SCLogDebug("zsock_sndtimeo: %d", zsock_sndtimeo(tdata->writer));
    SCLogDebug("zsock_affinity: %d", zsock_affinity(tdata->writer));
    SCLogDebug("zsock_immediate: %d", zsock_immediate(tdata->writer));
    SCLogDebug("zsock_metadata: %d", zsock_metadata(tdata->writer));

    *thread_data = tdata;

    return 0;
}

/**
 * Deinitialize a thread.
 *
 * This is where any cleanup per thread should be done including free'ing of the
 * thread_data if needed.
 */
static void ZmqThreadDeinit(const void *ctx, void *thread_data)
{
    if (thread_data == NULL) {
        // Nothing to do.
        return;
    }

    ThreadData *tdata = thread_data;

    zsock_destroy(&tdata->writer);

    SCFree(tdata);
}

/**
 * This method is called with formatted Eve JSON data.
 *
 * \param buffer Formatted JSON buffer \param buffer_len Length of formatted
 * JSON buffer \param data Data set in Init callback \param thread_data Data set
 * in ThreadInit callbacl
 *
 * Do not block in this thread, it will cause packet loss. Instead of outputting
 * to any resource that may block it might be best to enqueue the buffers for
 * further processing which will require copying of the provided buffer.
 */
static int ZmqWrite(
        const char *buffer, const int buffer_len, const void *data, void *thread_data)
{
    const Context *ctx = data;
    ThreadData *thread = thread_data;

    zmsg_t *msg = zmsg_new();
    if (msg == NULL) {
        thread->err_alloc++;
        return -1;
    }

    int rc = zmsg_addmem(msg, buffer, buffer_len);
    if (rc != 0) {
        thread->err_add++;
        goto failed;
    }
    SCLogDebug("zmsg_size: %d", zmsg_size(msg));
    SCLogDebug("zmsg_content_size: %d", zmsg_content_size(msg));

    rc = zmsg_send(&msg, thread->writer);
    if (rc != 0) {
        thread->err_send++;
        goto failed;
    }

    zmsg_destroy(&msg);

    thread->success++;

    if (ctx->verbose) {
        SCLogNotice("Thread %u received write with %s", thread->thread_id, buffer);
    }
    return 0;

failed:
    if (msg) {
        zmsg_destroy(&msg);
    }
    return -1;
}

/**
 * Called by Suricata to initialize the module. This module registers
 * new file type to the JSON logger.
 */
void PluginInit(void)
{
    SCEveFileType *my_output = SCCalloc(1, sizeof(SCEveFileType));
    my_output->name = PLUGIN_NAME;
    my_output->Init = ZmqInit;
    my_output->Deinit = ZmqDeinit;
    my_output->ThreadInit = ZmqThreadInit;
    my_output->ThreadDeinit = ZmqThreadDeinit;
    my_output->Write = ZmqWrite;
    if (!SCRegisterEveFileType(my_output)) {
        FatalError("Failed to register filetype plugin: %s", PLUGIN_NAME);
    }
}

const SCPlugin PluginRegistration = {
    .version = SC_API_VERSION,
    .suricata_version = SC_PACKAGE_VERSION,
    .name = PLUGIN_NAME,
    .plugin_version = "0.1.0",
    .author = "shihb1553 <shihb0416121210@163.com>",
    .license = "GPL-2.0-only",
    .Init = PluginInit,
};

/**
 * The function called by Suricata after loading this plugin.
 *
 * A pointer to a populated SCPlugin struct must be returned.
 */
const SCPlugin *SCPluginRegister()
{
    return &PluginRegistration;
}
