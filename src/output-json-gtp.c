/* Copyright (C) 2025 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * TODO: Update \author in this file and in output-json-gtp.h.
 * TODO: Remove SCLogNotice statements, or convert to debug.
 * TODO: Implement your app-layers logging.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Implement JSON/eve logging app-layer Gtp.
 */

#include "suricata-common.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "output-json-gtp.h"
#include "rust.h"

typedef struct LogGtpFileCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} LogGtpFileCtx;

typedef struct LogGtpLogThread_ {
    LogGtpFileCtx *gtplog_ctx;
    OutputJsonThreadCtx *ctx;
} LogGtpLogThread;

static int JsonGtpLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *state, void *tx, uint64_t tx_id)
{
    SCLogNotice("JsonGtpLogger");
    LogGtpLogThread *thread = thread_data;

    JsonBuilder *js =
            CreateEveHeader(p, LOG_DIR_PACKET, "gtp", NULL, thread->gtplog_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "gtp");
    if (!rs_gtp_logger_log(tx, js)) {
        goto error;
    }
    jb_close(js);

    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static void OutputGtpLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogGtpFileCtx *gtplog_ctx = (LogGtpFileCtx *)output_ctx->data;
    SCFree(gtplog_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputGtpLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogGtpFileCtx *gtplog_ctx = SCCalloc(1, sizeof(*gtplog_ctx));
    if (unlikely(gtplog_ctx == NULL)) {
        return result;
    }
    gtplog_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(gtplog_ctx);
        return result;
    }
    output_ctx->data = gtplog_ctx;
    output_ctx->DeInit = OutputGtpLogDeInitCtxSub;

    SCLogNotice("Gtp log sub-module initialized.");

    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_GTP);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonGtpLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogGtpLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogGtp.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->gtplog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->gtplog_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonGtpLogThreadDeinit(ThreadVars *t, void *data)
{
    LogGtpLogThread *thread = (LogGtpLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonGtpLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonGtpLog", "eve-log.gtp",
            OutputGtpLogInitSub, ALPROTO_GTP, JsonGtpLogger,
            JsonGtpLogThreadInit, JsonGtpLogThreadDeinit, NULL);

    SCLogNotice("Gtp JSON logger registered.");
}
