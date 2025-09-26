/* Copyright (C) 2018-2021 Open Information Security Foundation
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

/**
 * \file
 *
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 * \author Frank Honza <frank.honza@dcso.de>
 *
 * Implement JSON/eve logging app-layer IKE.
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

#include "app-layer-ccsds.h"
#include "output-json-ccsds.h"
#include "util-byte.h"
#include "util-print.h"

#define LOG_IKE_DEFAULT  0
#define LOG_IKE_EXTENDED (1 << 0)

typedef struct LogCcsdsFileCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} LogCcsdsFileCtx;

typedef struct LogCcsdsLogThread_ {
    LogCcsdsFileCtx *ccsdslog_ctx;
    OutputJsonThreadCtx *ctx;
} LogCcsdsLogThread;

static int JsonCcsdsLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f, void *state,
        void *tx, uint64_t tx_id)
{
    LogCcsdsLogThread *thread = thread_data;
    JsonBuilder *jb = CreateEveHeader(
            (Packet *)p, LOG_DIR_PACKET, "ccsds", NULL, thread->ccsdslog_ctx->eve_ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    // LogLLMNRFileCtx *llmnr_ctx = thread->llmnrlog_ctx;
    CcsdsTransaction *ccsds_tx = (CcsdsTransaction *)tx;
    if (tx != NULL) {
        printf("JsonCcsdsLogger  begin!\n");
        uint32_t offset = 0;
        uint8_t acBuf[512] = { 0x0 };
        JsonBuilder *jsccsds = jb_new_object();

        if (ccsds_tx->request_buffer_len > 0) {
            PrintStringsToBuffer(acBuf, &offset, sizeof(acBuf), ccsds_tx->request_buffer,
                    ccsds_tx->request_buffer_len);
            if (offset > 0) {
                jb_set_string(jsccsds, "banner", (const char *)acBuf);
            }
        }
        jb_set_object(jb, "ccsds", jsccsds);
    }
    OutputJsonBuilderBuffer(jb, thread->ctx);

    jb_free(jb);
    return TM_ECODE_OK;
}

static void OutputCcsdsLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogCcsdsFileCtx *log_ctx = (LogCcsdsFileCtx *)output_ctx->data;
    SCFree(log_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputCcsdsLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogCcsdsFileCtx *log_ctx = SCCalloc(1, sizeof(*log_ctx));
    if (unlikely(log_ctx == NULL)) {
        return result;
    }
    log_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(log_ctx);
        return result;
    }

    output_ctx->data = log_ctx;
    output_ctx->DeInit = OutputCcsdsLogDeInitCtxSub;

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_CCSDS);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonCcsdsLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogCcsdsLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogIKE.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->ccsdslog_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->ccsdslog_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }

    *data = (void *)thread;
    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonCcsdsLogThreadDeinit(ThreadVars *t, void *data)
{
    LogCcsdsLogThread *thread = (LogCcsdsLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonCcsdsLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonCcsdsLog", "eve-log.ccsds",
            OutputCcsdsLogInitSub, ALPROTO_CCSDS, JsonCcsdsLogger, JsonCcsdsLogThreadInit,
            JsonCcsdsLogThreadDeinit, NULL);
}
