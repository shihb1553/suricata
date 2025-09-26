#include "suricata-common.h"
#include "suricata.h"

#include "util-debug.h"
#include "util-byte.h"
#include "util-enum.h"
#include "util-mem.h"
#include "util-misc.h"

#include "stream.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-ccsds.h"

#include "app-layer-detect-proto.h"

#include "conf.h"
#include "decode.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "pkt-var.h"
#include "util-profiling.h"


SCEnumCharMap ccsds_decoder_event_table[] = {
    { NULL, -1 },
};

SCEnumCharMap ccsds_primary_header_sequence_flags[] = {
    { "Continuation segment", 0 },
    { "First segment", 1 },
    { "Last segment", 2 },
    { "Unsegmented data", 3 },
    { NULL, -1 }
};

SCEnumCharMap ccsds_secondary_header_type[] = {
    { "Core", 0 },
    { "Payload", 1 },
    { NULL, -1 }
};

SCEnumCharMap ccsds_secondary_header_packet_type[] = {
    { "UNDEFINED", 0 },
    { "Data Dump", 1 },
    { "UNDEFINED", 2 },
    { "UNDEFINED", 3 },
    { "TLM/Status", 4 },
    { "UNDEFINED", 5 },
    { "Payload Private/Science", 6 },
    { "Ancillary Data", 7 },
    { "Essential Cmd", 8 },
    { "System Cmd", 9 },
    { "Payload Cmd", 10 },
    { "Data Load/File Transfer", 11 },
    { "UNDEFINED", 12 },
    { "UNDEFINED", 13 },
    { "UNDEFINED", 14 },
    { "UNDEFINED", 15 },
    { NULL, -1 }
};

SCEnumCharMap ccsds_secondary_header_element_id[] = {
    { "NASA (Ground Test Only)", 0 },
    { "NASA", 1 },
    { "ESA/APM", 2 },
    { "NASDA", 3 },
    { "RSA", 4 },
    { "CSA", 5 },
    { "ESA/ATV", 6 },
    { "ASI", 7 },
    { "ESA/ERA", 8 },
    { "Reserved", 9 },
    { "RSA SPP", 10 },
    { "NASDA HTV", 11 },
    { "Reserved", 12 },
    { "Reserved", 13 },
    { "Reserved", 14 },
    { "Reserved", 15 },
    { NULL, -1 }
};

SCEnumCharMap ccsds_secondary_header_cmd_data_packet[] __attribute__((unused)) = {
    { "Command Packet", 0 },
    { "Data Packet", 1 },
    { NULL, -1 }
};

SCEnumCharMap ccsds_secondary_header_format_id[] __attribute__((unused)) = {
    { "Reserved", 0 },
    { "Essential Telemetry", 1 },
    { "Housekeeping Tlm - 1", 2 },
    { "Housekeeping Tlm - 2", 3 },
    { "PCS DDT", 4 },
    { "CCS S-Band Command Response", 5 },
    { "Contingency Telemetry via the SMCC", 6 },
    { "Normal Data Dump", 7 },
    { "Extended Data Dump", 8 },
    { "Reserved", 9 },
    { "Reserved", 10 },
    { "Broadcast Ancillary Data", 11 },
    { "Reserved", 12 },
    { "NCS to OIU Telemetry and ECOMM Telemetry", 13 },
    { "CCS to OIU Telemetry - Direct", 14 },
    { "Reserved", 15 },
    { "Normal File Dump", 16 },
    { "Extended File Dump", 17 },
    { "NCS to FGB Telemetry", 18 },
    { "Reserved", 19 },
    { "ZOE Normal Dump (S-Band)", 20 },
    { "ZOE Extended Dump (S-Band)", 21 },
    { "EMU S-Band TLM Packet", 22 },
    { "Reserved", 23 },
    { "Reserved", 24 },
    { "Reserved", 25 },
    { "CCS to OIU Telemetry via UHF", 26 },
    { "OSTP Telemetry (After Flight 1E, CCS R5)", 27 },
    { "Reserved", 28 },
    { "Reserved", 29 },
    { "Reserved", 30 }, { "Reserved", 31 }, { "Reserved", 32 }, { "Reserved", 33 },
    { "Reserved", 34 }, { "Reserved", 35 }, { "Reserved", 36 }, { "Reserved", 37 },
    { "Reserved", 38 }, { "Reserved", 39 }, { "Reserved", 40 }, { "Reserved", 41 },
    { "Reserved", 42 }, { "Reserved", 43 }, { "Reserved", 44 }, { "Reserved", 45 },
    { "Reserved", 46 }, { "Reserved", 47 }, { "Reserved", 48 }, { "Reserved", 49 },
    { "Reserved", 50 }, { "Reserved", 51 }, { "Reserved", 52 }, { "Reserved", 53 },
    { "Reserved", 54 }, { "Reserved", 55 }, { "Reserved", 56 }, { "Reserved", 57 },
    { "Reserved", 58 }, { "Reserved", 59 }, { "Reserved", 60 }, { "Reserved", 61 },
    { "Reserved", 62 }, { "Reserved", 63 }, { NULL, -1 } };

/** \brief get value for 'complete' status in ccsds
 *
 *  For ccsds we use a simple bool.
 */
static int CcsdsGetAlstateProgress(void *tx, uint8_t direction)
{
    return 1;
}

static AppLayerTxData *CcsdsGetTxData(void *vtx)
{
    CcsdsTransaction *tx = (CcsdsTransaction *)vtx;
    return &tx->tx_data;
}

static AppLayerStateData *CcsdsGetStateData(void *vstate)
{
    CcsdsState *state = (CcsdsState *)vstate;
    return &state->state_data;
}

static void *CcsdsGetTx(void *alstate, uint64_t tx_id)
{
    CcsdsState *Ccsds = (CcsdsState *)alstate;
    CcsdsTransaction *tx = NULL;

    if (Ccsds->curr && Ccsds->curr->tx_num == tx_id + 1)
        return Ccsds->curr;

    TAILQ_FOREACH (tx, &Ccsds->tx_list, next) {
        if (tx->tx_num != (tx_id + 1))
            continue;

        SCLogDebug("returning tx %p", tx);
        return tx;
    }

    return NULL;
}

static uint64_t CcsdsGetTxCnt(void *alstate)
{
    return ((CcsdsState *)alstate)->transaction_max;
}

static int CcsdsStateGetEventInfo(
        const char *event_name, int *event_id, AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, ccsds_decoder_event_table);

    if (*event_id == -1) {
        SCLogError("event \"%s\" not present in "
                   "Ccsds's enum map table.",
                event_name);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static int CcsdsStateGetEventInfoById(
        int event_id, const char **event_name, AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, ccsds_decoder_event_table);
    if (*event_name == NULL) {
        SCLogError("event \"%d\" not present in "
                   "Ccsds's enum map table.",
                event_id);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

/** \brief Allocate Ccsds state
 *
 *  return state
 */
static void *CcsdsStateAlloc(void *orig_state, AppProto proto_orig)
{
    SCLogDebug("CcsdsStateAlloc");
    void *s = SCMalloc(sizeof(CcsdsState));
    if (unlikely(s == NULL))
        return NULL;

    memset(s, 0, sizeof(CcsdsState));

    CcsdsState *proto_state = (CcsdsState *)s;

    TAILQ_INIT(&proto_state->tx_list);
    return s;
}

/** \internal
 *  \brief Free a Ccsds TX
 *  \param tx Ccsds TX to free */
static void CcsdsTransactionFree(CcsdsTransaction *tx, CcsdsState *state)
{
    SCEnter();
    SCLogDebug("CcsdsTransactionFree");

    AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

    if (tx->tx_data.de_state != NULL) {
        DetectEngineStateFree(tx->tx_data.de_state);

        state->tx_with_detect_state_cnt--;
    }
    if (tx->request_buffer_len > 0) {
        SCFree(tx->request_buffer);
        tx->request_buffer = NULL;
        tx->request_buffer_len = 0;
    }
    if (tx->response_buffer_len > 0) {
        SCFree(tx->response_buffer);
        tx->response_buffer = NULL;
        tx->response_buffer_len = 0;
    }

    if (state->iter == tx)
        state->iter = NULL;

    SCFree(tx);
    SCReturn;
}

/** \brief Free Ccsds state
 *
 */
static void CcsdsStateFree(void *s)
{
    SCEnter();
    SCLogDebug("CcsdsStateFree");
    if (s) {
        CcsdsState *proto_state = (CcsdsState *)s;

        CcsdsTransaction *tx = NULL;
        while ((tx = TAILQ_FIRST(&proto_state->tx_list))) {
            TAILQ_REMOVE(&proto_state->tx_list, tx, next);
            CcsdsTransactionFree(tx, proto_state);
        }

        SCFree(s);
    }
    SCReturn;
}

/** \internal
 *  \brief Allocate a Ccsds TX
 *  \retval tx or NULL */
static CcsdsTransaction *CcsdsTransactionAlloc(CcsdsState *state)
{
    SCLogDebug("CcsdsStateTransactionAlloc");
    CcsdsTransaction *tx = (CcsdsTransaction *)SCCalloc(1, sizeof(CcsdsTransaction));
    if (unlikely(tx == NULL))
        return NULL;

    state->curr = tx;
    state->transaction_max++;

    memset(tx, 0x00, sizeof(CcsdsTransaction));

    tx->Ccsds = state;
    tx->tx_num = state->transaction_max;

    TAILQ_INSERT_TAIL(&state->tx_list, tx, next);

    return tx;
}

/**
 *  \brief Ccsds transaction cleanup callback
 */
static void CcsdsStateTransactionFree(void *state, uint64_t tx_id)
{
    SCEnter();
    SCLogDebug("CcsdsStateTransactionFree");
    CcsdsState *ccsds_state = state;
    CcsdsTransaction *tx = NULL;
    TAILQ_FOREACH (tx, &ccsds_state->tx_list, next) {

        if ((tx_id + 1) < tx->tx_num)
            break;
        else if ((tx_id + 1) > tx->tx_num)
            continue;

        if (tx == ccsds_state->curr)
            ccsds_state->curr = NULL;

        if (tx->tx_data.events != NULL) {
            if (tx->tx_data.events->cnt <= ccsds_state->events)
                ccsds_state->events -= tx->tx_data.events->cnt;
            else
                ccsds_state->events = 0;
        }

        TAILQ_REMOVE(&ccsds_state->tx_list, tx, next);
        CcsdsTransactionFree(tx, state);
        break;
    }
    SCReturn;
}

/** \internal
 *
 * \brief This function is called to retrieve a Ccsds
 *
 * \param state     Ccsds state structure for the parser
 * \param input     Input line of the command
 * \param input_len Length of the request
 *
 * \retval 1 when the command is parsed, 0 otherwise
 */
static AppLayerResult CcsdsParse(Flow *f, void *state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data, uint8_t direction)
{
    SCEnter();
    CcsdsState *Ccsds = (CcsdsState *)state;
    CcsdsTransaction *tx;

    const uint8_t *input = StreamSliceGetData(&stream_slice);
    uint32_t input_len = StreamSliceGetDataLen(&stream_slice);

    if (input == NULL && AppLayerParserStateIssetFlag(
                                 pstate, APP_LAYER_PARSER_EOF_TS | APP_LAYER_PARSER_EOF_TC)) {
        SCReturnStruct(APP_LAYER_OK);
    } else if (input == NULL && input_len != 0) {
        // GAP
        SCReturnStruct(APP_LAYER_OK);
    } else if (input == NULL || input_len == 0) {
        SCReturnStruct(APP_LAYER_ERROR);
    }
    if (input_len > CCSDS_PRIMARY_HEADER_LENGTH) {
        CcsdsHdr *pHdr = (CcsdsHdr *)input;
        int iPacketLen = 0;
        int iCssdsLen = 0;

        iPacketLen = htons(pHdr->usPacketDataLen) + 1;
        iCssdsLen = iPacketLen + CCSDS_PRIMARY_HEADER_LENGTH;

        if (input_len < (uint32_t)iCssdsLen) {
            SCReturnStruct(APP_LAYER_OK);
        } else {
            unsigned short usVerType = htons(pHdr->usVerType);
            unsigned short usSeqInfo = htons(pHdr->usSeqInfo);

            const char *pcSeqFlag = NULL;
            const char *pcVerType = NULL;
            printf("version=%d type=%d apid=%d secondhdr=%d seqFlag=%d seqnum=%d\n",
                    usVerType & HDR_VERSION, usVerType & HDR_TYPE, usVerType & HDR_APID,
                    (usVerType & HDR_SECHDR) >> 11, (usSeqInfo & 0xc000) >> 14, usSeqInfo & 0x3fff);
            pcSeqFlag = SCMapEnumValueToName((usSeqInfo & 0xc000) >> 14, ccsds_primary_header_sequence_flags);
            if (pcSeqFlag != NULL) {
                printf("sequence flag %s\n", pcSeqFlag);
            }
            pcVerType = SCMapEnumValueToName((uint8_t)(usVerType & HDR_TYPE), ccsds_secondary_header_type);
            if (pcVerType != NULL) {
                printf("pcVerType %s\n", pcVerType);
            }
            if ((usVerType & HDR_SECHDR) >> 11) {
                if (input_len >= CCSDS_PRIMARY_HEADER_LENGTH + CCSDS_SECONDARY_HEADER_LENGTH - 1) {
                    CcsdsSecondHdr *pSecHdr =
                            (CcsdsSecondHdr *)(input + CCSDS_PRIMARY_HEADER_LENGTH);
                    const char *pcSecHdrType = NULL;
                    const char *pcSecCategory = NULL;
                    pcSecHdrType = SCMapEnumValueToName((pSecHdr->ucHdrTypeCat & 0x80) >> 7, ccsds_secondary_header_packet_type);
                    if (pcSecHdrType != NULL) {
                        printf("second header type %s\n", pcSecHdrType);
                    }
                    pcSecCategory = SCMapEnumValueToName((pSecHdr->ucHdrTypeCat & 0x7F), ccsds_secondary_header_element_id);
                    if (pcSecCategory != NULL) {
                        printf("second category %s\n", pcSecCategory);
                    }
                }
            } else {
                printf("\nno second header: data:\n");
                // DepProt_PrintHex(input + CCSDS_PRIMARY_HEADER_LENGTH, input_len - CCSDS_PRIMARY_HEADER_LENGTH);
            }
        }
    }

    if (input_len > 0) {
        tx = CcsdsTransactionAlloc(Ccsds);
        if (tx == NULL)
            SCReturnStruct(APP_LAYER_OK);
        if (tx->request_buffer == NULL && tx->request_buffer_len == 0) {
            tx->request_buffer_len = input_len;
            tx->request_buffer = SCCalloc(1, input_len + 1);
            if (tx->request_buffer != NULL) {
                memcpy(tx->request_buffer, input, input_len);
                tx->request_buffer[input_len] = '\0';
            } else {
                tx->request_buffer_len = 0;
            }
            tx->tx_id = f->tenant_id;
        }
    }

    SCReturnStruct(APP_LAYER_OK);
}

static AppLayerResult CcsdsParseRequest(Flow *f, void *state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    return CcsdsParse(f, state, pstate, stream_slice, local_data, STREAM_TOSERVER);
}

static AppLayerResult CcsdsParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    return CcsdsParse(f, state, pstate, stream_slice, local_data, STREAM_TOCLIENT);
}

static uint16_t CcsdsProbingParser(
        Flow *f, uint8_t direction, const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
    SCLogNotice("CcsdsProbingParser %d\n", input_len);
    if (input_len < sizeof(CcsdsHdr)) {
        SCLogNotice("CcsdsProbingParser length too small to be a Ccsds header");
        return ALPROTO_UNKNOWN;
    }

    if (direction == STREAM_TOSERVER) {
        printf("CcsdsProbingParser direction=STREAM_TOSERVER\n");
    } else {
        printf("CcsdsProbingParser direction=STREAM_TOCLIENT\n");
    }

    if (input_len > CCSDS_PRIMARY_HEADER_LENGTH) {
        CcsdsHdr *pHdr = (CcsdsHdr *)input;
        uint32_t iPacketLen = 0;
        uint32_t iCssdsLen = 0;

        iPacketLen = htons(pHdr->usPacketDataLen) + 1;
        iCssdsLen = iPacketLen + CCSDS_PRIMARY_HEADER_LENGTH;

        if (input_len < iCssdsLen) {
            return ALPROTO_UNKNOWN;
        } else {
            return ALPROTO_CCSDS;
        }
    }

    SCLogNotice("Protocol not detected as ALPROTO_CCSDS.");
    return ALPROTO_UNKNOWN;
}

static AppLayerGetTxIterTuple CcsdsGetTxIterator(const uint8_t ipproto, const AppProto alproto,
        void *alstate, uint64_t min_tx_id, uint64_t max_tx_id, AppLayerGetTxIterState *state)
{
    CcsdsState *proto_state = (CcsdsState *)alstate;
    AppLayerGetTxIterTuple no_tuple = { NULL, 0, false };
    if (proto_state) {
        CcsdsTransaction *tx_ptr;
        if (state->un.ptr == NULL) {
            tx_ptr = TAILQ_FIRST(&proto_state->tx_list);
        } else {
            tx_ptr = (CcsdsTransaction *)state->un.ptr;
        }
        if (tx_ptr) {
            while (tx_ptr->tx_num < min_tx_id + 1) {
                tx_ptr = TAILQ_NEXT(tx_ptr, next);
                if (!tx_ptr) {
                    return no_tuple;
                }
            }
            if (tx_ptr->tx_num >= max_tx_id + 1) {
                return no_tuple;
            }
            state->un.ptr = TAILQ_NEXT(tx_ptr, next);
            AppLayerGetTxIterTuple tuple = {
                .tx_ptr = tx_ptr,
                .tx_id = tx_ptr->tx_num - 1,
                .has_next = (state->un.ptr != NULL),
            };
            return tuple;
        }
    }
    return no_tuple;
}

static int __attribute__((unused)) CcsdsRegisterPatternsForProtocolDetection(void)
{
    const char method_buffer[32] = "CCSDS";

    if (AppLayerProtoDetectPMRegisterPatternCSwPP(IPPROTO_UDP, ALPROTO_CCSDS, method_buffer,
                (uint16_t)strlen(method_buffer) - 3, 0, STREAM_TOSERVER, CcsdsProbingParser, 0,
                15) < 0) {
        return -1;
    }

    return 0;
}

/**
 * \brief Function to register the Ccsds protocol parsers and other functions
 */
void RegisterCcsdsParsers(void)
{
    SCEnter();
    const char *proto_name = "ccsds";

    if (AppLayerProtoDetectConfProtoDetectionEnabledDefault("udp", proto_name, false)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_CCSDS, proto_name);
        // if (CcsdsRegisterPatternsForProtocolDetection() < 0)
        //     return;

#if 1
        if (RunmodeIsUnittests()) {
            AppLayerProtoDetectPPRegister(IPPROTO_UDP, "161", ALPROTO_CCSDS, 0, sizeof(CcsdsHdr),
                    STREAM_TOSERVER, CcsdsProbingParser, NULL);

            AppLayerProtoDetectPPRegister(IPPROTO_UDP, "161", ALPROTO_CCSDS, 0, sizeof(CcsdsHdr),
                    STREAM_TOCLIENT, CcsdsProbingParser, NULL);

        } else {
            if (!AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP, proto_name, ALPROTO_CCSDS,
                        0, sizeof(CcsdsHdr), CcsdsProbingParser, CcsdsProbingParser)) {
                SCLogDebug("no Ccsds UDP config found enabling Ccsds detection on port 161.");

                AppLayerProtoDetectPPRegister(IPPROTO_UDP, "161", ALPROTO_CCSDS, 0,
                        sizeof(CcsdsHdr), STREAM_TOSERVER, CcsdsProbingParser, NULL);

                AppLayerProtoDetectPPRegister(IPPROTO_UDP, "161", ALPROTO_CCSDS, 0,
                        sizeof(CcsdsHdr), STREAM_TOCLIENT, CcsdsProbingParser, NULL);
            }
        }
#endif
    } else {
        SCLogConfig("Protocol detection and parser disabled for %s protocol.", proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name)) {
        AppLayerParserRegisterParser(
                IPPROTO_UDP, ALPROTO_CCSDS, STREAM_TOSERVER, CcsdsParseRequest);
        AppLayerParserRegisterParser(
                IPPROTO_UDP, ALPROTO_CCSDS, STREAM_TOCLIENT, CcsdsParseResponse);

        AppLayerParserRegisterStateFuncs(
                IPPROTO_UDP, ALPROTO_CCSDS, CcsdsStateAlloc, CcsdsStateFree);

        AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_CCSDS, CcsdsGetTx);
        AppLayerParserRegisterGetTxIterator(IPPROTO_UDP, ALPROTO_CCSDS, CcsdsGetTxIterator);
        AppLayerParserRegisterTxDataFunc(IPPROTO_UDP, ALPROTO_CCSDS, CcsdsGetTxData);
        AppLayerParserRegisterStateDataFunc(IPPROTO_UDP, ALPROTO_CCSDS, CcsdsGetStateData);
        AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_CCSDS, CcsdsGetTxCnt);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_CCSDS, CcsdsStateTransactionFree);

        AppLayerParserRegisterGetStateProgressFunc(
                IPPROTO_UDP, ALPROTO_CCSDS, CcsdsGetAlstateProgress);
        AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_CCSDS, 1, 1);

        AppLayerParserRegisterGetEventInfo(IPPROTO_UDP, ALPROTO_CCSDS, CcsdsStateGetEventInfo);
        AppLayerParserRegisterGetEventInfoById(
                IPPROTO_UDP, ALPROTO_CCSDS, CcsdsStateGetEventInfoById);

        AppLayerParserRegisterParserAcceptableDataDirection(
                IPPROTO_UDP, ALPROTO_CCSDS, STREAM_TOSERVER | STREAM_TOCLIENT);
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                  "still on.",
                proto_name);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_UDP, ALPROTO_CCSDS, CcsdsParserRegisterTests);
#endif

    SCReturn;
}

/* UNITTESTS */
#ifdef UNITTESTS
#include "flow-util.h"
#include "stream-tcp.h"

static uint8_t CcsdsResponse[] = {};

/**
 * \brief Test if Ccsds Packet matches signature
 */
static int ALDecodeCcsdsTest(void)
{
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_CCSDS;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_CCSDS, STREAM_TOSERVER, CcsdsResponse,
            sizeof(CcsdsResponse));
    FAIL_IF(r != 0);

    CcsdsState *proto_state = f.alstate;
    FAIL_IF_NULL(proto_state);

    CcsdsTransaction *tx = CcsdsGetTx(proto_state, 0);
    FAIL_IF_NULL(tx);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);

    PASS;
}

#endif /* UNITTESTS */

void CcsdsParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ALDecodeCcsdsTest", ALDecodeCcsdsTest);
#endif /* UNITTESTS */
}
