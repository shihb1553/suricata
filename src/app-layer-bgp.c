#include "suricata-common.h"
#include "suricata.h"

#include "util-debug.h"
#include "util-byte.h"
#include "util-enum.h"
#include "util-mem.h"
#include "util-misc.h"
#include "util-print.h"

#include "stream.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-bgp.h"

#include "app-layer-detect-proto.h"

#include "conf.h"
#include "decode.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "pkt-var.h"
#include "util-profiling.h"


SCEnumCharMap bgp_decoder_event_table[] = {
    { NULL, -1 },
};

SCEnumCharMap bErrCode[] __attribute__((unused)) = {
    { "Message Header Error", 1 },
    { "OPEN Message Error", 2 },
    { "UPDATE Message Error", 3 },
    { "Hold Timer Expired", 4 },
    { "Finite State Machine Error", 5 },
    { "Cease", 6 },
    { NULL, -1 },
};

SCEnumCharMap bHeaderErrCode[] __attribute__((unused)) = {
    { "Connection Not Synchronized", 1 },
    { "Bad Message Length", 2 },
    { "Bad Message Type", 3 },
    { NULL, -1 },
};

SCEnumCharMap bOpenErrCode[] __attribute__((unused)) = {
    { "Unsupported Version Number", 1 },
    { "Bad Peer AS", 2 },
    { "Bad BGP Identifier", 3 },
    { "Unsupported Optional Parameter", 4 },
    { "Deprecated", 5 },
    { "Unacceptable Hold Time", 6 },
    { NULL, -1 },
};

SCEnumCharMap bUpdateErrCode[] __attribute__((unused)) = {
    { "Malformed Attribute List", 1 },
    { "Unrecognized Well-known Attribute", 2 },
    { "Missing Well-known Attribute", 3 },
    { "Attribute Flags Error", 4 },
    { "Attribute Length Error", 5 },
    { "Invalid ORIGIN Attribute", 6 },
    { "Deprecated", 7 },
    { "Invalid NEXT_HOP Attribute", 8 },
    { "Optional Attribute Error", 9 },
    { "Invalid Network Field", 10 },
    { "Malformed AS_PATH", 11 },
    { NULL, -1 },
};

SCEnumCharMap bErrCeaseCode[] __attribute__((unused)) = {
    { "Maximum Number of Prefixes Reached", 1 },
    { "Administrative Shutdown", 2 },
    { "Peer De-configured", 3 },
    { "Administrative Reset", 4 },
    { "Connection Rejected", 5 },
    { "Other Configuration Change", 6 },
    { "Connection Collision Resolution", 7 },
    { "Out of Resources", 8 },
    { NULL, -1 },
};

SCEnumCharMap bgp_attr_type[] = {
    { "ORIGIN", BGPTYPE_ORIGIN },
    { "AS_PATH", BGPTYPE_AS_PATH },
    { "NEXT_HOP", BGPTYPE_NEXT_HOP },
    { "MULTI_EXIT_DISC", BGPTYPE_MULTI_EXIT_DISC },
    { "LOCAL_PREF", BGPTYPE_LOCAL_PREF },
    { "ATOMIC_AGGREGATE", BGPTYPE_ATOMIC_AGGREGATE },
    { "AGGREGATOR", BGPTYPE_AGGREGATOR },
    { "COMMUNITIES", BGPTYPE_COMMUNITIES },
    { "ORIGINATOR_ID", BGPTYPE_ORIGINATOR_ID },
    { "CLUSTER_LIST", BGPTYPE_CLUSTER_LIST },
    { "DPA", BGPTYPE_DPA },
    { "ADVERTISER", BGPTYPE_ADVERTISER },
    { "RCID_PATH / CLUSTER_ID", BGPTYPE_RCID_PATH },
    { "MP_REACH_NLRI", BGPTYPE_MP_REACH_NLRI },
    { "MP_UNREACH_NLRI", BGPTYPE_MP_UNREACH_NLRI },
    { "EXTENDED_COMMUNITIES", BGPTYPE_EXTENDED_COMMUNITY },
    { "AS4_PATH", BGPTYPE_AS4_PATH },
    { "AS4_AGGREGATOR", BGPTYPE_AS4_AGGREGATOR },
    { "SAFI_SPECIFIC_ATTRIBUTE", BGPTYPE_SAFI_SPECIFIC_ATTR },
    { "Connector Attribute", BGPTYPE_CONNECTOR_ATTRIBUTE },
    { "AS_PATHLIMIT ", BGPTYPE_AS_PATHLIMIT },
    { "TUNNEL_ENCAPSULATION_ATTRIBUTE", BGPTYPE_TUNNEL_ENCAPS_ATTR },
    { "PMSI_TUNNEL_ATTRIBUTE", BGPTYPE_PMSI_TUNNEL_ATTR },
    { "Traffic Engineering", BGPTYPE_TRAFFIC_ENGINEERING },
    { "IPv6 Address Specific Extended Community", BGPTYPE_IPV6_ADDR_SPEC_EC },
    { "AIGP", BGPTYPE_AIGP },
    { "PE Distinguisher Labels", BGPTYPE_PE_DISTING_LABLES },
    { "BGP Entropy Label Capability Attribute", BGPTYPE_BGP_ENTROPY_LABEL },
    { "BGP-LS Attribute", BGPTYPE_LINK_STATE_ATTR },
    { "Deprecated", BGPTYPE_30 },
    { "Deprecated", BGPTYPE_31 },
    { "LARGE_COMMUNITY", BGPTYPE_LARGE_COMMUNITY },
    { "BGPsec_PATH", BGPTYPE_BGPSEC_PATH },
    { "D_PATH", BGPTYPE_D_PATH },
    { "BGP Prefix-SID", BGPTYPE_BGP_PREFIX_SID },
    { "LINK_STATE (unofficial code point)", BGPTYPE_LINK_STATE_OLD_ATTR },
    { "ATTR_SET", BGPTYPE_ATTR_SET },
    { "Deprecated", BGPTYPE_129 },
    { "Deprecated", BGPTYPE_241 },
    { "Deprecated", BGPTYPE_242 },
    { "Deprecated", BGPTYPE_243 },
    { NULL, -1 }
};

SCEnumCharMap bgpattr_origin[] = {
    { "IGP", 0 },
    { "EGP", 1 },
    { "INCOMPLETE", 2 },
    { NULL, -1 }
};

/** \brief get value for 'complete' status in Bgp
 *
 *  For Bgp we use a simple bool.
 */
static int BgpGetAlstateProgress(void *tx, uint8_t direction)
{
    return 1;
}

static AppLayerTxData *BgpGetTxData(void *vtx)
{
    BgpTransaction *tx = (BgpTransaction *)vtx;
    return &tx->tx_data;
}

static AppLayerStateData *BgpGetStateData(void *vstate)
{
    BgpState *state = (BgpState *)vstate;
    return &state->state_data;
}

static void *BgpGetTx(void *alstate, uint64_t tx_id)
{
    BgpState *Bgp = (BgpState *)alstate;
    BgpTransaction *tx = NULL;

    if (Bgp->curr && Bgp->curr->tx_num == tx_id + 1)
        return Bgp->curr;

    TAILQ_FOREACH (tx, &Bgp->tx_list, next) {
        if (tx->tx_num != (tx_id + 1))
            continue;

        SCLogDebug("returning tx %p", tx);
        return tx;
    }

    return NULL;
}

static uint64_t BgpGetTxCnt(void *alstate)
{
    return ((BgpState *)alstate)->transaction_max;
}

static int BgpStateGetEventInfo(
        const char *event_name, int *event_id, AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, bgp_decoder_event_table);

    if (*event_id == -1) {
        SCLogError("event \"%s\" not present in "
                   "bgp's enum map table.",
                event_name);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static int BgpStateGetEventInfoById(
        int event_id, const char **event_name, AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, bgp_decoder_event_table);
    if (*event_name == NULL) {
        SCLogError("event \"%d\" not present in "
                   "bgp's enum map table.",
                event_id);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

/** \brief Allocate bgp state
 *
 *  return state
 */
static void *BgpStateAlloc(void *orig_state, AppProto proto_orig)
{
    SCLogDebug("BgpStateAlloc");
    void *s = SCMalloc(sizeof(BgpState));
    if (unlikely(s == NULL))
        return NULL;

    memset(s, 0, sizeof(BgpState));

    BgpState *bgp_state = (BgpState *)s;

    TAILQ_INIT(&bgp_state->tx_list);
    return s;
}

/** \internal
 *  \brief Free a Bgp TX
 *  \param tx Bgp TX to free */
static void BgpTransactionFree(BgpTransaction *tx, BgpState *state)
{
    SCEnter();
    SCLogDebug("BgpTransactionFree");

    AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

    if (tx->tx_data.de_state != NULL) {
        DetectEngineStateFree(tx->tx_data.de_state);

        state->tx_with_detect_state_cnt--;
    }
    if (tx->payload_buffer_len > 0) {
        SCFree(tx->payload_buffer);
        tx->payload_buffer = NULL;
        tx->payload_buffer_len = 0;
    }

    if (tx->stBgpMsg.iMsgCurNum >= 0 && tx->stBgpMsg.iMsgMaxNum > 0 &&
            tx->stBgpMsg.pMsgInfoItem != NULL) {
        int i = 0;

        for (i = 0; i < tx->stBgpMsg.iMsgCurNum; i++) {
            if (tx->stBgpMsg.pMsgInfoItem[i].pstOpenMsg != NULL) {
                free(tx->stBgpMsg.pMsgInfoItem[i].pstOpenMsg);
                tx->stBgpMsg.pMsgInfoItem[i].pstOpenMsg = NULL;
            }
            if (tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg != NULL) {
                if (tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->iPrefixCurNum > 0 &&
                        tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->pPrefixList != NULL) {
                    free(tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->pPrefixList);
                    tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->pPrefixList = NULL;
                }
                if (tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->stAsList.iAsNum > 0 &&
                        tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->stAsList.piASList != NULL) {
                    free(tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->stAsList.piASList);
                    tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->stAsList.piASList = NULL;
                }
                if (tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->stAsPathInfo.iAsNum > 0 &&
                        tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->stAsPathInfo.piASList != NULL) {
                    free(tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->stAsPathInfo.piASList);
                    tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->stAsPathInfo.piASList = NULL;
                }

                free(tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg);
                tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg = NULL;
            }
            if (tx->stBgpMsg.pMsgInfoItem[i].pstNotifyMsg != NULL) {
                free(tx->stBgpMsg.pMsgInfoItem[i].pstNotifyMsg);
                tx->stBgpMsg.pMsgInfoItem[i].pstNotifyMsg = NULL;
            }
        }
    }
    if (state->iter == tx)
        state->iter = NULL;

    SCFree(tx);
    SCReturn;
}

/** \brief Free bgp state
 *
 */
static void BgpStateFree(void *s)
{
    SCEnter();
    SCLogDebug("BgpStateFree");
    if (s) {
        BgpState *bgp_state = (BgpState *)s;

        BgpTransaction *tx = NULL;
        while ((tx = TAILQ_FIRST(&bgp_state->tx_list))) {
            TAILQ_REMOVE(&bgp_state->tx_list, tx, next);
            BgpTransactionFree(tx, bgp_state);
        }

        if (bgp_state->buffer != NULL) {
            SCFree(bgp_state->buffer);
        }

        SCFree(s);
    }
    SCReturn;
}

/** \internal
 *  \brief Allocate a Bgp TX
 *  \retval tx or NULL */
static BgpTransaction *BgpTransactionAlloc(BgpState *state)
{
    SCLogDebug("BgpStateTransactionAlloc");
    BgpTransaction *tx = (BgpTransaction *)SCCalloc(1, sizeof(BgpTransaction));
    if (unlikely(tx == NULL))
        return NULL;

    state->curr = tx;
    state->transaction_max++;

    memset(tx, 0x00, sizeof(BgpTransaction));

    tx->Bgp = state;
    tx->tx_num = state->transaction_max;

    TAILQ_INSERT_TAIL(&state->tx_list, tx, next);

    return tx;
}

/**
 *  \brief bgp transaction cleanup callback
 */

static void BgpStateTransactionFree(void *state, uint64_t tx_id)
{
    SCEnter();
    SCLogDebug("BgpStateTransactionFree");
    BgpState *bgp_state = state;
    BgpTransaction *tx = NULL;
    TAILQ_FOREACH (tx, &bgp_state->tx_list, next) {
        if ((tx_id + 1) < tx->tx_num)
            break;
        else if ((tx_id + 1) > tx->tx_num)
            continue;

        if (tx == bgp_state->curr)
            bgp_state->curr = NULL;

        if (tx->payload_buffer != NULL) {
            free(tx->payload_buffer);
            tx->payload_buffer = NULL;
            tx->payload_buffer_len = 0;
        }
        if (tx->stBgpMsg.iMsgCurNum > 0 && tx->stBgpMsg.pMsgInfoItem != NULL) {
            int i = 0;

            for (i = 0; i < tx->stBgpMsg.iMsgCurNum; i++) {
                switch (tx->stBgpMsg.pMsgInfoItem[i].iMsgType) {
                    case BGP_MSG_TYPE_OPEN:
                        if (tx->stBgpMsg.pMsgInfoItem[i].pstOpenMsg != NULL) {
                            free(tx->stBgpMsg.pMsgInfoItem[i].pstOpenMsg);
                            tx->stBgpMsg.pMsgInfoItem[i].pstOpenMsg = NULL;
                        }
                        break;
                    case BGP_MSG_TYPE_UPDATE:
                        if (tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg != NULL) {
                            if (tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->pPrefixList != NULL) {
                                free(tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->pPrefixList);
                                tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->pPrefixList = NULL;
                            }
                            if (tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->stAsList.iAsNum > 0) {
                                free(tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->stAsList.piASList);
                                tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg->stAsList.piASList = NULL;
                            }
                            free(tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg);
                            tx->stBgpMsg.pMsgInfoItem[i].pstUpdateMsg = NULL;
                        }
                        break;
                    case BGP_MSG_TYPE_NOTIFICATION:
                        if (tx->stBgpMsg.pMsgInfoItem[i].pstNotifyMsg != NULL) {
                            free(tx->stBgpMsg.pMsgInfoItem[i].pstNotifyMsg);
                            tx->stBgpMsg.pMsgInfoItem[i].pstNotifyMsg = NULL;
                        }
                        break;
                }
            }
            free(tx->stBgpMsg.pMsgInfoItem);
            tx->stBgpMsg.pMsgInfoItem = NULL;
        }
        if (tx->tx_data.events != NULL) {
            if (tx->tx_data.events->cnt <= bgp_state->events)
                bgp_state->events -= tx->tx_data.events->cnt;
            else
                bgp_state->events = 0;
        }

        TAILQ_REMOVE(&bgp_state->tx_list, tx, next);
        BgpTransactionFree(tx, state);
        break;
    }
    SCReturn;
}

/** \internal
 *
 * \brief This function is called to retrieve a Bgp
 *
 * \param state     Bgp state structure for the parser
 * \param input     Input line of the command
 * \param input_len Length of the request
 *
 * \retval 1 when the command is parsed, 0 otherwise
 */
static AppLayerResult BgpParse(Flow *f, void *state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data, uint8_t direction)
{
    SCEnter();
    BgpState *Bgp = (BgpState *)state;
    BgpTransaction *tx = NULL;

    BgpHeader *pBgpHdr = NULL;
    unsigned short usPacketLen = 0;

    const uint8_t *input = StreamSliceGetData(&stream_slice);
    uint32_t input_len = StreamSliceGetDataLen(&stream_slice);

    if (input == NULL && AppLayerParserStateIssetFlag(
                                 pstate, APP_LAYER_PARSER_EOF_TS | APP_LAYER_PARSER_EOF_TC)) {
        SCReturnStruct(APP_LAYER_OK);
    } else if (input == NULL && input_len != 0) {
        SCReturnStruct(APP_LAYER_OK);
    } else if (input == NULL || input_len == 0) {
        SCReturnStruct(APP_LAYER_ERROR);
    }
    pBgpHdr = (BgpHeader *)(input);
    usPacketLen = htons(pBgpHdr->usLen);
    SCLogDebug("\n----------------BgpParse usPacketLen=%d "
               "pBgpHdr->usLen=%d----------------------------\n",
            usPacketLen, pBgpHdr->usLen);
    if (input_len > 0 && usPacketLen <= input_len) {
        uint32_t iOff = 0;

        tx = BgpTransactionAlloc(Bgp);
        if (tx == NULL)
            SCReturnStruct(APP_LAYER_OK);
        tx->stBgpMsg.iMsgMaxNum = 0;
        tx->stBgpMsg.iMsgCurNum = 0;
        tx->stBgpMsg.pMsgInfoItem = NULL;

        if (tx->payload_buffer != NULL) {
            free(tx->payload_buffer);
            tx->payload_buffer_len = 0;
        }
        tx->payload_buffer_len = input_len;
        tx->payload_buffer = SCCalloc(1, input_len + 1);
        if (tx->payload_buffer != NULL) {
            memcpy(tx->payload_buffer, input, input_len);
            tx->payload_buffer[input_len] = '\0';
        } else {
            tx->payload_buffer_len = 0;
        }
        tx->tx_id = f->tenant_id;

        while (iOff < input_len) {
            pBgpHdr = (BgpHeader *)(input + iOff);
            usPacketLen = htons(pBgpHdr->usLen);
            iOff += BGP_HEADER_SIZE; // marker(16 bytes) + len(2 bytes) + type(1 byte)
            SCLogDebug("\n    ----------BgpParse usPacketLen=%d pBgpHdr->usLen=%d iOff=%d "
                       "input_len=%d\n",
                    usPacketLen, pBgpHdr->usLen, iOff, input_len);
            if (usPacketLen <= input_len) {
                switch (pBgpHdr->ucType) {
                    case BGP_MSG_TYPE_OPEN:
                        SCLogDebug("    BgpParse - OPEN");
                        if (input_len - iOff >= (BGP_MIN_OPEN_MSG_SIZE - BGP_HEADER_SIZE)) {
                            BgpOpenMsg *pOpenMsg = (BgpOpenMsg *)(input + iOff);

                            if (tx->stBgpMsg.iMsgMaxNum == 0) {
                                SCLogDebug("tx->stBgpMsg.iMsgMaxNum == 0\n");
                                tx->stBgpMsg.iMsgMaxNum = BGP_MAX_MSG_NUM_IN_A_PACKET;
                                tx->stBgpMsg.iMsgCurNum = 0;
                                tx->stBgpMsg.pMsgInfoItem = SCCalloc(
                                        1, sizeof(BgpMsgInfoItem) * tx->stBgpMsg.iMsgMaxNum);
                                if (tx->stBgpMsg.pMsgInfoItem == NULL) {
                                    tx->stBgpMsg.iMsgMaxNum = 0;
                                    SCLogError("BgpParse BGP_MSG_TYPE_OPEN "
                                               "tx->stBgpMsg.pMsgInfoItem SCCalloc error!");
                                    break;
                                }
                                tx->stBgpMsg.pMsgInfoItem[0].pstOpenMsg =
                                        SCCalloc(1, sizeof(BgpOpenMsg));
                                if (tx->stBgpMsg.pMsgInfoItem[0].pstOpenMsg == NULL) {
                                    SCFree(tx->stBgpMsg.pMsgInfoItem);
                                    tx->stBgpMsg.iMsgMaxNum = 0;
                                    tx->stBgpMsg.pMsgInfoItem = NULL;
                                    SCLogError("BgpParse BGP_MSG_TYPE_OPEN "
                                               "tx->stBgpMsg.pMsgInfoItem[0].pstOpenMsg SCCalloc "
                                               "error!");
                                    break;
                                }
                            } else {
                                if (tx->stBgpMsg.iMsgCurNum + 1 < tx->stBgpMsg.iMsgMaxNum) {
                                    tx->stBgpMsg.iMsgCurNum++;
                                    SCLogDebug("tx->stBgpMsg.iMsgCurNum == %d\n",
                                            tx->stBgpMsg.iMsgCurNum);
                                    tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum].pstOpenMsg =
                                            SCCalloc(1, sizeof(BgpOpenMsg));
                                    if (tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                    .pstOpenMsg == NULL) {
                                        SCFree(tx->stBgpMsg.pMsgInfoItem);
                                        tx->stBgpMsg.iMsgMaxNum = 0;
                                        tx->stBgpMsg.pMsgInfoItem = NULL;
                                        SCLogError("BgpParse BGP_MSG_TYPE_OPEN "
                                                   "tx->stBgpMsg.pMsgInfoItem[%d].pstOpenMsg "
                                                   "SCCalloc error!",
                                                tx->stBgpMsg.iMsgCurNum);
                                        break;
                                    }
                                } else {
                                    SCLogError("BgpParse BGP_MSG_TYPE_OPEN "
                                               "tx->stBgpMsg.iMsgCurNum+1(%d) >=  "
                                               "tx->stBgpMsg.iMsgMaxNum(%d)!",
                                            tx->stBgpMsg.iMsgCurNum + 1, tx->stBgpMsg.iMsgMaxNum);
                                    break;
                                }
                            }
                            tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum].iMsgType =
                                    BGP_MSG_TYPE_OPEN;
                            tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum].pstOpenMsg->ucVer =
                                    pOpenMsg->ucVer;
                            tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum].pstOpenMsg->usSys =
                                    htons(pOpenMsg->usSys);
                            tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                    .pstOpenMsg->usHoldTime = htons(pOpenMsg->usHoldTime);
                            tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                    .pstOpenMsg->ucOptParamLen = pOpenMsg->ucOptParamLen;
                            memcpy(tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                            .pstOpenMsg->ucRouteId,
                                    pOpenMsg->ucRouteId, 4);
                            // printf("\t iMsgtype=%d version=%d sys=%u holdtime=%u ucOptLen=%d\n",
                            //     tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum].iMsgType,
                            //     tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum].pstOpenMsg->ucVer,tx->stBgpMsg.pMsgInfoItem[0].pstOpenMsg->usSys,
                            //     tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum].pstOpenMsg->usHoldTime,pOpenMsg->ucOptParamLen);
                            memcpy(tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                            .pstOpenMsg->ucRouteId,
                                    pOpenMsg->ucRouteId, 4);
                            // printf("\tRouterid: ");

                            tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                    .pstOpenMsg->ucOptParamLen = pOpenMsg->ucOptParamLen;
                            if (tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                            .pstOpenMsg->ucOptParamLen > 0) {
                                iOff += sizeof(BgpOpenMsg);
                                if ((iOff + pOpenMsg->ucOptParamLen <= usPacketLen + iOff) &&
                                        (iOff + pOpenMsg->ucOptParamLen <= input_len)) {
                                    int iOptionOff = 0;
                                    int iOptionNum = 0;
                                    while (iOptionOff <
                                            tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                    .pstOpenMsg->ucOptParamLen) {
                                        BgpOptParamItem *pOpt = (BgpOptParamItem *)(input + iOff);
                                        SCLogDebug("\t----------------option %d---------\n",
                                                iOptionNum);
                                        SCLogDebug("\toption type %d\n", pOpt->ucParamType);
                                        SCLogDebug("\toption len %d\n", pOpt->ucParamLen);
                                        if (pOpt->ucParamType == BGP_OPTION_AUTHENTICATION) {
                                            SCLogDebug("\toption param type is "
                                                       "BGP_OPTION_AUTHENTICATION\n");
                                        } else if (pOpt->ucParamType == BGP_OPTION_CAPABILITY) {
                                            SCLogDebug("\toption param type is "
                                                       "BGP_OPTION_CAPABILITY\n");
                                        } else {
                                            SCLogError(
                                                    "BGP OPEN Message option %d type %d error!\n",
                                                    iOptionNum, pOpt->ucParamType);
                                            break;
                                        }
                                        iOff += 2 + pOpt->ucParamLen;
                                        iOptionOff += 2 + pOpt->ucParamLen;
                                        iOptionNum++;
                                    }
                                }
                            } else if (tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                               .pstOpenMsg->ucOptParamLen == 0) {
                                iOff += usPacketLen - BGP_HEADER_SIZE;
                            }
                        } else {
                            iOff = input_len;
                        }
                        break;
                    case BGP_MSG_TYPE_UPDATE:
                        SCLogDebug("    BgpParse - UPDATE");
                        if (input_len - iOff >= BGP_MIN_UPDATE_MSG_SIZE - BGP_HEADER_SIZE) {
                            int iAttrAllLen = 0;
                            BgpUpdateMsg *pUpdate = (BgpUpdateMsg *)(input + iOff);
                            // printf("    iOff=%d withdrawn routes length htons=%d  %d
                            // htons(pUpdate->usPathAttrLen)=%d\n",
                            //     iOff,htons(pUpdate->usWithdrawnRoutesLen),pUpdate->usWithdrawnRoutesLen,htons(pUpdate->usPathAttrLen));
                            if (tx->stBgpMsg.iMsgMaxNum == 0) {
                                SCLogDebug("tx->stBgpMsg.iMsgMaxNum == 0\n");
                                tx->stBgpMsg.iMsgMaxNum = BGP_MAX_MSG_NUM_IN_A_PACKET;
                                tx->stBgpMsg.iMsgCurNum = 0;
                                tx->stBgpMsg.pMsgInfoItem = SCCalloc(
                                        1, sizeof(BgpMsgInfoItem) * tx->stBgpMsg.iMsgMaxNum);
                                if (tx->stBgpMsg.pMsgInfoItem == NULL) {
                                    tx->stBgpMsg.iMsgMaxNum = 0;
                                    SCLogError("BgpParse BGP_MSG_TYPE_UPDATE "
                                               "tx->stBgpMsg.pMsgInfoItem SCCalloc error!");
                                    break;
                                }
                                tx->stBgpMsg.pMsgInfoItem[0].pstUpdateMsg =
                                        SCCalloc(1, sizeof(BgpMsgUpdateInfo));
                                if (tx->stBgpMsg.pMsgInfoItem[0].pstUpdateMsg == NULL) {
                                    SCFree(tx->stBgpMsg.pMsgInfoItem);
                                    tx->stBgpMsg.iMsgMaxNum = 0;
                                    tx->stBgpMsg.pMsgInfoItem = NULL;
                                    SCLogError("BgpParse BGP_MSG_TYPE_UPDATE "
                                               "tx->stBgpMsg.pMsgInfoItem[0].pstOpenMsg SCCalloc "
                                               "error!");
                                    break;
                                }
                            } else {
                                if (tx->stBgpMsg.iMsgCurNum + 1 < tx->stBgpMsg.iMsgMaxNum) {
                                    tx->stBgpMsg.iMsgCurNum++;
                                    SCLogDebug("tx->stBgpMsg.iMsgCurNum == %d\n",
                                            tx->stBgpMsg.iMsgCurNum);
                                    tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                            .pstUpdateMsg = SCCalloc(1, sizeof(BgpMsgUpdateInfo));
                                    if (tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                    .pstUpdateMsg == NULL) {
                                        SCFree(tx->stBgpMsg.pMsgInfoItem);
                                        tx->stBgpMsg.iMsgMaxNum = 0;
                                        tx->stBgpMsg.pMsgInfoItem = NULL;
                                        SCLogError("BgpParse BGP_MSG_TYPE_UPDATE "
                                                   "tx->stBgpMsg.pMsgInfoItem[%d].pstUpdateMsg "
                                                   "SCCalloc error!",
                                                tx->stBgpMsg.iMsgCurNum);
                                        break;
                                    }
                                } else {
                                    SCLogError("BgpParse BGP_MSG_TYPE_UPDATE "
                                               "tx->stBgpMsg.iMsgCurNum+1(%d) >=  "
                                               "tx->stBgpMsg.iMsgMaxNum(%d)!",
                                            tx->stBgpMsg.iMsgCurNum + 1, tx->stBgpMsg.iMsgMaxNum);
                                    break;
                                }
                            }
                            tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                    .pstUpdateMsg->pcOriginType = NULL;
                            tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum].iMsgType =
                                    BGP_MSG_TYPE_UPDATE;
                            if (pUpdate->usWithdrawnRoutesLen != 0) {
                                unsigned short *pusAttrLen = NULL;
                                unsigned short usWithDrawLen = 0;

                                usWithDrawLen = htons(pUpdate->usWithdrawnRoutesLen);
                                if (usWithDrawLen > 0 && ((iOff + usWithDrawLen) < input_len)) {
                                    int iWithDrawOff = 0;

                                    if (tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                    .pstUpdateMsg->iPrefixMaxNum == 0) {
                                        tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                .pstUpdateMsg->iPrefixMaxNum = usWithDrawLen / 2;
                                        tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                .pstUpdateMsg->iPrefixCurNum = 0;
                                        tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                .pstUpdateMsg->pPrefixList = SCCalloc(
                                                1, sizeof(BgpMsgPrefix) * usWithDrawLen / 2);
                                        if (tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                        .pstUpdateMsg->pPrefixList == NULL) {
                                            SCLogError("BgpParse BGP_MSG_TYPE_UPDATE "
                                                       "tx->stBgpMsg.pMsgInfoItem[%d].pstUpdateMsg."
                                                       "pPrefixList malloc error!",
                                                    tx->stBgpMsg.iMsgCurNum);
                                            break;
                                        } else {
                                        }
                                        iWithDrawOff += 2;
                                        SCLogDebug("tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg."
                                                   "iMsgCurNum].pstUpdateMsg->iPrefixCurNum=%d\n",
                                                tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                        .pstUpdateMsg->iPrefixCurNum);
                                        while (iWithDrawOff < usWithDrawLen) {
                                            unsigned char ucWithdrawItemLen = 0;

                                            ucWithdrawItemLen = input[iOff + iWithDrawOff] + 7 / 8;

                                            tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                    .pstUpdateMsg
                                                    ->pPrefixList[tx->stBgpMsg
                                                                    .pMsgInfoItem[tx->stBgpMsg
                                                                                    .iMsgCurNum]
                                                                    .pstUpdateMsg->iPrefixCurNum]
                                                    .ucLen = input[iOff + iWithDrawOff];
                                            memcpy(tx->stBgpMsg
                                                            .pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                            .pstUpdateMsg
                                                            ->pPrefixList[tx->stBgpMsg
                                                                            .pMsgInfoItem[tx->stBgpMsg
                                                                                            .iMsgCurNum]
                                                                            .pstUpdateMsg
                                                                            ->iPrefixCurNum]
                                                            .ucPrefix,
                                                    input + iOff + iWithDrawOff + 1,
                                                    ucWithdrawItemLen);
                                            tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                    .pstUpdateMsg->iPrefixCurNum++;
                                            iWithDrawOff += 1 + (ucWithdrawItemLen + 7) / 8;
                                            SCLogDebug("iWithdrawOff=%d ucWithdrawItemLen=%d \n",
                                                    iWithDrawOff, ucWithdrawItemLen);
                                        }
                                    }
                                }
                                iOff += 2; // Withdraw Route len (2bytes)
                                iOff += usWithDrawLen;
                                SCLogDebug("withdraw iOff=%d "
                                           "htons(pUpdate->usWithdrawnRoutesLen)=%d\n",
                                        iOff, htons(pUpdate->usWithdrawnRoutesLen));
                                if (iOff + 2 <= input_len) {
                                    pusAttrLen = (unsigned short *)(input + iOff);
                                    iAttrAllLen = htons(*pusAttrLen);
                                    SCLogDebug("\tTotalPath Attribute Length %d\n", iAttrAllLen);
                                    if (iAttrAllLen == 0) {
                                        iOff += 2;
                                    }
                                }
                            } else {
                                iAttrAllLen = htons(pUpdate->usPathAttrLen);
                                iOff += sizeof(BgpUpdateMsg);
                                SCLogDebug("\tTotalPath Attribute Length %d\n", iAttrAllLen);
                            }
                            if (iAttrAllLen > 0) {
                                if ((iOff + iAttrAllLen <= usPacketLen + iOff) &&
                                        (iOff + iAttrAllLen <= input_len)) {
                                    int iAttrOff = 0;
                                    int iAttrNum = 0;
                                    while ((iAttrOff < iAttrAllLen - 3) && (iOff < input_len)) {
                                        const char *pcAttrTypeStr = NULL;
                                        int iAttrLen = 0;
                                        // int iAttrExtend = 0;

                                        SCLogDebug("\t--------------------\n\t %d Path Attribute ",
                                                iAttrNum);
                                        BgpPathAddrItem *pAttr = (BgpPathAddrItem *)(input + iOff);
                                        SCLogDebug("\tFlags %02x\n", pAttr->ucFlags);
                                        SCLogDebug("\tType code %d\n", pAttr->ucType);
                                        pcAttrTypeStr = SCMapEnumValueToName(pAttr->ucType, bgp_attr_type);
                                        if (pcAttrTypeStr != NULL) {
                                            SCLogDebug("\tType code str %s\n", pcAttrTypeStr);
                                        }
                                        SCLogDebug("\tAttr flage:");
                                        if ((pAttr->ucFlags & BGP_ATTR_FLAG_OPTIONAL) == 0) {
                                            SCLogDebug("Well-known");
                                        }
                                        if ((pAttr->ucFlags & BGP_ATTR_FLAG_TRANSITIVE) == 0) {
                                            SCLogDebug(", Non-transitive");
                                        }
                                        if ((pAttr->ucFlags & BGP_ATTR_FLAG_PARTIAL) == 0) {
                                            SCLogDebug(", Complete");
                                        }
                                        if (pAttr->ucFlags & BGP_ATTR_FLAG_EXTENDED_LENGTH) {
                                            unsigned short *pusAttLen = NULL;

                                            pusAttLen = (unsigned short *)(input + iOff + 2);
                                            iAttrLen = htons(*pusAttLen);
                                            SCLogDebug("\tattrlen=%d iOff=%d\n", iAttrLen, iOff);
                                            iOff += 4;
                                            iAttrOff += 4;
                                            // iAttrExtend = 1;
                                        } else {
                                            SCLogDebug("\tattrlen=%d iOff=%d\n", input[iOff + 2],
                                                    iOff);
                                            iAttrLen = input[iOff + 2];
                                            iOff += 3;
                                            iAttrOff += 3;
                                        }
                                        switch (pAttr->ucType) {
                                            case BGPTYPE_ORIGIN:
                                                if (iAttrLen == 1) {
                                                    tx->stBgpMsg
                                                            .pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                            .pstUpdateMsg->pcOriginType = (char *)SCMapEnumValueToName(input[iOff], bgpattr_origin);
                                                    SCLogDebug("***********************tx->"
                                                               "stBgpMsg.pMsgInfoItem[%d]."
                                                               "pstUpdateMsg->pcOriginType=%s\n",
                                                            tx->stBgpMsg.iMsgCurNum,
                                                            tx->stBgpMsg
                                                                    .pMsgInfoItem[tx->stBgpMsg
                                                                                    .iMsgCurNum]
                                                                    .pstUpdateMsg->pcOriginType);
                                                } else {
                                                    SCLogError(
                                                            "BgpParse Origin (invalid): %u bytes\n",
                                                            iAttrLen);
                                                    break;
                                                }
                                                break;
                                            case BGPTYPE_AS_PATH:
                                                if (iAttrLen > 0) {
                                                    tx->stBgpMsg
                                                            .pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                            .pstUpdateMsg->iAsPathType =
                                                            input[iOff];
                                                    tx->stBgpMsg
                                                            .pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                            .pstUpdateMsg->stAsPathInfo.iAsNum =
                                                            input[iOff + 1];
                                                    if (tx->stBgpMsg
                                                                    .pMsgInfoItem[tx->stBgpMsg
                                                                                    .iMsgCurNum]
                                                                    .pstUpdateMsg->stAsPathInfo
                                                                    .iAsNum == 0) {
                                                        tx->stBgpMsg
                                                                .pMsgInfoItem[tx->stBgpMsg
                                                                                .iMsgCurNum]
                                                                .pstUpdateMsg->stAsPathInfo
                                                                .piASList = NULL;
                                                    } else {
                                                        tx->stBgpMsg
                                                                .pMsgInfoItem[tx->stBgpMsg
                                                                                .iMsgCurNum]
                                                                .pstUpdateMsg->stAsPathInfo
                                                                .piASList = SCCalloc(
                                                                1, sizeof(int) * input[iOff + 1]);

                                                        SCLogDebug("BGPTYPE_AS_PATH iAsPathType=%d "
                                                                   "AsNum=%d\n",
                                                                input[iOff], input[iOff + 1]);
                                                        if (tx->stBgpMsg
                                                                        .pMsgInfoItem[tx->stBgpMsg
                                                                                        .iMsgCurNum]
                                                                        .pstUpdateMsg->stAsPathInfo
                                                                        .piASList != NULL) {
                                                            int iAsNum = 0;

                                                            for (iAsNum = 0;
                                                                    iAsNum < input[iOff + 1];
                                                                    iAsNum++) {
                                                                int *piAsPathItem =
                                                                        (int *)(input + iOff + 2 +
                                                                                iAsNum * 4);

                                                                tx->stBgpMsg
                                                                        .pMsgInfoItem[tx->stBgpMsg
                                                                                        .iMsgCurNum]
                                                                        .pstUpdateMsg->stAsPathInfo
                                                                        .piASList[iAsNum] =
                                                                        htonl(*piAsPathItem);
                                                                SCLogDebug("BGPTYPE_AS_PATH %04x\n",
                                                                        tx->stBgpMsg
                                                                                .pMsgInfoItem[tx->stBgpMsg
                                                                                                .iMsgCurNum]
                                                                                .pstUpdateMsg
                                                                                ->stAsPathInfo
                                                                                .piASList[iAsNum]);
                                                            }
                                                        }
                                                    }
                                                }
                                                break;
                                            case BGPTYPE_NEXT_HOP:
                                                if (iAttrLen == 4) {
                                                    memcpy(tx->stBgpMsg
                                                                    .pMsgInfoItem[tx->stBgpMsg
                                                                                    .iMsgCurNum]
                                                                    .pstUpdateMsg->ucNextHopV4,
                                                            (unsigned char *)(input + iOff), 4);
                                                } else {
                                                    SCLogError("BgpParse attr BGPTYPE_NEXT_HOP len "
                                                               "is %d ,not 4 ,so it's invalid\n",
                                                            iAttrLen);
                                                }
                                                break;
                                            case BGPTYPE_AGGREGATOR:
                                                if (iAttrLen == 6) {
                                                    unsigned short *pusAs =
                                                            (unsigned short *)(input + iOff);
                                                    tx->stBgpMsg
                                                            .pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                            .pstUpdateMsg->uiAggregatorAs =
                                                            htons(*pusAs);
                                                    memcpy(&(tx->stBgpMsg
                                                                           .pMsgInfoItem[tx->stBgpMsg
                                                                                           .iMsgCurNum]
                                                                           .pstUpdateMsg
                                                                           ->uiAggregatorOrigin),
                                                            (unsigned char *)(input + iOff + 2), 4);
                                                } else if (iAttrLen == 8) {
                                                    unsigned int *puiAs =
                                                            (unsigned int *)(input + iOff);
                                                    tx->stBgpMsg
                                                            .pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                            .pstUpdateMsg->uiAggregatorAs =
                                                            htonl(*puiAs);
                                                    memcpy(&(tx->stBgpMsg
                                                                           .pMsgInfoItem[tx->stBgpMsg
                                                                                           .iMsgCurNum]
                                                                           .pstUpdateMsg
                                                                           ->uiAggregatorOrigin),
                                                            (unsigned char *)(input + iOff + 4), 4);
                                                } else if (iAttrLen == 0) {

                                                } else {
                                                    SCLogDebug("\tAggregator (invalid): %u byte\n",
                                                            iAttrLen);
                                                }
                                                break;

                                            case BGPTYPE_ORIGINATOR_ID:
                                                if (iAttrLen % 4 != 0) {
                                                    SCLogDebug("Originator identifier (invalid): "
                                                               "%u byte\n",
                                                            iAttrLen);
                                                    break;
                                                } else {
                                                    char acOrigin[16] = { 0x0 };
                                                    PrintInet(AF_INET, (const void *)(input + iOff), acOrigin, sizeof(acOrigin));
                                                    SCLogDebug(
                                                            "\tAggregator origin %s\n", acOrigin);
                                                }
                                                break;
                                            case BGPTYPE_EXTENDED_COMMUNITY:
                                                if (iAttrLen % 4 != 0) {
                                                    SCLogDebug("Community length %u wrong, must be "
                                                               "modulo 8",
                                                            iAttrLen);
                                                    break;
                                                }
                                                break;
                                            case BGPTYPE_MULTI_EXIT_DISC:
                                                if (iAttrLen == 4) {
                                                    // int *piMultiExitDisc = (int *)(input + iOff);

                                                    // SCLogDebug("\t attr multi_exit_disc %u
                                                    // %u\n",htonl(*piMultiExitDisc),*piMultiExitDisc);
                                                } else {
                                                    SCLogDebug(
                                                            "\t attr BGPTYPE_MULTI_EXIT_DISC len "
                                                            "is %d ,not 4 ,so it's invalid\n",
                                                            iAttrLen);
                                                }
                                                break;
                                            case BGPTYPE_LOCAL_PREF:
                                                if (iAttrLen == 4) {
                                                    // int *piMultiExitDisc = (int *)(input + iOff);

                                                    // SCLogDebug("\t attr multi_exit_disc %u
                                                    // %u\n",htonl(*piMultiExitDisc),*piMultiExitDisc);
                                                } else {
                                                    SCLogDebug(
                                                            "\t attr BGPTYPE_MULTI_EXIT_DISC len "
                                                            "is %d ,not 4 ,so it's invalid\n",
                                                            iAttrLen);
                                                }

                                                break;
                                            case BGPTYPE_ATOMIC_AGGREGATE:
                                                if (iAttrLen != 0) {
                                                    SCLogDebug("\tAtomic aggregate (invalid): %u "
                                                               "byte\n",
                                                            iAttrLen);
                                                } else {
                                                    SCLogDebug("\tBGPTYPE_ATOMIC_AGGREGATE\n");
                                                    iOff += iAttrLen;
                                                }
                                                break;
                                            case BGPTYPE_AS4_AGGREGATOR:
                                                if (iAttrLen == 8) {
                                                } else {
                                                    SCLogDebug("\tAggregator (invalid): %u byte\n",
                                                            iAttrLen);
                                                }
                                                break;
                                            case BGPTYPE_COMMUNITIES:
                                                if (iAttrLen % 4 != 0) {
                                                    SCLogDebug("Communities (invalid): %u byte\n",
                                                            iAttrLen);
                                                    break;
                                                } else {
                                                }
                                                break;
                                            case BGPTYPE_AS4_PATH:
                                            case BGPTYPE_CLUSTER_LIST:
                                            case BGPTYPE_D_PATH:
                                            case BGPTYPE_ATTR_SET:
                                            case BGPTYPE_LARGE_COMMUNITY:
                                            case BGPTYPE_BGPSEC_PATH:
                                            case BGPTYPE_BGP_PREFIX_SID:
                                            case BGPTYPE_PMSI_TUNNEL_ATTR:
                                            case BGPTYPE_MP_REACH_NLRI:
                                            case BGPTYPE_MP_UNREACH_NLRI:
                                            case BGPTYPE_SAFI_SPECIFIC_ATTR:
                                            case BGPTYPE_TUNNEL_ENCAPS_ATTR:
                                            case BGPTYPE_AIGP:
                                            case BGPTYPE_LINK_STATE_ATTR:
                                            case BGPTYPE_LINK_STATE_OLD_ATTR:
                                            default:
                                                break;
                                        }
                                        iOff += iAttrLen;
                                        iAttrOff += iAttrLen;
                                        iAttrNum++;
                                    }

                                    SCLogDebug("iAttrOff=%d iAttrNum=%d iOff=%d\n", iAttrOff,
                                            iAttrNum, iOff);
                                    if (iOff + 2 <= input_len) {
                                        int iNLRILen = 0;
                                        iNLRILen = (input[iOff] + 7) / 8;
                                        SCLogDebug(
                                                "+++++++++++++++++++++++++++++++++iNULRILen=%d "
                                                "input_len=%d iOff=%d tx->stBgpMsg.iMsgCurNum=%d\n",
                                                iNLRILen, input_len, iOff, tx->stBgpMsg.iMsgCurNum);
                                        if (iNLRILen != 0) {
                                            tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                    .pstUpdateMsg->stNLRI.ucLen = input[iOff];
                                            if (iOff + iNLRILen + 1 <= input_len) {
                                                memcpy(tx->stBgpMsg
                                                                .pMsgInfoItem[tx->stBgpMsg
                                                                                .iMsgCurNum]
                                                                .pstUpdateMsg->stNLRI.ucPrefix,
                                                        input + iOff + 1, iNLRILen);
                                                iOff += 1 + iNLRILen;
                                            }
                                            SCLogDebug(
                                                    "+++++++++++++++++++NLRI.ucLen=%d "
                                                    "NLRI.ucPrefix=%d tx->stBgpMsg.iMsgCurNum=%d\n",
                                                    tx->stBgpMsg
                                                            .pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                            .pstUpdateMsg->stNLRI.ucLen,
                                                    tx->stBgpMsg
                                                            .pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                            .pstUpdateMsg->stNLRI.ucPrefix[0],
                                                    tx->stBgpMsg.iMsgCurNum);
                                        }
                                    }
                                }
                            }

                        } else {
                            if (0) {
                                int iNLRILen = 0;
                                iNLRILen = (input[iOff] + 7) / 8;
                                if (iNLRILen != 0) {
                                    tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                            .pstUpdateMsg->stNLRI.ucLen = input[iOff];
                                    if (iOff + iNLRILen <= input_len) {
                                        memcpy(tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                        .pstUpdateMsg->stNLRI.ucPrefix,
                                                input + iOff + 1, iNLRILen);
                                        iOff += 1 + iNLRILen;
                                    }
                                }
                            }
                        }
                        break;
                    case BGP_MSG_TYPE_NOTIFICATION:
                        SCLogDebug("    BgpParse - NOTIFICATION");
                        if (input_len - iOff >= (BGP_MIN_NOTIFICATION_MSG_SIZE - BGP_HEADER_SIZE) ||
                                input_len ==
                                        (uint32_t)(BGP_MIN_NOTIFICATION_MSG_SIZE + usPacketLen)) {
                            BgpNotifyMsg *pNotifyMsg = (BgpNotifyMsg *)(input + iOff);
                            if (tx->stBgpMsg.iMsgMaxNum == 0) {
                                SCLogDebug("tx->stBgpMsg.iMsgMaxNum == 0\n");
                                tx->stBgpMsg.iMsgMaxNum = BGP_MAX_MSG_NUM_IN_A_PACKET;
                                tx->stBgpMsg.iMsgCurNum = 0;
                                tx->stBgpMsg.pMsgInfoItem = SCCalloc(
                                        1, sizeof(BgpMsgInfoItem) * tx->stBgpMsg.iMsgMaxNum);
                                if (tx->stBgpMsg.pMsgInfoItem == NULL) {
                                    tx->stBgpMsg.iMsgMaxNum = 0;
                                    SCLogError("BgpParse BGP_MSG_TYPE_NOTIFICATION "
                                               "tx->stBgpMsg.pMsgInfoItem SCCalloc error!");
                                    break;
                                }
                                tx->stBgpMsg.pMsgInfoItem[0].pstNotifyMsg =
                                        SCCalloc(1, sizeof(BgpNotifyMsg));
                                if (tx->stBgpMsg.pMsgInfoItem[0].pstNotifyMsg == NULL) {
                                    SCFree(tx->stBgpMsg.pMsgInfoItem);
                                    tx->stBgpMsg.iMsgMaxNum = 0;
                                    tx->stBgpMsg.pMsgInfoItem = NULL;
                                    SCLogError("BgpParse BGP_MSG_TYPE_NOTIFICATION "
                                               "tx->stBgpMsg.pMsgInfoItem[0].pstNotifyMsg SCCalloc "
                                               "error!");
                                    break;
                                }
                            } else {
                                if (tx->stBgpMsg.iMsgCurNum + 1 < tx->stBgpMsg.iMsgMaxNum) {
                                    tx->stBgpMsg.iMsgCurNum++;
                                    SCLogDebug("tx->stBgpMsg.iMsgCurNum == %d\n",
                                            tx->stBgpMsg.iMsgCurNum);
                                    tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                            .pstNotifyMsg = SCCalloc(1, sizeof(BgpNotifyMsg));
                                    if (tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                                    .pstNotifyMsg == NULL) {
                                        SCFree(tx->stBgpMsg.pMsgInfoItem);
                                        tx->stBgpMsg.iMsgMaxNum = 0;
                                        tx->stBgpMsg.pMsgInfoItem = NULL;
                                        SCLogError("BgpParse BGP_MSG_TYPE_NOTIFICATION "
                                                   "tx->stBgpMsg.pMsgInfoItem[%d].pstUpdateMsg "
                                                   "SCCalloc error!",
                                                tx->stBgpMsg.iMsgCurNum);
                                        break;
                                    }
                                } else {
                                    SCLogDebug("tx->stBgpMsg.iMsgCurNum == %d\n",
                                            tx->stBgpMsg.iMsgCurNum);
                                    SCLogError("BgpParse BGP_MSG_TYPE_NOTIFICATION "
                                               "tx->stBgpMsg.iMsgCurNum+1(%d) >=  "
                                               "tx->stBgpMsg.iMsgMaxNum(%d)!",
                                            tx->stBgpMsg.iMsgCurNum + 1, tx->stBgpMsg.iMsgMaxNum);
                                    break;
                                }
                            }
                            tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum].iMsgType =
                                    BGP_MSG_TYPE_NOTIFICATION;
                            tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                    .pstNotifyMsg->ucErrCode = pNotifyMsg->ucErrCode;
                            tx->stBgpMsg.pMsgInfoItem[tx->stBgpMsg.iMsgCurNum]
                                    .pstNotifyMsg->ucErrSubCode = pNotifyMsg->ucErrSubCode;

                        } else {
                            iOff = input_len;
                        }
                        break;
                    case BGP_MSG_TYPE_KEEPALIVE:
                        SCLogDebug("    BgpParse - KEEPALIVE");
                        if ((input_len - iOff < BGP_MIN_KEEPALVE_MSG_SIZE) &&
                                (usPacketLen < input_len)) {
                            if (iOff + BGP_HEADER_SIZE == input_len) {
                                iOff += usPacketLen - BGP_HEADER_SIZE;
                            } else {
                                iOff = input_len;
                                SCLogDebug("BgpParse - KEEPALIVE error input_len-iOff =%d \n",
                                        input_len - iOff);
                            }
                        } else if (iOff == input_len) {
                            iOff += usPacketLen - BGP_HEADER_SIZE;
                            break;
                        } else {
                            iOff += usPacketLen - BGP_HEADER_SIZE;
                            SCLogDebug(
                                    "BgpParse - KEEPALIVE iOff=%d input_len=%d\n", iOff, input_len);
                        }
                        break;
                    case BGP_MSG_TYPE_ROUTE_REFRESH:
                        SCLogDebug("    BgpParse - REFRESH");
                        iOff += usPacketLen;
                        break;
                    case BGP_MSG_TYPE_CAPABILITY:
                        SCLogDebug("    BgpParse -CAPABILITY");
                        iOff += usPacketLen;
                        break;
                    case BGP_MSG_TYPE_ROUTE_REFRESH_CISCO:
                        SCLogDebug("    BgpParse -ROUTE REFRESH CISCO");
                        iOff += usPacketLen;
                        break;
                    default:
                        SCLogDebug("    BgpParse - UNKNOWN");
                        iOff += usPacketLen;
                        break;
                }
                // iOff += usPacketLen;
            } else {
                SCReturnStruct(APP_LAYER_ERROR);
            }
        }
    }
    SCLogDebug("\n******************************BgpParser "
               "end**************************************\n");
    SCReturnStruct(APP_LAYER_OK);
}

static AppLayerResult BgpParseRequest(Flow *f, void *state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    return BgpParse(f, state, pstate, stream_slice, local_data, STREAM_TOSERVER);
}

static AppLayerResult BgpParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    return BgpParse(f, state, pstate, stream_slice, local_data, STREAM_TOCLIENT);
}

#define Bgp_LEN_REGISTER_SESSION 4 // protocol u16, options u16

static uint16_t BgpProbingParser(
        Flow *f, uint8_t direction, const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
    BgpHeader *pBgpHdr = NULL;
    unsigned short usPacketLen = 0;
    unsigned int iOff = 0;

    SCLogDebug("\n-----------------------------BgpProbingParser begin!\n");
    if (input_len < BGP_HEADER_SIZE) {
        SCLogNotice("BgpProbingParser length too small to be a Bgp header");
        return ALPROTO_UNKNOWN;
    }

    if (direction == STREAM_TOSERVER) {
        SCLogDebug("BgpProbingParser direction=STREAM_TOSERVER\n");
    } else {
        SCLogDebug("BgpProbingParser direction=STREAM_TOCLIENT\n");
    }
    while (iOff < input_len) {
        pBgpHdr = (BgpHeader *)(input);
        usPacketLen = htons(pBgpHdr->usLen);
        SCLogDebug("usPacketLen=%d pBgpHdr->usLen=%d iOff=%d\n", usPacketLen, pBgpHdr->usLen, iOff);
        if (usPacketLen <= input_len) {
            switch (pBgpHdr->ucType) {
                case BGP_MSG_TYPE_OPEN:
                    SCLogDebug("BgpParse - OPEN");
                    if (input_len - iOff < BGP_MIN_OPEN_MSG_SIZE) {
                        return ALPROTO_UNKNOWN;
                    }
                    break;
                case BGP_MSG_TYPE_UPDATE:
                    SCLogDebug("BgpParse - UPDATE");
                    if (input_len - iOff < BGP_MIN_UPDATE_MSG_SIZE) {
                        return ALPROTO_UNKNOWN;
                    }
                    break;
                case BGP_MSG_TYPE_NOTIFICATION:
                    SCLogDebug("BgpParse - NOTIFICATION");
                    if (input_len - iOff < BGP_MIN_NOTIFICATION_MSG_SIZE) {
                        return ALPROTO_UNKNOWN;
                    }
                    break;
                case BGP_MSG_TYPE_KEEPALIVE:
                    SCLogDebug("BgpParse - KEEPALIVE");
                    if (input_len - iOff < BGP_MIN_KEEPALVE_MSG_SIZE) {
                        return ALPROTO_UNKNOWN;
                    }
                    break;
                case BGP_MSG_TYPE_ROUTE_REFRESH:
                    SCLogDebug("BgpParse - REFRESH");
                    break;
                case BGP_MSG_TYPE_CAPABILITY:
                    SCLogDebug("BgpParse -CAPABILITY");
                    break;
                case BGP_MSG_TYPE_ROUTE_REFRESH_CISCO:
                    SCLogDebug("BgpParse -ROUTE REFRESH CISCO");
                    break;
                default:
                    SCLogDebug("BgpParse - UNKNOWN");
                    return ALPROTO_UNKNOWN;
            }
            iOff += usPacketLen;
        } else {
            return ALPROTO_UNKNOWN;
        }
        // iOff += usPacketLen;
    }
    return ALPROTO_BGP;
}

static AppLayerGetTxIterTuple BgpGetTxIterator(const uint8_t ipproto, const AppProto alproto,
        void *alstate, uint64_t min_tx_id, uint64_t max_tx_id, AppLayerGetTxIterState *state)
{
    BgpState *bgp_state = (BgpState *)alstate;
    AppLayerGetTxIterTuple no_tuple = { NULL, 0, false };
    if (bgp_state) {
        BgpTransaction *tx_ptr;
        if (state->un.ptr == NULL) {
            tx_ptr = TAILQ_FIRST(&bgp_state->tx_list);
        } else {
            tx_ptr = (BgpTransaction *)state->un.ptr;
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
static int BgpRegisterPatternsForProtocolDetection(void)
{
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_BGP,
                "|ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff|", 16, 0, STREAM_TOSERVER) < 0) {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_BGP,
                "|ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff|", 16, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }
    return 0;
}

/**
 * \brief Function to register the Bgp protocol parsers and other functions
 */
void RegisterBgpParsers()
{
    SCEnter();
    const char *proto_name = "bgp";

    if (AppLayerProtoDetectConfProtoDetectionEnabledDefault("tcp", proto_name, false)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_BGP, proto_name);
        if (BgpRegisterPatternsForProtocolDetection() < 0)
            return;

        if (RunmodeIsUnittests()) {
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, BGP_TCP_PORT, ALPROTO_BGP, 0,
                    sizeof(BgpHeader), STREAM_TOSERVER, BgpProbingParser, NULL);

            AppLayerProtoDetectPPRegister(IPPROTO_TCP, BGP_TCP_PORT, ALPROTO_BGP, 0,
                    sizeof(BgpHeader), STREAM_TOCLIENT, BgpProbingParser, NULL);

        } else {
            if (!AppLayerProtoDetectPPParseConfPorts("TCP", IPPROTO_TCP, proto_name, ALPROTO_BGP, 0,
                        sizeof(BgpHeader), BgpProbingParser, BgpProbingParser)) {
                SCLogNotice("no BGP TCP config found enabling BGP detection on port 179.");

                AppLayerProtoDetectPPRegister(IPPROTO_TCP, BGP_TCP_PORT, ALPROTO_BGP, 0,
                        sizeof(BgpHeader), STREAM_TOSERVER, BgpProbingParser, NULL);

                AppLayerProtoDetectPPRegister(IPPROTO_TCP, BGP_TCP_PORT, ALPROTO_BGP, 0,
                        sizeof(BgpHeader), STREAM_TOCLIENT, BgpProbingParser, NULL);
            }
        }

    } else {
        SCLogDebug("RegisterBgpParsers Protocol detection and parser disabled for %s protocol.",
                proto_name);
        SCReturn;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_BGP, STREAM_TOSERVER, BgpParseRequest);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_BGP, STREAM_TOCLIENT, BgpParseResponse);
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_BGP, BgpStateAlloc, BgpStateFree);

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_BGP, BgpGetTx);
        AppLayerParserRegisterGetTxIterator(IPPROTO_TCP, ALPROTO_BGP, BgpGetTxIterator);
        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_BGP, BgpGetTxData);
        AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_BGP, BgpGetStateData);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_BGP, BgpGetTxCnt);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_BGP, BgpStateTransactionFree);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_BGP, BgpGetAlstateProgress);
        AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_BGP, 1, 1);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_BGP, BgpStateGetEventInfo);
        AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_BGP, BgpStateGetEventInfoById);

        AppLayerParserRegisterParserAcceptableDataDirection(
                IPPROTO_TCP, ALPROTO_BGP, STREAM_TOSERVER | STREAM_TOCLIENT);

    } else {
        SCLogConfig("Parser disabled for %s protocol. Protocol detection still on.", proto_name);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_BGP, BgpParserRegisterTests);
#endif

    SCReturn;
}

/* UNITTESTS */
#ifdef UNITTESTS
#include "flow-util.h"
#include "stream-tcp.h"

static uint8_t Notificataion[] = { /* marker */ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    /* Length */ 0x00, 0x15,
    /* Type:NOTIFICATION message */ 0x03,
    /* Major error code */ 0x06,
    /* Minor error code:Connection Rejected */ 0x05 };

/**
 * \brief Test if Bgp Packet matches signature
 */
static int ALDecodeBgpTest(void)
{
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_BGP;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(
            NULL, alp_tctx, &f, ALPROTO_BGP, STREAM_TOSERVER, Notificataion, sizeof(Notificataion));
    FAIL_IF(r != 0);

    BgpState *bgp_state = f.alstate;
    FAIL_IF_NULL(bgp_state);

    BgpTransaction *tx = BgpGetTx(bgp_state, 0);
    FAIL_IF_NULL(tx);

    FAIL_IF(tx->header.command != 99);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);

    PASS;
}

#endif /* UNITTESTS */

void BgpParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ALDecodeBgpTest", ALDecodeBgpTest);
#endif /* UNITTESTS */
}
