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
    SCLogDebug("usPacketLen=%d pBgpHdr->usLen=%d\n", usPacketLen, pBgpHdr->usLen);
    if (input_len > 0 && usPacketLen <= input_len) {
        int iOff = 0;
        tx = BgpTransactionAlloc(Bgp);
        if (tx == NULL)
            SCReturnStruct(APP_LAYER_OK);

        if (direction == STREAM_TOSERVER) // request
        {
            tx->request_buffer_len = input_len;
            tx->request_buffer = SCCalloc(1, input_len + 1);
            if (tx->request_buffer != NULL) {
                memcpy(tx->request_buffer, input, input_len);
                tx->request_buffer[input_len] = '\0';
            } else {
                tx->request_buffer_len = 0;
            }
            tx->tx_id = f->tenant_id;
        } else if (direction == STREAM_TOCLIENT) // response
        {
            tx->response_buffer_len = input_len;
            tx->response_buffer = SCCalloc(1, input_len + 1);
            if (tx->response_buffer != NULL) {
                memcpy(tx->response_buffer, input, input_len);
                tx->response_buffer[input_len] = '\0';
            } else {
                tx->request_buffer_len = 0;
            }
            tx->tx_id = f->tenant_id;
        }

        tx->iMsgType = pBgpHdr->ucType;
        iOff = 19; // sizeof(BgpHeader)
        switch (pBgpHdr->ucType) {
            case BGP_MSG_TYPE_OPEN:
                printf("BgpParse - OPEN\n");
                {
                    BgpOpenMsg *pOpenMsg = (BgpOpenMsg *)(input + iOff);
                    tx->stOpenMsg.ucVer = pOpenMsg->ucVer;
                    tx->stOpenMsg.usSys = htons(pOpenMsg->usSys);
                    tx->stOpenMsg.usHoldTime = htons(pOpenMsg->usHoldTime);
                    printf("    version=%d sys=%u holdtime=%u ucOptLen=%d\n", tx->stOpenMsg.ucVer,
                            tx->stOpenMsg.usSys, tx->stOpenMsg.usHoldTime, pOpenMsg->ucOptParamLen);
                    memcpy(tx->stOpenMsg.ucRouteId, pOpenMsg->ucRouteId, 4);
                    printf("    Routerid: ");
                    // DepProt_PrintHex(pOpenMsg->ucRouteId, 4);
                    tx->stOpenMsg.ucOptParamLen = pOpenMsg->ucOptParamLen;
                    if (tx->stOpenMsg.ucOptParamLen > 0) {
                        iOff += sizeof(BgpOpenMsg);
                        if (iOff + pOpenMsg->ucOptParamLen <= usPacketLen) {
                            int iOptionOff = 0;
                            int iOptionNum = 0;
                            while (iOptionOff < tx->stOpenMsg.ucOptParamLen) {
                                BgpOptParamItem *pOpt = (BgpOptParamItem *)(input + iOff);
                                printf("\t----------------option %d---------\n", iOptionNum);
                                printf("\toption type %d\n", pOpt->ucParamType);
                                printf("\toption len %d\n", pOpt->ucParamLen);
                                if (pOpt->ucParamType == BGP_OPTION_AUTHENTICATION) {
                                    printf("\toption param type is BGP_OPTION_AUTHENTICATION\n");
                                } else if (pOpt->ucParamType == BGP_OPTION_CAPABILITY) {
                                    printf("\toption param type is BGP_OPTION_CAPABILITY\n");
                                } else {
                                    SCLogNotice("BGP OPEN Message option %d type %d error!\n",
                                            iOptionNum, pOpt->ucParamType);
                                    break;
                                }
                                iOff += 2 + pOpt->ucParamLen;
                                iOptionOff += 2 + pOpt->ucParamLen;
                                iOptionNum++;
                                printf("\tiOff=%d\n", iOff);
                            }
                        }
                    }
                }
                break;
            case BGP_MSG_TYPE_UPDATE:
                printf("BgpParse - UPDATE\n");
                {
                    int iAttrLen = 0;
                    BgpUpdateMsg *pUpdate = (BgpUpdateMsg *)(input + iOff);
                    printf("    withdrawn routes length %d\n    TotalPath Attribute Length %d\n",
                            htons(pUpdate->usWithdrawnRoutesLen), htons(pUpdate->usPathAttrLen));
                    iAttrLen = htons(pUpdate->usPathAttrLen);
                    if (iAttrLen > 0) {
                        iOff += sizeof(BgpUpdateMsg);
                        if (iOff + iAttrLen <= usPacketLen) {
                            int iAttrOff = 0;
                            int iAttrNum = 0;
                            while (iAttrOff < iAttrLen - 3) {
                                const char *pcAttrTypeStr = NULL;
                                int iAttrLen = 0;
                                int iAttrExtend = 0;

                                printf("\t--------------------\n\t %d Path Attribute ", iAttrNum);
                                BgpPathAddrItem *pAttr = (BgpPathAddrItem *)(input + iOff);
                                printf("\tFlags %02x\n", pAttr->ucFlags);
                                printf("\tType code %d\n", pAttr->ucType);
                                pcAttrTypeStr = SCMapEnumValueToName(pAttr->ucType, bgp_attr_type);
                                if (pcAttrTypeStr != NULL) {
                                    printf("\tType code str %s\n", pcAttrTypeStr);
                                }
                                printf("\tAttr flage:");
                                if ((pAttr->ucFlags & BGP_ATTR_FLAG_OPTIONAL) == 0) {
                                    printf("Well-known");
                                }
                                if ((pAttr->ucFlags & BGP_ATTR_FLAG_TRANSITIVE) == 0) {
                                    printf(", Non-transitive");
                                }
                                if ((pAttr->ucFlags & BGP_ATTR_FLAG_PARTIAL) == 0) {
                                    printf(", Complete");
                                }
                                printf("\n");
                                if (pAttr->ucFlags & BGP_ATTR_FLAG_EXTENDED_LENGTH) {
                                    unsigned short *pusAttLen = NULL;

                                    pusAttLen = (unsigned short *)(input + iOff + 2);
                                    iAttrLen = htons(*pusAttLen);
                                    printf("\tattrlen=%d iOff=%d\n", iAttrLen, iOff);
                                    iOff += 4;
                                    iAttrOff += 4;
                                    iAttrExtend = 1;
                                    printf("\tattrextend=%d\n", iAttrExtend);
                                } else {
                                    printf("\tattrlen=%d iOff=%d\n", input[iOff + 2], iOff);
                                    iAttrLen = input[iOff + 2];
                                    iOff += 3;
                                    iAttrOff += 3;
                                }
                                switch (pAttr->ucType) {
                                    case BGPTYPE_ORIGIN:
                                        if (iAttrLen == 1) {
                                            const char *pcBgpAttrOrigin = SCMapEnumValueToName(input[iOff], bgpattr_origin);
                                            if (pcBgpAttrOrigin != NULL) {
                                                printf("\t attr origin %s\n", pcBgpAttrOrigin);
                                            } else {
                                                printf("\t attr orgin id %d is invalid\n",
                                                        input[iOff]);
                                            }
                                        } else {
                                            printf("Origin (invalid): %u bytes\n", iAttrLen);
                                            break;
                                        }
                                        break;
                                    case BGPTYPE_AS_PATH:
                                    case BGPTYPE_AS4_PATH:

                                        break;
                                    case BGPTYPE_NEXT_HOP:
                                        if (iAttrLen == 4) {
                                            char acTmp[16] = { 0x0 };
                                            PrintInet(AF_INET, (const void *)(input + iOff), acTmp, sizeof(acTmp));
                                            printf("\t attr net hot %s\n", acTmp);
                                        } else {
                                            printf("\t attr BGPTYPE_NEXT_HOP len is %d ,not 4 ,so "
                                                   "it's invalid\n",
                                                    iAttrLen);
                                        }
                                        break;
                                    case BGPTYPE_MULTI_EXIT_DISC:
                                        if (iAttrLen == 4) {
                                            int *piMultiExitDisc = (int *)(input + iOff);

                                            printf("\t attr multi_exit_disc %u %u\n",
                                                    htonl(*piMultiExitDisc), *piMultiExitDisc);
                                        } else {
                                            printf("\t attr BGPTYPE_MULTI_EXIT_DISC len is %d ,not "
                                                   "4 ,so it's invalid\n",
                                                    iAttrLen);
                                        }
                                        break;
                                    case BGPTYPE_LOCAL_PREF:
                                        if (iAttrLen == 4) {
                                            int *piMultiExitDisc = (int *)(input + iOff);

                                            printf("\t attr multi_exit_disc %u %u\n",
                                                    htonl(*piMultiExitDisc), *piMultiExitDisc);
                                        } else {
                                            printf("\t attr BGPTYPE_MULTI_EXIT_DISC len is %d ,not "
                                                   "4 ,so it's invalid\n",
                                                    iAttrLen);
                                        }

                                        break;
                                    case BGPTYPE_ATOMIC_AGGREGATE:
                                        if (iAttrLen != 0) {
                                            printf("Atomic aggregate (invalid): %u byte\n",
                                                    iAttrLen);
                                        } else {
                                            printf("BGPTYPE_ATOMIC_AGGREGATE\n");
                                        }
                                        break;
                                    case BGPTYPE_AGGREGATOR:
                                        if (iAttrLen == 6) {
                                            unsigned short *pusAs =
                                                    (unsigned short *)(input + iOff);
                                            char acOrigin[16] = { 0x0 };
                                            printf("Aggregator AS: %d\n", htons(*pusAs));
                                            iOff += 2;

                                            PrintInet(AF_INET, (const void *)(input + iOff), acOrigin, sizeof(acOrigin));
                                            printf("Aggregator origin %s\n", acOrigin);

                                        } else if (iAttrLen == 8) {

                                        } else {
                                            printf("Aggregator (invalid): %u byte\n", iAttrLen);
                                        }
                                        /* FALL THROUGH */
                                    case BGPTYPE_AS4_AGGREGATOR:
                                        if (iAttrLen == 8) {
                                            printf("Aggregator (invalid): %u byte", iAttrLen);
                                            break;
                                        } else {
                                        }
                                        break;
                                    case BGPTYPE_COMMUNITIES:
                                        if (iAttrLen % 4 != 0) {
                                            printf("Communities (invalid): %u byte\n", iAttrLen);
                                            break;
                                        }
                                        break;
                                    case BGPTYPE_ORIGINATOR_ID:
                                        if (iAttrLen % 4 != 0) {
                                            printf("Originator identifier (invalid): %u byte\n",
                                                    iAttrLen);
                                            break;
                                        } else {
                                            char acOrigin[16] = { 0x0 };
                                            PrintInet(AF_INET, (const void *)(input + iOff), acOrigin, sizeof(acOrigin));
                                            printf("Aggregator origin %s\n", acOrigin);
                                        }

                                        break;
                                    case BGPTYPE_MP_REACH_NLRI:

                                        break;
                                    case BGPTYPE_MP_UNREACH_NLRI:
                                        break;
                                    case BGPTYPE_CLUSTER_LIST:
                                        if (iAttrLen % 4 != 0) {
                                            printf("Cluster list (invalid): %u byte\n", iAttrLen);
                                            break;
                                        }
                                        break;
                                    case BGPTYPE_EXTENDED_COMMUNITY:
                                        if (iAttrLen % 4 != 0) {
                                            printf("Community length %u wrong, must be modulo 8",
                                                    iAttrLen);
                                            break;
                                        } else {
                                            // DepProt_PrintHex(input + iOff, 8);
                                        }
                                        break;
                                    case BGPTYPE_SAFI_SPECIFIC_ATTR:
                                        break;
                                    case BGPTYPE_TUNNEL_ENCAPS_ATTR:

                                        break;
                                    case BGPTYPE_AIGP:
                                        break;
                                    case BGPTYPE_LINK_STATE_ATTR:
                                    case BGPTYPE_LINK_STATE_OLD_ATTR:
                                        break;

                                    case BGPTYPE_LARGE_COMMUNITY:
                                        if (iAttrLen == 0 || iAttrLen % 12) {
                                            break;
                                        }

                                        break;
                                    case BGPTYPE_BGPSEC_PATH:

                                        break;
                                    case BGPTYPE_BGP_PREFIX_SID:

                                        break;
                                    case BGPTYPE_PMSI_TUNNEL_ATTR:

                                        break;

                                    case BGPTYPE_ATTR_SET:
                                        if (iAttrLen >= 4) {
                                        } else {
                                            printf("Attribute set (invalid): %u bytes\n", iAttrLen);
                                            break;
                                        }
                                        break;
                                    case BGPTYPE_D_PATH:
                                        if (iAttrLen < 8) {
                                            printf("D-PATH attribute has invalid length (invalid): "
                                                   "%u byte\n",
                                                    iAttrLen);
                                            break;
                                        }

                                        break;
                                    default:

                                        break;
                                }

                                iOff += iAttrLen;
                                iAttrOff += iAttrLen;
                                iAttrNum++;
                            }
                        }
                    }
                }
                break;
            case BGP_MSG_TYPE_NOTIFICATION:
                printf("BgpParse - NOTIFICATION\n");
                {
                    BgpNotifyMsg *pNotifyMsg = (BgpNotifyMsg *)(input + 19);
                    tx->stNotifyMsg.ucErrCode = pNotifyMsg->ucErrCode;
                    tx->stNotifyMsg.ucErrSubCode = pNotifyMsg->ucErrSubCode;
                    printf("    ucErrCode=%d ucErrSubCode=%d\n", pNotifyMsg->ucErrCode,
                            pNotifyMsg->ucErrSubCode);
                }
                break;
            case BGP_MSG_TYPE_KEEPALIVE:
                printf("BgpParse - KEEPALIVE\n");
                break;
            case BGP_MSG_TYPE_ROUTE_REFRESH:
                printf("BgpParse - REFRESH\n");
                break;
            case BGP_MSG_TYPE_CAPABILITY:
                printf("BgpParse -CAPABILITY\n");
                break;
            default:
                printf("BgpParse - type unknown\n");
                SCReturnStruct(APP_LAYER_OK);
        }
    }
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

    SCLogNotice("\n-----------------------------BgpProbingParser begin!\n");
    if (input_len < BGP_HEADER_SIZE) {
        SCLogNotice("BgpProbingParser length too small to be a Bgp header");
        return ALPROTO_UNKNOWN;
    }

    if (direction == STREAM_TOSERVER) {
        SCLogNotice("BgpProbingParser direction=STREAM_TOSERVER\n");
    } else {
        SCLogNotice("BgpProbingParser direction=STREAM_TOCLIENT\n");
    }
    while (iOff < input_len) {
        pBgpHdr = (BgpHeader *)(input);
        usPacketLen = htons(pBgpHdr->usLen);
        SCLogNotice(
                "usPacketLen=%d pBgpHdr->usLen=%d iOff=%d\n", usPacketLen, pBgpHdr->usLen, iOff);
        if (usPacketLen <= input_len) {
            switch (pBgpHdr->ucType) {
                case BGP_MSG_TYPE_OPEN:
                    SCLogNotice("BgpParse - OPEN");
                    if (input_len - iOff < BGP_MIN_OPEN_MSG_SIZE) {
                        return ALPROTO_UNKNOWN;
                    }
                    break;
                case BGP_MSG_TYPE_UPDATE:
                    SCLogNotice("BgpParse - UPDATE");
                    if (input_len - iOff < BGP_MIN_UPDATE_MSG_SIZE) {
                        return ALPROTO_UNKNOWN;
                    }
                    break;
                case BGP_MSG_TYPE_NOTIFICATION:
                    SCLogNotice("BgpParse - NOTIFICATION");
                    if (input_len - iOff < BGP_MIN_NOTIFICATION_MSG_SIZE) {
                        return ALPROTO_UNKNOWN;
                    }
                    break;
                case BGP_MSG_TYPE_KEEPALIVE:
                    SCLogNotice("BgpParse - KEEPALIVE");
                    if (input_len - iOff < BGP_MIN_KEEPALVE_MSG_SIZE) {
                        return ALPROTO_UNKNOWN;
                    }
                    break;
                case BGP_MSG_TYPE_ROUTE_REFRESH:
                    SCLogNotice("BgpParse - REFRESH");
                    break;
                case BGP_MSG_TYPE_CAPABILITY:
                    SCLogNotice("BgpParse -CAPABILITY");
                    break;
                case BGP_MSG_TYPE_ROUTE_REFRESH_CISCO:
                    SCLogNotice("BgpParse -ROUTE REFRESH CISCO");
                    break;
                default:
                    SCLogNotice("BgpParse - UNKNOWN");
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
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, "179", ALPROTO_BGP, 0, sizeof(BgpHeader),
                    STREAM_TOSERVER, BgpProbingParser, NULL);

            AppLayerProtoDetectPPRegister(IPPROTO_TCP, "179", ALPROTO_BGP, 0, sizeof(BgpHeader),
                    STREAM_TOCLIENT, BgpProbingParser, NULL);

        } else {
            if (!AppLayerProtoDetectPPParseConfPorts("TCP", IPPROTO_TCP, proto_name, ALPROTO_BGP, 0,
                        sizeof(BgpHeader), BgpProbingParser, BgpProbingParser)) {
                SCLogNotice("no BGP TCP config found enabling BGP detection on port 179.");

                AppLayerProtoDetectPPRegister(IPPROTO_TCP, "179", ALPROTO_BGP, 0, sizeof(BgpHeader),
                        STREAM_TOSERVER, BgpProbingParser, NULL);

                AppLayerProtoDetectPPRegister(IPPROTO_TCP, "179", ALPROTO_BGP, 0, sizeof(BgpHeader),
                        STREAM_TOCLIENT, BgpProbingParser, NULL);
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
