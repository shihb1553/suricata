#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-ospf.h"
#include "flow.h"

#include "util-validate.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-enum.h"
#include "util-print.h"


// { 0, 31, "IPv6 unicast AF" },
// { 32, 63, "IPv6 multicast AF" },
// { 64, 95, "IPv4 unicast AF" },
// { 96, 127, "IPv4 multicast AF" },
// { 128, 255, "Reserved" },

SCEnumCharMap ospf_msg_type_vals[] __attribute__((unused)) = {
    { "Hello Packet", OSPF_HELLO },
    { "DB Description", OSPF_DB_DESC },
    { "LS Request", OSPF_LS_REQ },
    { "LS Update", OSPF_LS_UPD },
    { "LS Acknowledge", OSPF_LS_ACK },
    { NULL, -1 }
};

SCEnumCharMap ospf_at_authentication_type_vals[] __attribute__((unused)) = {
    { "Reserved", 0 },
    { "HMAC Cryptographic Authentication", 1 },
    { NULL, -1 }
};

#define OSPF_AUTH_NONE   0
#define OSPF_AUTH_SIMPLE 1
#define OSPF_AUTH_CRYPT  2

SCEnumCharMap ospf_v2_auth_vals[] = {
    { "Null", OSPF_AUTH_NONE },
    { "Simple password", OSPF_AUTH_SIMPLE },
    { "Cryptographic", OSPF_AUTH_CRYPT },
    { NULL, -1 }
};

/**
 * \brief Function to decode OSPF packets
 */

static int DecodeOSPFPacket(ThreadVars *tv, Packet *p, const uint8_t *pkt, uint16_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    if (unlikely(len < OSPF_VERSION_3_HEADER_LENGTH)) {
        ENGINE_SET_INVALID_EVENT(p, OSPF_HEADER_TOO_SMALL);
        return -1;
    }
    if (!PacketIncreaseCheckLayers(p)) {
        return -1;
    }
    p->ospf = (OSPFHdrBase *)pkt;
    if (p->ospf->ucVer == OSPF_VERSION_2 || p->ospf->ucVer == OSPF_VERSION_3) {
        int iOspfLen = 0;
        printf("\n----------------DecodeOSPFPacket version=%d--------------\n", p->ospf->ucVer);
        iOspfLen = (int)htons(p->ospf->usLen);
        printf("iOspfLen=%d len=%d p->ospf->usLen=%d\n", iOspfLen, len, p->ospf->usLen);
        if ((iOspfLen == len &&
                    (p->ospf->ucVer == OSPF_VERSION_3 || p->ospf->ucVer == OSPF_VERSION_2)) ||
                ((p->ospf->ucVer == OSPF_VERSION_2) && (len > OSPF_VERSION_2_HEADER_LENGTH) &&
                        pkt[141] == 0x00 && pkt[15] == 0x02)) {
            char ip_str[32] = { 0x0 };
            int iOff = 0;
            int iAuthCryptDataLen = 0;
            int iLSAIndex = 0;
            int iLSANum = 0;

            printf("checksum %04x\n", htons(p->ospf->usCheckSum));
            PrintInet(AF_INET, (const void *)&(p->ospf->ucSourceRouter[0]), ip_str, sizeof(ip_str));
            printf("sources router %s\n", ip_str);
            memset(ip_str, 0x0, sizeof(ip_str));
            PrintInet(AF_INET, (const void *)&(p->ospf->ucAreaId[0]), ip_str, sizeof(ip_str));
            printf("area id %s\n", ip_str);

            if (p->ospf->ucVer == OSPF_VERSION_2) {
                unsigned char ucAuthType = 0;
                const char *pcAuthTypeStr = NULL;

                OSPFV2Hdr *pV2Hdr = (OSPFV2Hdr *)pkt;
                ucAuthType = htons(pV2Hdr->usAuthType);
                pcAuthTypeStr = SCMapEnumValueToName(ucAuthType, ospf_v2_auth_vals);
                iOff = sizeof(OSPFV2Hdr);
                printf("ospf auth type %s\n", pcAuthTypeStr);
                switch (ucAuthType) {
                    case OSPF_AUTH_NONE:
                        printf("ospf auth type is NULL,auth data :\n");
                        if (iOff + 8 < len) {
                            // DepProt_PrintHex((unsigned char *)(pkt + iOff), 8);
                            iOff += 8;
                        }
                        break;
                    case OSPF_AUTH_SIMPLE:
                        printf("ospf auth type is SIMPLE,auth data:\n");
                        if (iOff + 8 < len) {
                            // DepProt_PrintHex((unsigned char *)(pkt + iOff), 8);
                            iOff += 8;
                        }
                        break;
                    case OSPF_AUTH_CRYPT:
                        printf("ospf auth type is OSPF_AUTH_CRYPT iOff=%d\n", iOff);
                        iOff += 2;
                        if (iOff + 6 < len) {
                            int *piAuthSeqNum = 0;

                            printf("Auth Crypt Key id %d\n", pkt[iOff]);
                            iAuthCryptDataLen = pkt[iOff + 1];
                            printf("Auth Crypt Data Length %d\n", iAuthCryptDataLen);
                            piAuthSeqNum = (int *)(pkt + iOff + 2);
                            printf("Auth Crypt Sequence Number %ud\n", htonl(*piAuthSeqNum));
                            // DepProt_PrintHex((unsigned char *)(pkt + iOff + 2), 4);
                            if (iOspfLen + iAuthCryptDataLen == len) {
                                iOff += 6;
                                printf("Auth Crypt Data :\n");
                                // DepProt_PrintHex((unsigned char *)(pkt + len - iAuthCryptDataLen), iAuthCryptDataLen);
                            } else {
                                return -1;
                            }
                        }
                        break;
                    default:
                        printf("ospf auth type is %d,auth data:\n", ucAuthType);
                        // DepProt_PrintHex((unsigned char *)(pkt + iOff), 8);
                        iOff += 8;
                        break;
                }
                switch (p->ospf->ucMsgType) {
                    case OSPF_HELLO:
                        printf("OSPF HELLO packet\n");

                        OSPFV2HelloPacket *pHello = (OSPFV2HelloPacket *)(pkt + iOff);
                        memset(ip_str, 0x0, sizeof(ip_str));
                        PrintInet(AF_INET, (const void *)&(pHello->ucNetMask[0]), ip_str, sizeof(ip_str));
                        printf("\tnetwork mask %s\n", ip_str);
                        printf("\thello interval %d\n", htons(pHello->usInterval));
                        printf("\thello option %d\n", pHello->ucOptions);
                        printf("\trouter priority %d\n", pHello->ucRouterPriority);
                        printf("\trouter Dead interval %d\n", htonl(pHello->iDeadInterval));
                        memset(ip_str, 0x0, sizeof(ip_str));
                        PrintInet(AF_INET, (const void *)&(pHello->ucDesignatedRouter[0]), ip_str, sizeof(ip_str));
                        printf("\tDesignated router %s\n", ip_str);
                        memset(ip_str, 0x0, sizeof(ip_str));
                        PrintInet(AF_INET, (const void *)&(pHello->ucBackupRouter[0]), ip_str, sizeof(ip_str));
                        printf("\tBackup Designated router %s\n", ip_str);
                        memset(ip_str, 0x0, sizeof(ip_str));
                        PrintInet(AF_INET, (const void *)&(pHello->ucNeighbor[0]), ip_str, sizeof(ip_str));
                        printf("\tactive neighbor %s\n", ip_str);

                        break;
                    case OSPF_DB_DESC:
                        printf("DB_DESC\n");

                        OSPFV2DBDesc *pDBDesc = (OSPFV2DBDesc *)(pkt + iOff);

                        printf("interface MTU %d\n", htons(pDBDesc->usInterfaceMtu));
                        printf("option %02x\n", pDBDesc->ucOption);
                        printf("DB Description %02x\n", pDBDesc->ucDBDesc);
                        printf("DD sequence %d\n", htonl(pDBDesc->uiDDSeq));
                        iOff += sizeof(OSPFV2DBDesc);
                        if ((len - iOff > 0) && ((len - iOff) % sizeof(OSPFLSAV2Hdr) == 0)) {
                            iLSANum = (len - iOff) / sizeof(OSPFLSAV2Hdr);
                            if (iLSANum > 0) {
                                for (iLSAIndex = 0; iLSAIndex < iLSANum; iLSAIndex++) {
                                    OSPFLSAV2Hdr *pLSAHdr =
                                            (OSPFLSAV2Hdr *)(pkt + iOff +
                                                                iLSAIndex * sizeof(OSPFLSAV2Hdr));
                                    printf("\n\t***********LSA %d**********\n", iLSAIndex);
                                    printf("\tLS Age %d\n", htons(pLSAHdr->usLSAge));
                                    printf("\tLS OPTION %02x\n", pLSAHdr->ucOption);
                                    printf("\tLS Type %d\n", pLSAHdr->ucLSType);
                                    memset(ip_str, 0x0, sizeof(ip_str));
                                    PrintInet(AF_INET, (const void *)&(pLSAHdr->ucLinkStateId[0]), ip_str, sizeof(ip_str));
                                    printf("\tLink State ID %s\n", ip_str);
                                    memset(ip_str, 0x0, sizeof(ip_str));
                                    PrintInet(AF_INET, (const void *)&(pLSAHdr->ucAdvRouter[0]), ip_str, sizeof(ip_str));
                                    printf("\tAdvertising Router %s\n", ip_str);
                                    printf("\tSequence Number %u\n", htonl(pLSAHdr->uiSeqNum));
                                    printf("\tchecksum %d\n", htons(pLSAHdr->usChecksum));
                                    printf("\tlenght %d\n", htons(pLSAHdr->usLen));
                                }
                            }
                        }

                        break;
                    case OSPF_LS_REQ:
                        printf("LS_REQ iOff=%d\n", iOff);
                        {
                            if ((len - iOff > 0) && ((len - iOff) % sizeof(OSPFLSAV2Req) == 0)) {
                                iLSANum = (len - iOff) / sizeof(OSPFLSAV2Req);
                                if (iLSANum > 0) {
                                    for (iLSAIndex = 0; iLSAIndex < iLSANum; iLSAIndex++) {
                                        OSPFLSAV2Req *pReq =
                                                (OSPFLSAV2Req *)(pkt + iOff +
                                                                 iLSAIndex * sizeof(OSPFLSAV2Req));
                                        printf("\n\t***********LSA REQ %d**********\n", iLSAIndex);
                                        printf("\tLS Type %u %08x\n", htonl(pReq->uiLSType),
                                                pReq->uiLSType);
                                        memset(ip_str, 0x0, sizeof(ip_str));
                                        PrintInet(AF_INET, (const void *)&(pReq->ucLinkStateId[0]), ip_str, sizeof(ip_str));
                                        printf("\tLink State ID %s\n", ip_str);
                                        memset(ip_str, 0x0, sizeof(ip_str));
                                        PrintInet(AF_INET, (const void *)&(pReq->ucAdvRouter[0]), ip_str, sizeof(ip_str));
                                        printf("\tAdvertising Router %s\n", ip_str);
                                    }
                                }
                            }
                        }
                        break;
                    case OSPF_LS_UPD:
                        int *piLSANum = 0;

                        piLSANum = (int *)(pkt + iOff);
                        iLSANum = htonl(*piLSANum);
                        printf("LS_UPD iLSANum=%u\n", iLSANum);
                        iOff += 4;
                        if ((iLSANum > 0) && (len - iOff > 0) &&
                                (len - iOff - iLSANum * sizeof(OSPFLSAV2Hdr) > 0)) {
                            if (iLSANum > 0) {
                                for (iLSAIndex = 0; iLSAIndex < iLSANum; iLSAIndex++) {
                                    OSPFLSAV2Hdr *pLSAHdr = (OSPFLSAV2Hdr *)(pkt + iOff);
                                    int iLSAItemLen = 0;

                                    printf("\n\t***********LSA UPDATE %d**********\n", iLSAIndex);
                                    printf("\tLS Age %d\n", htons(pLSAHdr->usLSAge));
                                    printf("\tLS OPTION %02x\n", pLSAHdr->ucOption);
                                    printf("\tLS Type %d\n", pLSAHdr->ucLSType);
                                    memset(ip_str, 0x0, sizeof(ip_str));
                                    PrintInet(AF_INET, (const void *)&(pLSAHdr->ucLinkStateId[0]), ip_str, sizeof(ip_str));
                                    printf("\tLink State ID %s\n", ip_str);
                                    memset(ip_str, 0x0, sizeof(ip_str));
                                    PrintInet(AF_INET, (const void *)&(pLSAHdr->ucAdvRouter[0]), ip_str, sizeof(ip_str));
                                    printf("\tAdvertising Router %s\n", ip_str);
                                    printf("\tSequence Number %08x\n", htonl(pLSAHdr->uiSeqNum));
                                    printf("\tchecksum %04x\n", htons(pLSAHdr->usChecksum));

                                    iLSAItemLen = htons(pLSAHdr->usLen);
                                    printf("\tlenght %d\n", iLSAItemLen);
                                    iOff += iLSAItemLen;
                                }
                            }
                        }
                        break;
                    case OSPF_LS_ACK:
                        printf("LS_ACK\n");
                        if ((len - iOff > 0) && ((len - iOff) % sizeof(OSPFLSAV2Hdr) == 0)) {
                            iLSANum = (len - iOff) / sizeof(OSPFLSAV2Hdr);
                            if (iLSANum > 0) {
                                for (iLSAIndex = 0; iLSAIndex < iLSANum; iLSAIndex++) {
                                    OSPFLSAV2Hdr *pLSAHdr =
                                            (OSPFLSAV2Hdr *)(pkt + iOff +
                                                             iLSAIndex * sizeof(OSPFLSAV2Hdr));
                                    printf("\n\t***********LSA %d**********\n", iLSAIndex);
                                    printf("\tLS Age %d\n", htons(pLSAHdr->usLSAge));
                                    printf("\tLS OPTION %02x\n", pLSAHdr->ucOption);
                                    printf("\tLS Type %d\n", pLSAHdr->ucLSType);
                                    memset(ip_str, 0x0, sizeof(ip_str));
                                    PrintInet(AF_INET, (const void *)&(pLSAHdr->ucLinkStateId[0]), ip_str, sizeof(ip_str));
                                    printf("\tLink State ID %s\n", ip_str);
                                    memset(ip_str, 0x0, sizeof(ip_str));
                                    PrintInet(AF_INET, (const void *)&(pLSAHdr->ucAdvRouter[0]), ip_str, sizeof(ip_str));
                                    printf("\tAdvertising Router %s\n", ip_str);
                                    printf("\tSequence Number %08x\n", htonl(pLSAHdr->uiSeqNum));
                                    printf("\tchecksum %04x\n", htons(pLSAHdr->usChecksum));
                                    printf("\tlenght %d\n", htons(pLSAHdr->usLen));
                                }
                            }
                        }
                        break;
                    default:
                        return -1;
                }
            } else if (p->ospf->ucVer == OSPF_VERSION_3) {
                OSPFV3Hdr *pV3Hdr = (OSPFV3Hdr *)pkt;
                unsigned char ucAddrFamily = OSPF_AF_6;

                iOff = sizeof(OSPFV3Hdr);

                if (pV3Hdr->ucInstanceId > 65 && pV3Hdr->ucInstanceId < 128) {
                    ucAddrFamily = OSPF_AF_4;
                }
                printf("pV3Hdr->ucAddrFamily=%u\n", ucAddrFamily);
                printf("pV3Hdr->ucInstanceId=%d\n", pV3Hdr->ucInstanceId);

                switch (p->ospf->ucMsgType) {
                    case OSPF_HELLO:
                        printf("OSPF HELLO packet\n");
                        {
                            OSPFV3HelloPacket *pHello = (OSPFV3HelloPacket *)(pkt + iOff);
                            printf("\tinterface id %d\n", htonl(pHello->iInterfaceId));
                            printf("\trouter priority %d\n", pHello->ucRouterPriority);
                            printf("\toptions:");
                            // DepProt_PrintHex((unsigned char *)(pkt + iOff + 5), 3);
                            printf("\thello interval %d\n", htons(pHello->usHelloInterval));
                            printf("\trouter dead interval %d\n", htons(pHello->usDeadInterval));
                            memset(ip_str, 0x0, sizeof(ip_str));
                            PrintInet(AF_INET, (const void *)&(pHello->ucDesignatedRouter[0]), ip_str, sizeof(ip_str));
                            printf("\tDesignated router %s\n", ip_str);
                            memset(ip_str, 0x0, sizeof(ip_str));
                            PrintInet(AF_INET, (const void *)&(pHello->ucBackupRouter[0]), ip_str, sizeof(ip_str));
                            printf("\tBackup Designated router %s\n", ip_str);
                            memset(ip_str, 0x0, sizeof(ip_str));
                            PrintInet(AF_INET, (const void *)&(pHello->ucNeighbor[0]), ip_str, sizeof(ip_str));
                            printf("\tactive neighbor %s\n", ip_str);
                        }
                        break;
                    case OSPF_DB_DESC:
                        printf("DB_DESC\n");
                        {
                            OSPFV3DBDesc *pDb = (OSPFV3DBDesc *)(pkt + iOff);
                            // DepProt_PrintHex((unsigned char *)(pkt + iOff + 1), 3);
                            printf("interface MTU %d\n", htons(pDb->usInterfaceMtu));
                            printf("DB Description %d", pDb->ucDBDesc);
                            printf("DB Sequence %d\n", htonl(pDb->uiDDSeq));
                            iOff += sizeof(OSPFV3DBDesc);
                            if ((len - iOff > 0) && ((len - iOff) % sizeof(OSPFLSAV3Hdr) == 0)) {
                                iLSANum = (len - iOff) / sizeof(OSPFLSAV3Hdr);
                                if (iLSANum > 0) {
                                    for (iLSAIndex = 0; iLSAIndex < iLSANum; iLSAIndex++) {
                                        OSPFLSAV3Hdr *pLSAHdr =
                                                (OSPFLSAV3Hdr *)(pkt + iOff +
                                                                 iLSAIndex * sizeof(OSPFLSAV3Hdr));
                                        printf("\n\t***********LSA %d**********\n", iLSAIndex);
                                        printf("\tLS Age %d\n", htons(pLSAHdr->usLSAge));
                                        printf("\tLS Type %04x\n", htons(pLSAHdr->usLSType));
                                        memset(ip_str, 0x0, sizeof(ip_str));
                                        PrintInet(AF_INET, (const void *)&(pLSAHdr->ucLinkStateId[0]), ip_str, sizeof(ip_str));
                                        printf("\tLink State ID %s\n", ip_str);
                                        memset(ip_str, 0x0, sizeof(ip_str));
                                        PrintInet(AF_INET, (const void *)&(pLSAHdr->ucAdvRouter[0]), ip_str, sizeof(ip_str));
                                        printf("\tAdvertising Router %s\n", ip_str);
                                        printf("\tSequence Number %08x\n",
                                                htonl(pLSAHdr->uiSeqNum));
                                        printf("\tchecksum %04x\n", htons(pLSAHdr->usChecksum));
                                        printf("\tlenght %d\n", htons(pLSAHdr->usLen));
                                    }
                                }
                            }
                        }
                        break;
                    case OSPF_LS_REQ:
                        printf("LS_REQ\n");
                        break;
                    case OSPF_LS_UPD: {
                        int *piLSANum = 0;

                        piLSANum = (int *)(pkt + iOff);
                        iLSANum = htonl(*piLSANum);
                        printf("LS_UPD iLSANum=%u\n", iLSANum);
                        iOff += 4;
                        if ((iLSANum > 0) && (len - iOff > 0) &&
                                (len - iOff - iLSANum * sizeof(OSPFLSAV2Hdr) > 0)) {
                            if (iLSANum > 0) {
                                for (iLSAIndex = 0; iLSAIndex < iLSANum; iLSAIndex++) {
                                    OSPFLSAV3Hdr *pLSAHdr = (OSPFLSAV3Hdr *)(pkt + iOff);
                                    int iLSAItemLen = 0;

                                    printf("\n\t***********LSA UPDATE %d**********\n", iLSAIndex);
                                    printf("\tLS Age %d\n", htons(pLSAHdr->usLSAge));
                                    printf("\tLS Type %04x\n", htons(pLSAHdr->usLSType));

                                    memset(ip_str, 0x0, sizeof(ip_str));
                                    PrintInet(AF_INET, (const void *)&(pLSAHdr->ucLinkStateId[0]), ip_str, sizeof(ip_str));
                                    printf("\tLink State ID %s\n", ip_str);
                                    memset(ip_str, 0x0, sizeof(ip_str));
                                    PrintInet(AF_INET, (const void *)&(pLSAHdr->ucAdvRouter[0]), ip_str, sizeof(ip_str));
                                    printf("\tAdvertising Router %s\n", ip_str);
                                    printf("\tSequence Number %08x\n", htonl(pLSAHdr->uiSeqNum));
                                    printf("\tchecksum %04x\n", htons(pLSAHdr->usChecksum));

                                    iLSAItemLen = htons(pLSAHdr->usLen);
                                    printf("\tlenght %d\n", iLSAItemLen);
                                    iOff += iLSAItemLen;
                                }
                            }
                        }
                    } break;
                    case OSPF_LS_ACK:
                        printf("LS_ACK\n");
                        if ((len - iOff > 0) && ((len - iOff) % sizeof(OSPFLSAV3Hdr) == 0)) {
                            iLSANum = (len - iOff) / sizeof(OSPFLSAV3Hdr);
                            if (iLSANum > 0) {
                                for (iLSAIndex = 0; iLSAIndex < iLSANum; iLSAIndex++) {
                                    OSPFLSAV3Hdr *pLSAHdr =
                                            (OSPFLSAV3Hdr *)(pkt + iOff +
                                                             iLSAIndex * sizeof(OSPFLSAV3Hdr));
                                    printf("\n\t***********LSA %d**********\n", iLSAIndex);
                                    printf("\tLS Age %d\n", htons(pLSAHdr->usLSAge));
                                    printf("\tLS Type %04x\n", htons(pLSAHdr->usLSType));
                                    memset(ip_str, 0x0, sizeof(ip_str));
                                    PrintInet(AF_INET, (const void *)&(pLSAHdr->ucLinkStateId[0]), ip_str, sizeof(ip_str));
                                    printf("\tLink State ID %s\n", ip_str);
                                    memset(ip_str, 0x0, sizeof(ip_str));
                                    PrintInet(AF_INET, (const void *)&(pLSAHdr->ucAdvRouter[0]), ip_str, sizeof(ip_str));
                                    printf("\tAdvertising Router %s\n", ip_str);
                                    printf("\tSequence Number %08x\n", htonl(pLSAHdr->uiSeqNum));
                                    printf("\tchecksum %04x\n", htons(pLSAHdr->usChecksum));
                                    printf("\tlenght %d\n", htons(pLSAHdr->usLen));
                                }
                            }
                        }
                        break;
                    default:
                        return -1;
                }
            }
            return TM_ECODE_OK;
        } else {
            return -1;
        }
    } else {
        return -1;
    }
    return 0;
}

int DecodeOSPF(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint32_t len)
{
    StatsIncr(tv, dtv->counter_ospf);

    if (unlikely(DecodeOSPFPacket(tv, p, pkt, len) < 0)) {
        CLEAR_OSPF_PACKET(p);
        return TM_ECODE_FAILED;
    }
    p->proto = IPPROTO_OSPF;
    FlowSetupPacket(p);
    return TM_ECODE_OK;
}

#ifdef UNITTESTS
/**
 * \test DecodeOSPF
 */

static int DecodeOSPFtest(void)
{
    PASS;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for OSPF decoder
 */

void DecodeOSPFRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeOSPFtest", DecodeOSPFtest);
#endif /* UNITTESTS */
}
/**
 * @}
 */
