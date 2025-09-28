/**
 * \file
 *
 * \author
 *
 * Decodes igmp
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-igmp.h"
#include "flow.h"


#include "util-validate.h"
#include "util-unittest.h"
#include "util-debug.h"


static uint16_t IgmpCalcChecksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    size_t i = 0;

    // 以16位为单位累加
    for (i = 0; i < len; i += 2)
    {
        uint16_t word = ((data[i] << 8) | (i + 1 < len ? data[i + 1] : 0));
        sum += word;
    }

    // 处理进位
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}


static int IgmpParseV3Query(Packet *p,const uint8_t *buffer, size_t len)
{
    int iRet = -1;
    if (len < sizeof(IGMPV3QueryHdr) - sizeof(uint32_t *))
    {
        ENGINE_SET_INVALID_EVENT(p, IGMP_MSG_LEN_TOO_SMALL);
        return iRet;
    }

    return TM_ECODE_OK;
}
static int ParseIGMPV3Report(Packet *p,const uint8_t *buffer, size_t len)
{
    int iRet = -1;
    if (len < sizeof(IGMPV3ReportHdr) - sizeof(IGMPV3GroupRecord *))
    {
        ENGINE_SET_INVALID_EVENT(p, IGMP_MSG_LEN_TOO_SMALL);
        return iRet;
    }
    return TM_ECODE_OK;
}

static int IgmpParseV1V2(Packet *p,const uint8_t *buffer, size_t len)
{
    int iRet = -1;
    if (len < sizeof(IGMPHdrBase))
    {
        ENGINE_SET_INVALID_EVENT(p, IGMP_MSG_LEN_TOO_SMALL);
        return iRet;
    }

    IGMPHdrBase *header = (IGMPHdrBase *)buffer;

    printf("  IGMP version: %d\n", header->ucType == IGMP_V1_MEMBERSHIP_REPORT ? 1 : 2);
    printf("  Message type: ");
    switch (header->ucType)
    {
        case IGMP_MEMBERSHIP_QUERY:
            printf("IGMP_MEMBERSHIP_QUERY\n");
            break;
        case IGMP_V1_MEMBERSHIP_REPORT:
            printf("IGMP_V1_MEMBERSHIP_REPORT\n");
            break;
        case IGMP_V2_MEMBERSHIP_REPORT:
            printf("IGMP_V2_MEMBERSHIP_REPORT\n");
            break;
        case IGMP_LEAVE_GROUP:
            printf("IGMP_LEAVE_GROUP\n");
            break;
        default:
            printf("未知 (0x%02x)\n", header->ucType);
            ENGINE_SET_INVALID_EVENT(p, IGMP_UNSUPPORTED_MST_TYPE);
            return -1;
    }

    if (header->ucType == IGMP_MEMBERSHIP_QUERY || header->ucType == IGMP_V2_MEMBERSHIP_REPORT)
    {
        printf("  max response time: %ds\n", header->ucMaxRespTime / 10);
    }

    printf("  checksum: 0x%04x\n", ntohs(header->usChecksum));

    char group_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &header->uiGroupAddr, group_str, INET_ADDRSTRLEN);
    printf("  group addr: %s\n", group_str);

    // 验证校验和
    uint16_t computed_checksum = IgmpCalcChecksum(buffer, len);
    if (computed_checksum != 0) {
        printf("  checksum incorect: 0x%04x\n", computed_checksum);
    }
    return TM_ECODE_OK;
}

static int DecodeIGMPPacket(ThreadVars *tv, Packet *p, const uint8_t *pkt, uint16_t len)
{
    int iRet = -1;

    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    if (unlikely(len < sizeof(IGMPHdrBase)))
    {
        ENGINE_SET_INVALID_EVENT(p, IGMP_HEADER_TOO_SMALL);
        return iRet;
    }
    if (!PacketIncreaseCheckLayers(p))
    {
        return iRet;
    }
    p->igmp = (IGMPHdrBase *)pkt;

    switch (p->igmp->ucType)
    {
        case IGMP_MEMBERSHIP_QUERY:
            if (len > 8 && (pkt[1] & 0x0F) != 0)
            {
                iRet = IgmpParseV3Query(p,pkt, len);
            }
            else
            {
                iRet = IgmpParseV1V2(p,pkt, len);
            }
            break;
        case IGMP_V1_MEMBERSHIP_REPORT:
            iRet = IgmpParseV1V2(p,pkt, len);
            break;
        case IGMP_V2_MEMBERSHIP_REPORT:
            if (len > 8 && pkt[2] == 0 && pkt[3] == 0)
            {
                iRet = ParseIGMPV3Report(p,pkt, len);
            }
            else
            {
                iRet = IgmpParseV1V2(p,pkt, len);
            }
            break;
        case IGMP_LEAVE_GROUP:
            iRet = IgmpParseV1V2(p,pkt, len);
            break;
        default:
            ENGINE_SET_INVALID_EVENT(p, IGMP_UNSUPPORTED_MST_TYPE);
            return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}


int DecodeIGMP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint32_t len)
{
    StatsIncr(tv, dtv->counter_igmp);
    if (unlikely(DecodeIGMPPacket(tv, p,pkt,len) < 0))
    {
        CLEAR_IGMP_PACKET(p);
        return TM_ECODE_FAILED;
    }
    p->proto = IPPROTO_IGMP;
    FlowSetupPacket(p);
    return TM_ECODE_OK;
}


#ifdef UNITTESTS
/**
 * \test DecodeIGMP
 */

static int DecodeIGMPtest (void)
{
    PASS;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for IGMP decoder
 */

void DecodeIGMPRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeIGMPtest", DecodeIGMPtest);
#endif
}
