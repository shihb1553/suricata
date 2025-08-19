#ifndef __APP_LAYER_BGP_H__
#define __APP_LAYER_BGP_H__

/* OPEN message Optional Parameter types  */
#define BGP_OPTION_AUTHENTICATION 1 /* RFC1771 */
#define BGP_OPTION_CAPABILITY     2 /* RFC2842 */

/* https://www.iana.org/assignments/capability-codes/capability-codes.xhtml (last updated
 * 2018-08-21) */
/* BGP capability code */
#define BGP_CAPABILITY_RESERVED                    0   /* RFC5492 */
#define BGP_CAPABILITY_MULTIPROTOCOL               1   /* RFC2858 */
#define BGP_CAPABILITY_ROUTE_REFRESH               2   /* RFC2918 */
#define BGP_CAPABILITY_COOPERATIVE_ROUTE_FILTERING 3   /* RFC5291 */
#define BGP_CAPABILITY_MULTIPLE_ROUTE_DEST         4   /* RFC8277 Deprecated */
#define BGP_CAPABILITY_EXTENDED_NEXT_HOP           5   /* RFC5549 */
#define BGP_CAPABILITY_EXTENDED_MESSAGE            6   /* draft-ietf-idr-bgp-extended-messages */
#define BGP_CAPABILITY_BGPSEC                      7   /* RFC8205 */
#define BGP_CAPABILITY_MULTIPLE_LABELS             8   /* RFC8277 */
#define BGP_CAPABILITY_BGP_ROLE                    9   /* draft-ietf-idr-bgp-open-policy */
#define BGP_CAPABILITY_GRACEFUL_RESTART            64  /* RFC4724 */
#define BGP_CAPABILITY_4_OCTET_AS_NUMBER           65  /* RFC6793 */
#define BGP_CAPABILITY_DYNAMIC_CAPABILITY_CISCO    66  /* Cisco Dynamic capabaility*/
#define BGP_CAPABILITY_DYNAMIC_CAPABILITY          67  /* draft-ietf-idr-dynamic-cap */
#define BGP_CAPABILITY_MULTISESSION                68  /* draft-ietf-idr-bgp-multisession */
#define BGP_CAPABILITY_ADDITIONAL_PATHS            69  /* [RFC7911] */
#define BGP_CAPABILITY_ENHANCED_ROUTE_REFRESH      70  /* [RFC7313] */
#define BGP_CAPABILITY_LONG_LIVED_GRACEFUL_RESTART 71  /* draft-uttaro-idr-bgp-persistence */
#define BGP_CAPABILITY_CP_ORF                      72  /* [RFC7543] */
#define BGP_CAPABILITY_FQDN                        73  /* draft-walton-bgp-hostname-capability */
#define BGP_CAPABILITY_ROUTE_REFRESH_CISCO         128 /* Cisco */
#define BGP_CAPABILITY_ORF_CISCO                   130 /* Cisco */
#define BGP_CAPABILITY_MULTISESSION_CISCO          131 /* Cisco */

/* attribute types */
#define BGPTYPE_ORIGIN           1  /* RFC4271           */
#define BGPTYPE_AS_PATH          2  /* RFC4271           */
#define BGPTYPE_NEXT_HOP         3  /* RFC4271           */
#define BGPTYPE_MULTI_EXIT_DISC  4  /* RFC4271           */
#define BGPTYPE_LOCAL_PREF       5  /* RFC4271           */
#define BGPTYPE_ATOMIC_AGGREGATE 6  /* RFC4271           */
#define BGPTYPE_AGGREGATOR       7  /* RFC4271           */
#define BGPTYPE_COMMUNITIES      8  /* RFC1997           */
#define BGPTYPE_ORIGINATOR_ID    9  /* RFC4456           */
#define BGPTYPE_CLUSTER_LIST     10 /* RFC4456           */
#define BGPTYPE_DPA              11 /* DPA (deprecated) [RFC6938]  */
#define BGPTYPE_ADVERTISER       12 /* ADVERTISER (historic) (deprecated) [RFC1863][RFC4223][RFC6938] */
#define BGPTYPE_RCID_PATH                                                                          \
    13 /* RCID_PATH / CLUSTER_ID (historic) (deprecated) [RFC1863][RFC4223][RFC6938] */
#define BGPTYPE_MP_REACH_NLRI      14 /* RFC4760           */
#define BGPTYPE_MP_UNREACH_NLRI    15 /* RFC4760           */
#define BGPTYPE_EXTENDED_COMMUNITY 16 /* RFC4360           */
#define BGPTYPE_AS4_PATH           17 /* RFC 6793          */
#define BGPTYPE_AS4_AGGREGATOR     18 /* RFC 6793          */
#define BGPTYPE_SAFI_SPECIFIC_ATTR                                                                 \
    19 /* SAFI Specific Attribute (SSA) (deprecated) draft-kapoor-nalawade-idr-bgp-ssa-00.txt */
#define BGPTYPE_CONNECTOR_ATTRIBUTE 20 /* Connector Attribute (deprecated) [RFC6037] */
#define BGPTYPE_AS_PATHLIMIT        21 /* AS_PATHLIMIT (deprecated) [draft-ietf-idr-as-pathlimit] */
#define BGPTYPE_PMSI_TUNNEL_ATTR    22 /* RFC6514 */
#define BGPTYPE_TUNNEL_ENCAPS_ATTR  23 /* RFC5512 */
#define BGPTYPE_TRAFFIC_ENGINEERING 24 /* Traffic Engineering [RFC5543] */
#define BGPTYPE_IPV6_ADDR_SPEC_EC   25 /* IPv6 Address Specific Extended Community [RFC5701] */
#define BGPTYPE_AIGP                26 /* RFC7311 */
#define BGPTYPE_PE_DISTING_LABLES   27 /* PE Distinguisher Labels [RFC6514] */
#define BGPTYPE_BGP_ENTROPY_LABEL                                                                  \
    28 /* BGP Entropy Label Capability Attribute (deprecated) [RFC6790][RFC7447] */
#define BGPTYPE_LINK_STATE_ATTR 29 /* RFC7752 */
#define BGPTYPE_30              30 /* Deprecated [RFC8093] */
#define BGPTYPE_31              31 /* Deprecated [RFC8093] */
#define BGPTYPE_LARGE_COMMUNITY 32 /* RFC8092 */
#define BGPTYPE_BGPSEC_PATH     33 /* BGPsec_PATH [RFC8205] */
#define BGPTYPE_D_PATH                                                                             \
    36 /* https://tools.ietf.org/html/draft-rabadan-sajassi-bess-evpn-ipvpn-interworking-02 */
#define BGPTYPE_BGP_PREFIX_SID 40 /* BGP Prefix-SID [RFC8669] */
#define BGPTYPE_LINK_STATE_OLD_ATTR                                                                \
    99                       /* squatted value used by at least 2                                  \
                                implementations before IANA assignment */
#define BGPTYPE_ATTR_SET 128 /* RFC6368           */
#define BGPTYPE_129      129 /* Deprecated [RFC8093] */
#define BGPTYPE_241      241 /* Deprecated [RFC8093] */
#define BGPTYPE_242      242 /* Deprecated [RFC8093] */
#define BGPTYPE_243      243 /* Deprecated [RFC8093] */

/* attribute flags, from RFC1771 */
#define BGP_ATTR_FLAG_OPTIONAL        0x80
#define BGP_ATTR_FLAG_TRANSITIVE      0x40
#define BGP_ATTR_FLAG_PARTIAL         0x20
#define BGP_ATTR_FLAG_EXTENDED_LENGTH 0x10
#define BGP_ATTR_FLAG_UNUSED          0x0F

/* AS_PATH segment types */
#define BGP_ATTR_AS_SET             1 /* RFC1771 */
#define BGP_ATTR_AS_SEQUENCE        2 /* RFC1771 */
#define BGP_ATTR_AS_CONFED_SET      4 /* RFC1965 has the wrong values, corrected in  */
#define BGP_ATTR_AS_CONFED_SEQUENCE 3 /* draft-ietf-idr-bgp-confed-rfc1965bis-01.txt */

void RegisterBgpParsers(void);
void BgpParserRegisterTests(void);

typedef struct tagStBgpHeader {
    unsigned char ucChar[16];
    unsigned short usLen;
    unsigned char ucType;
} BgpHeader;

#pragma pack(1)
typedef struct tagStBgpOpenMsg {
    unsigned char ucVer;
    unsigned short usSys;
    unsigned short usHoldTime;
    unsigned char ucRouteId[4];
    unsigned char ucOptParamLen;
} BgpOpenMsg;
#pragma pack()

typedef struct tagStBgpUpdateMsg {
    unsigned short usWithdrawnRoutesLen;
    unsigned short usPathAttrLen;
} BgpUpdateMsg;
typedef struct tagStBgpPathAddrItem {
    unsigned char ucFlags;
    unsigned char ucType;
} BgpPathAddrItem;

typedef struct tagStBgpOptParamItem {
    unsigned char ucParamType;
    unsigned char ucParamLen;
} BgpOptParamItem;

typedef struct tagStBgpNotifyMsg {
    unsigned char ucErrCode;
    unsigned char ucErrSubCode;
} BgpNotifyMsg;

enum BgpMsgType {
    BGP_MSG_TYPE_OPEN = 1,
    BGP_MSG_TYPE_UPDATE,
    BGP_MSG_TYPE_NOTIFICATION,
    BGP_MSG_TYPE_KEEPALIVE,
    BGP_MSG_TYPE_ROUTE_REFRESH,
    BGP_MSG_TYPE_CAPABILITY,
    BGP_MSG_TYPE_ROUTE_REFRESH_CISCO = 0x80
};

#define BGP_MAX_PACKET_SIZE           4096
#define BGP_MARKER_SIZE               16 /* size of BGP marker */
#define BGP_HEADER_SIZE               19 /* size of BGP header, including marker */
#define BGP_MIN_OPEN_MSG_SIZE         29
#define BGP_MIN_UPDATE_MSG_SIZE       23
#define BGP_MIN_NOTIFICATION_MSG_SIZE 21
#define BGP_MIN_KEEPALVE_MSG_SIZE     BGP_HEADER_SIZE
#define BGP_TCP_PORT                  179
#define BGP_ROUTE_DISTINGUISHER_SIZE  8

typedef struct BgpTransaction {
    struct BgpState_ *Bgp;

    uint64_t tx_num; /**< internal: id */
    uint16_t tx_id;  /**< transaction id */

    uint8_t *request_buffer;
    uint32_t request_buffer_len;

    uint8_t *response_buffer;
    uint32_t response_buffer_len;
    int iMsgType;
    BgpOpenMsg stOpenMsg;
    BgpNotifyMsg stNotifyMsg;
    DetectEngineState *de_state;
    TAILQ_ENTRY(BgpTransaction) next;
    AppLayerTxData tx_data;

} BgpTransaction;

typedef struct BgpState_ {

    AppLayerStateData state_data;

    /** List of LLMNR transactions associated with this
     *  state. */
    TAILQ_HEAD(, BgpTransaction) tx_list;

    /** A count of the number of transactions created. The
     *  transaction ID for each transaction is allocted
     *  by incrementing this value. */
    uint64_t transaction_max;

    BgpTransaction *curr; /**< ptr to current tx */
    BgpTransaction *iter;
    uint64_t tx_with_detect_state_cnt;

    uint16_t events;
    uint16_t givenup;

    /* used by TCP only */
    uint16_t offset;
    uint16_t record_len;
    uint8_t *buffer;
} BgpState;

#endif
