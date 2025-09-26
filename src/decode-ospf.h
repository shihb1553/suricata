#ifndef __DECODE_OSPF_H__
#define __DECODE_OSPF_H__


#ifndef IPPROTO_OSPF
#define IPPROTO_OSPF 89
#endif

#define OSPF_VERSION_2               2
#define OSPF_VERSION_3               3
#define OSPF_AF_4                    4
#define OSPF_AF_6                    6
#define OSPF_VERSION_2_HEADER_LENGTH 24
#define OSPF_VERSION_3_HEADER_LENGTH 16

#define OSPF_HELLO   1
#define OSPF_DB_DESC 2
#define OSPF_LS_REQ  3
#define OSPF_LS_UPD  4
#define OSPF_LS_ACK  5
#define OSPF_LS_BASE OSPF_HELLO

typedef struct tagStOSPFHdrBase {
    unsigned char ucVer;
    unsigned char ucMsgType;
    unsigned short usLen;
    unsigned char ucSourceRouter[4];
    unsigned char ucAreaId[4];
    unsigned short usCheckSum;
} OSPFHdrBase;

typedef struct tagStOSPV3Hdr {
    OSPFHdrBase stBase;
    unsigned char ucInstanceId;
    unsigned char ucReserved;
} OSPFV3Hdr;

typedef struct tagStOSPV2Hdr {
    OSPFHdrBase stBase;
    unsigned short usAuthType;
} OSPFV2Hdr;

#define CLEAR_OSPF_PACKET(p)                                                                       \
    {                                                                                              \
        (p)->ospf = NULL;                                                                          \
    }                                                                                              \
    while (0)

typedef struct tagStOSPFV2HelloPacket {
    unsigned char ucNetMask[4];
    unsigned short usInterval; // sec
    unsigned char ucOptions;
    unsigned char ucRouterPriority;
    int iDeadInterval; // sec
    unsigned char ucDesignatedRouter[4];
    unsigned char ucBackupRouter[4];
    unsigned char ucNeighbor[4];
} OSPFV2HelloPacket;

typedef struct tagStOSPFV2DBDesc {
    unsigned short usInterfaceMtu;
    unsigned char ucOption;
    unsigned char ucDBDesc;
    unsigned int uiDDSeq;
} OSPFV2DBDesc;

typedef struct tagStOSPFV3HelloPacket {
    int iInterfaceId;
    unsigned char ucRouterPriority;
    unsigned char ucOptions[3];
    unsigned short usHelloInterval; // sec
    unsigned short usDeadInterval;  // sec
    unsigned char ucDesignatedRouter[4];
    unsigned char ucBackupRouter[4];
    unsigned char ucNeighbor[4];
} OSPFV3HelloPacket;

typedef struct tagStOSPFV3DBDesc {
    unsigned char ucResv;
    unsigned char ucOption[3];
    unsigned short usInterfaceMtu;
    unsigned char ucResv1;
    unsigned char ucDBDesc;
    unsigned int uiDDSeq;
} OSPFV3DBDesc;

typedef struct tagOSPFLSAV2Hdr {
    unsigned short usLSAge; // lsa 老化时间
    unsigned char ucOption;
    unsigned char ucLSType;
    unsigned char ucLinkStateId[4]; // 本路由器对应网卡IP
    unsigned char ucAdvRouter[4];   // 本路由器Router ID
    unsigned int uiSeqNum;
    unsigned short usChecksum;
    unsigned short usLen;
} OSPFLSAV2Hdr;

typedef struct tagOSPFLSAV3Hdr {
    unsigned short usLSAge; // lsa 老化时间
    unsigned short usLSType;
    unsigned char ucLinkStateId[4]; // 本路由器对应网卡IP
    unsigned char ucAdvRouter[4];   // 本路由器Router ID
    unsigned int uiSeqNum;
    unsigned short usChecksum;
    unsigned short usLen;
} OSPFLSAV3Hdr;

typedef struct tagOSPFLSAV2Req {
    unsigned int uiLSType;
    unsigned char ucLinkStateId[4];
    unsigned char ucAdvRouter[4];
} OSPFLSAV2Req;

void DecodeOSPFRegisterTests(void);

#endif
