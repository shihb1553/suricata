#ifndef __DECODE_IGMP_H__
#define __DECODE_IGMP_H__

#ifndef IPPROTO_IGMP
#define IPPROTO_IGMP 2
#endif

#define IGMP_VERSION_1 1
#define IGMP_VERSION_2 2
#define IGMP_VERSION_3 3

// IGMP v1 and v2 message type
#define IGMP_MEMBERSHIP_QUERY     0x11
#define IGMP_V1_MEMBERSHIP_REPORT 0x12
#define IGMP_V2_MEMBERSHIP_REPORT 0x22
#define IGMP_LEAVE_GROUP          0x23

#define IGMP_V3_MEMBERSHIP_REPORT 0x22

#define MODE_IS_INCLUDE   1
#define MODE_IS_EXCLUDE   2
#define CHANGE_TO_INCLUDE 3
#define CHANGE_TO_EXCLUDE 4
#define ALLOW_NEW_SOURCES 5
#define BLOCK_OLD_SOURCES 6

typedef struct tagStIGMPV3QueryHdr {
    unsigned char ucType; // 0x22
    unsigned char ucMaxRespTimeFlags;
    unsigned short usChecksum;
    unsigned char ucFlagQrvQqic; // 1 bit flag;3 bits qrv; 4 bits qqic
    unsigned short usNumSources;
    unsigned int *uipSourceAddrs;
} IGMPV3QueryHdr;

typedef struct tagStIGMPV3GroupRecord {
    unsigned char ucRecordType;
    unsigned char ucAuxDataLen;
    unsigned short usNumSources;
    unsigned int uiMulticastAddr;
    unsigned int *puiSourceAddrs;
} IGMPV3GroupRecord;

typedef struct tagStIGMPV3ReportHdr {
    unsigned char ucType; // 0x022
    unsigned char ucResv1;
    unsigned short usChecksum;
    unsigned short ucResv2;
    unsigned short usNumGroupRecords;
    IGMPV3GroupRecord *pstRecords;
} IGMPV3ReportHdr;

typedef struct tagStIGMPHdrBase {
    unsigned char ucType;
    unsigned char ucMaxRespTime;
    unsigned short usChecksum;
    unsigned int uiGroupAddr;
} IGMPHdrBase;

#define CLEAR_IGMP_PACKET(p)                                                                       \
    {                                                                                              \
        (p)->igmp = NULL;                                                                          \
    }                                                                                              \
    while (0)

void DecodeIGMPRegisterTests(void);

#endif
