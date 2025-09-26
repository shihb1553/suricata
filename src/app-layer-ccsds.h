#ifndef __APP_LAYER_CCSDS_H__
#define __APP_LAYER_CCSDS_H__

#include "detect-engine-state.h"

#include "queue.h"

void RegisterCcsdsParsers(void);
void CcsdsParserRegisterTests(void);

#define HDR_VERSION 0xe000
#define HDR_TYPE    0x1000
#define HDR_SECHDR  0x0800
#define HDR_APID    0x07ff

/* some basic sizing parameters */
enum {
    IP_HEADER_LENGTH = 48,
    VCDU_HEADER_LENGTH = 6,
    CCSDS_PRIMARY_HEADER_LENGTH = 6,
    CCSDS_SECONDARY_HEADER_LENGTH = 10
};

/*
 * CCSDS packet header
 */
typedef struct stCcsdsHdr {
    unsigned short usVerType; // 3bits ver,1 bit packet type,1 bit secondaryHeader flag,11 bits apid
    unsigned short usSeqInfo; // 2 bits sequence Flag; 14 bits sequence cout
    unsigned short usPacketDataLen;
} CcsdsHdr;

typedef struct CcsdsSecondHdr {
    unsigned char ucTime[4];
    unsigned char ucHdrTypeCat; // 1 bit header type;7bits category
    unsigned char ucAduCount;
    unsigned char ucAduChannelId;
    unsigned char ucSegInfo; // 2bit segementFlag;14bits segmentcount
} CcsdsSecondHdr;

typedef struct CcsdsTransaction_ {
    struct CcsdsState_ *Ccsds;

    uint64_t tx_num; /**< internal: id */
    uint16_t tx_id;  /**< transaction id */

    uint8_t *request_buffer;
    uint32_t request_buffer_len;

    uint8_t *response_buffer;
    uint32_t response_buffer_len;

    DetectEngineState *de_state;
    TAILQ_ENTRY(CcsdsTransaction_) next;
    AppLayerTxData tx_data;

} CcsdsTransaction;

typedef struct CcsdsState_ {

    AppLayerStateData state_data;

    /** List of LLMNR transactions associated with this
     *  state. */
    TAILQ_HEAD(, CcsdsTransaction_) tx_list;

    /** A count of the number of transactions created. The
     *  transaction ID for each transaction is allocted
     *  by incrementing this value. */
    uint64_t transaction_max;

    CcsdsTransaction *curr; /**< ptr to current tx */
    CcsdsTransaction *iter;
    uint64_t tx_with_detect_state_cnt;

    uint16_t events;
    uint16_t givenup;
} CcsdsState;

#endif /* __APP_LAYER_LLMNR_H__ */
