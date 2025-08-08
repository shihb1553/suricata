#ifndef __DETECT_RECORD_H__
#define __DETECT_RECORD_H__

#include "suricata-common.h"

#define DETECT_RECORD_MATCH_LIMIT 10
#define DETECT_RECORD_MAX_RECORDS 50

enum {
    DETECT_RECORD_TYPE_SESSION,
    DETECT_RECORD_TYPE_IPPAIRS,
    DETECT_RECORD_TYPE_HOST,
    DETECT_RECORD_TYPE_MAX
};

enum {
    DETECT_RECORD_DIR_SRC,
    DETECT_RECORD_DIR_DST,
};

/** This will be the rule options/parameters */
typedef struct DetectRecordData_ {
    uint8_t type;          /**< record type */
    uint8_t direction;     /**< host direction */
    uint32_t packets;      /**< packets */
    uint32_t bytes;        /**< bytes */
    uint32_t seconds;      /**< seconds */
    char *file;            /**< filename of the record */
} DetectRecordData;

/** This is the installed data at the session/global or host table */
typedef struct DetectRecordDataEntry_ {
    uint8_t flags;
    uint16_t cnt_match;                 /**< number of times this record was reset/updated */

    uint32_t packet_limit;              /**< packet setting from rule */
    uint32_t byte_limit;                /**< byte setting from rule */
    uint32_t time_limit;                /**< second setting from rule */
    uint32_t sid;                       /**< sid originating */
    uint32_t gid;                       /**< gid originating */
    uint32_t packets;                   /**< number of packets */
    uint32_t bytes;                     /**< number of bytes */
    uint32_t first_ts;                  /**< First time seen */
    uint32_t last_ts;                   /**< Last time seen (to prune old sessions) */
    char *file;                         /**< filename of the record */

    struct DetectRecordDataEntry_ *next;   /**< Pointer to the next record of this
                                         *   session/src_host/dst_host (if any from other rule) */
} DetectRecordDataEntry;

#define RECORD_ENTRY_FLAG_DIR_SRC          0x01
#define RECORD_ENTRY_FLAG_DIR_DST          0x02

/* prototypes */
struct DetectEngineCtx_ ;
void DetectRecordRegister(void);
void DetectRecordDataFree(struct DetectEngineCtx_ *, void *ptr);
void DetectRecordDataListFree(void *ptr);

#endif /* __DETECT_RECORD_H__ */
