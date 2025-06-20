#include "suricata-common.h"
#include "detect-engine.h"
#include "util-hash.h"
#include "util-atomic.h"
#include "util-time.h"
#include "util-hashlist.h"
#include "detect-engine-record.h"
#include "detect-engine-build.h"
#include "detect-record.h"
#include "host.h"
#include "host-storage.h"
#include "flow-storage.h"
#include "ippair-storage.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "flow-util.h"
#include "stream-tcp-private.h"

SC_ATOMIC_DECLARE(unsigned int, num_records);

static HostStorageId host_record_id = { .id = -1 }; /**< Host storage id for records */
static FlowStorageId flow_record_id = { .id = -1 }; /**< Flow storage id for records */
static IPPairStorageId ippair_record_id = { .id = -1 }; /**< IPPair storage id for records */

void RecordInitCtx(void)
{
    SC_ATOMIC_INIT(num_records);

    host_record_id = HostStorageRegister("record", sizeof(void *), NULL, DetectRecordDataListFree);
    if (host_record_id.id == -1) {
        FatalError("Can't initiate host storage for record");
    }
    flow_record_id = FlowStorageRegister("record", sizeof(void *), NULL, DetectRecordDataListFree);
    if (flow_record_id.id == -1) {
        FatalError("Can't initiate flow storage for record");
    }
    ippair_record_id = IPPairStorageRegister("record", sizeof(void *), NULL, DetectRecordDataListFree);
    if (ippair_record_id.id == -1) {
        FatalError("Can't initiate ippair storage for record");
    }
}

/**
 * \brief Destroy record context hash tables
 *
 * \param record_ctx Record Context
 *
 */
void RecordDestroyCtx(void)
{
#ifdef DEBUG
    BUG_ON(SC_ATOMIC_GET(num_records) != 0);
#endif
}

/** \brief Reset the record engine context
 */
void RecordRestartCtx(void)
{
    RecordDestroyCtx();
    RecordInitCtx();
}

int RecordIPPairHasRecord(IPPair *ipp)
{
    return IPPairGetStorageById(ipp, ippair_record_id) ? 1 : 0;
}

int RecordHostHasRecord(Host *host)
{
    return HostGetStorageById(host, host_record_id) ? 1 : 0;
}

static DetectRecordDataEntry *DetectRecordDataCopy(DetectRecordDataEntry *drd)
{
    DetectRecordDataEntry *rde = SCMalloc(sizeof(DetectRecordDataEntry));
    if (unlikely(rde == NULL)) {
        return NULL;
    }
    memset(rde, 0, sizeof(DetectRecordDataEntry));

    rde->sid = drd->sid;
    rde->gid = drd->gid;
    rde->flags = drd->flags;
    rde->packet_limit = drd->packet_limit;
    rde->byte_limit = drd->byte_limit;
    rde->time_limit = drd->time_limit;
    rde->file = strdup(drd->file);

    rde->first_ts = drd->first_ts;
    rde->last_ts = drd->last_ts;
    return rde;
}

/**
 * \brief This function is used to add a record to a session (type session)
 *        or update it if it's already installed. The number of times to
 *        allow an update is limited by DETECT_RECORD_MATCH_LIMIT. This way
 *        repetitive matches to the same rule are limited of setting records,
 *        to avoid DOS attacks
 *
 * \param rde pointer to the new DetectRecordDataEntry
 * \param p pointer to the current packet
 *
 * \retval 0 if the rde was added successfully
 * \retval 1 if an entry of this sid/gid already exist and was updated
 */
int RecordFlowAdd(DetectRecordDataEntry *rde, Packet *p)
{
    uint8_t updated = 0;
    uint16_t record_cnt = 0;
    DetectRecordDataEntry *iter = NULL;

    if (p->flow == NULL)
        return 1;

    iter = FlowGetStorageById(p->flow, flow_record_id);
    if (iter != NULL) {
        /* First iterate installed entries searching a duplicated sid/gid */
        for (; iter != NULL; iter = iter->next) {
            record_cnt++;

            if (iter->sid == rde->sid && iter->gid == rde->gid) {
                iter->cnt_match++;

                /* If so, update data, unless the maximum MATCH limit is
                 * reached. This prevents possible DOS attacks */
                if (iter->cnt_match < DETECT_RECORD_MATCH_LIMIT) {
                    /* Reset time and counters */
                    iter->first_ts = iter->last_ts = rde->first_ts;
                    iter->packets = 0;
                    iter->bytes = 0;
                }
                updated = 1;
                break;
            }
        }
    }

    /* If there was no entry of this rule, prepend the new rde */
    if (updated == 0 && record_cnt < DETECT_RECORD_MAX_RECORDS) {
        DetectRecordDataEntry *new_tde = DetectRecordDataCopy(rde);
        if (new_tde != NULL) {
            new_tde->next = FlowGetStorageById(p->flow, flow_record_id);
            FlowSetStorageById(p->flow, flow_record_id, new_tde);
            SCLogDebug("adding record with first_ts %u", new_tde->first_ts);
            (void) SC_ATOMIC_ADD(num_records, 1);
        }
    } else if (record_cnt == DETECT_RECORD_MAX_RECORDS) {
        SCLogDebug("Max records for sessions reached (%"PRIu16")", record_cnt);
    }

    return updated;
}

/**
 * \brief Add a record entry for an ippair. If it already exist, update it.
 *
 * \param record_ctx Record context for ippairs
 * \param rde Record data
 * \param p packet
 *
 * \retval 0 if it was added, 1 if it was updated
 */
int RecordIPPairAdd(DetectRecordDataEntry *rde, Packet *p)
{
    SCEnter();

    uint8_t updated = 0;
    uint16_t nrecords = 0;

    IPPair *ipp = IPPairGetIPPairFromHash(&p->src, &p->dst);
    if (ipp == NULL)
        return -1;

    void *record = IPPairGetStorageById(ipp, ippair_record_id);
    if (record == NULL) {
        /* get a new rde as the one we have is on the stack */
        DetectRecordDataEntry *new_tde = DetectRecordDataCopy(rde);
        if (new_tde != NULL) {
            IPPairSetStorageById(ipp, ippair_record_id, new_tde);
            (void) SC_ATOMIC_ADD(num_records, 1);
            SCLogDebug("ippair record added");
        }
    } else {
        /* Append the record to the list of this ippair */
        SCLogDebug("updating existing ippair");

        /* First iterate installed entries searching a duplicated sid/gid */
        DetectRecordDataEntry *iter = NULL;

        for (iter = record; iter != NULL; iter = iter->next) {
            nrecords++;
            if (iter->sid == rde->sid && iter->gid == rde->gid) {
                iter->cnt_match++;
                /* If so, update data, unless the maximum MATCH limit is
                 * reached. This prevents possible DOS attacks */
                if (iter->cnt_match < DETECT_RECORD_MATCH_LIMIT) {
                    /* Reset time and counters */
                    iter->first_ts = iter->last_ts = rde->first_ts;
                    iter->packets = 0;
                    iter->bytes = 0;
                }
                updated = 1;
                break;
            }
        }

        /* If there was no entry of this rule, append the new rde */
        if (updated == 0 && nrecords < DETECT_RECORD_MAX_RECORDS) {
            /* get a new rde as the one we have is on the stack */
            DetectRecordDataEntry *new_tde = DetectRecordDataCopy(rde);
            if (new_tde != NULL) {
                (void) SC_ATOMIC_ADD(num_records, 1);

                new_tde->next = record;
                IPPairSetStorageById(ipp, ippair_record_id, new_tde);
            }
        } else if (nrecords == DETECT_RECORD_MAX_RECORDS) {
            SCLogDebug("Max records for sessions reached (%"PRIu16")", nrecords);
        }
    }

    IPPairRelease(ipp);
    SCReturnInt(updated);
}

/**
 * \brief Add a record entry for a host. If it already exist, update it.
 *
 * \param record_ctx Record context for hosts
 * \param rde Record data
 * \param p packet
 *
 * \retval 0 if it was added, 1 if it was updated
 */
int RecordHostAdd(DetectRecordDataEntry *rde, Packet *p)
{
    SCEnter();

    uint8_t updated = 0;
    uint16_t nrecords = 0;
    Host *host = NULL;

    /* Lookup host in the hash. If it doesn't exist yet it's
     * created. */
    if (rde->flags & RECORD_ENTRY_FLAG_DIR_SRC) {
        host = HostGetHostFromHash(&p->src);
    } else if (rde->flags & RECORD_ENTRY_FLAG_DIR_DST) {
        host = HostGetHostFromHash(&p->dst);
    }
    /* no host for us */
    if (host == NULL) {
        SCLogDebug("host record not added: no host");
        return -1;
    }

    void *record = HostGetStorageById(host, host_record_id);
    if (record == NULL) {
        /* get a new rde as the one we have is on the stack */
        DetectRecordDataEntry *new_tde = DetectRecordDataCopy(rde);
        if (new_tde != NULL) {
            HostSetStorageById(host, host_record_id, new_tde);
            (void) SC_ATOMIC_ADD(num_records, 1);
            SCLogDebug("host record added");
        }
    } else {
        /* Append the record to the list of this host */
        SCLogDebug("updating existing host");

        /* First iterate installed entries searching a duplicated sid/gid */
        DetectRecordDataEntry *iter = NULL;

        for (iter = record; iter != NULL; iter = iter->next) {
            nrecords++;
            if (iter->sid == rde->sid && iter->gid == rde->gid) {
                iter->cnt_match++;
                /* If so, update data, unless the maximum MATCH limit is
                 * reached. This prevents possible DOS attacks */
                if (iter->cnt_match < DETECT_RECORD_MATCH_LIMIT) {
                    /* Reset time and counters */
                    iter->first_ts = iter->last_ts = rde->first_ts;
                    iter->packets = 0;
                    iter->bytes = 0;
                }
                updated = 1;
                break;
            }
        }

        /* If there was no entry of this rule, append the new rde */
        if (updated == 0 && nrecords < DETECT_RECORD_MAX_RECORDS) {
            /* get a new rde as the one we have is on the stack */
            DetectRecordDataEntry *new_tde = DetectRecordDataCopy(rde);
            if (new_tde != NULL) {
                (void) SC_ATOMIC_ADD(num_records, 1);

                new_tde->next = record;
                HostSetStorageById(host, host_record_id, new_tde);
            }
        } else if (nrecords == DETECT_RECORD_MAX_RECORDS) {
            SCLogDebug("Max records for sessions reached (%"PRIu16")", nrecords);
        }
    }

    HostRelease(host);
    SCReturnInt(updated);
}

static void RecordHandlePacketFlow(Flow *f, Packet *p)
{
    if (FlowGetStorageById(f, flow_record_id) == NULL)
        return;

    DetectRecordDataEntry *rde = NULL;
    DetectRecordDataEntry *prev = NULL;
    DetectRecordDataEntry *iter = FlowGetStorageById(f, flow_record_id);
    uint8_t flag_added = 0;

    while (iter != NULL) {
        /* update counters */
        iter->last_ts = SCTIME_SECS(p->ts);
        iter->packets++;
        iter->bytes += GET_PKT_LEN(p);

        /* remove if record expired; and set alerts */
        if ((iter->packet_limit && iter->packets > iter->packet_limit)
                || (iter->byte_limit && iter->bytes > iter->byte_limit)
                || (iter->time_limit && iter->last_ts - iter->first_ts > iter->time_limit)) {
            /* record expired */
            if (prev != NULL) {
                rde = iter;
                prev->next = iter->next;
                iter = iter->next;
                SCFree(rde->file);
                SCFree(rde);
                (void) SC_ATOMIC_SUB(num_records, 1);
                continue;
            } else {
                FlowSetStorageById(p->flow, flow_record_id, iter->next);
                rde = iter;
                iter = iter->next;
                SCFree(rde->file);
                SCFree(rde);
                (void) SC_ATOMIC_SUB(num_records, 1);
                continue;
            }
        } else if (flag_added == 0) {
            /* It's matching the record. Add it to be logged and
                * update "flag_added" to add the packet once. */
            p->flags |= PKT_HAS_RECORD;
            flag_added++;
        }

        prev = iter;
        iter = iter->next;
    }
}

static void RecordHandlePacketIPPair(IPPair *ipp, Packet *p)
{
    DetectRecordDataEntry *rde = NULL;
    DetectRecordDataEntry *prev = NULL;
    DetectRecordDataEntry *iter;
    uint8_t flag_added = 0;

    iter = IPPairGetStorageById(ipp, ippair_record_id);
    prev = NULL;
    while (iter != NULL) {
        /* update counters */
        iter->last_ts = SCTIME_SECS(p->ts);
        iter->packets++;
        iter->bytes += GET_PKT_LEN(p);

        /* remove if record expired; and set alerts */
        if ((iter->packet_limit && iter->packets > iter->packet_limit)
                || (iter->byte_limit && iter->bytes > iter->byte_limit)
                || (iter->time_limit && iter->last_ts - iter->first_ts > iter->time_limit)) {
            /* record expired */
            if (prev != NULL) {
                rde = iter;
                prev->next = iter->next;
                iter = iter->next;
                SCFree(rde->file);
                SCFree(rde);
                (void) SC_ATOMIC_SUB(num_records, 1);
                continue;
            } else {
                IPPairSetStorageById(ipp, ippair_record_id, iter->next);
                rde = iter;
                iter = iter->next;
                SCFree(rde->file);
                SCFree(rde);
                (void) SC_ATOMIC_SUB(num_records, 1);
                continue;
            }
        } else if (flag_added == 0) {
            /* It's matching the record. Add it to be logged and
                * update "flag_added" to add the packet once. */
            p->flags |= PKT_HAS_RECORD;
            flag_added++;
        }

        prev = iter;
        iter = iter->next;
    }
}

static void RecordHandlePacketHost(Host *host, Packet *p)
{
    DetectRecordDataEntry *rde = NULL;
    DetectRecordDataEntry *prev = NULL;
    DetectRecordDataEntry *iter;
    uint8_t flag_added = 0;

    iter = HostGetStorageById(host, host_record_id);
    prev = NULL;
    while (iter != NULL) {
        /* update counters */
        iter->last_ts = SCTIME_SECS(p->ts);
        iter->packets++;
        iter->bytes += GET_PKT_LEN(p);

        /* remove if record expired; and set alerts */
        if ((iter->packet_limit && iter->packets > iter->packet_limit)
                || (iter->byte_limit && iter->bytes > iter->byte_limit)
                || (iter->time_limit && iter->last_ts - iter->first_ts > iter->time_limit)) {
            /* record expired */
            if (prev != NULL) {
                rde = iter;
                prev->next = iter->next;
                iter = iter->next;
                SCFree(rde->file);
                SCFree(rde);
                (void) SC_ATOMIC_SUB(num_records, 1);
                continue;
            } else {
                HostSetStorageById(host, host_record_id, iter->next);
                rde = iter;
                iter = iter->next;
                SCFree(rde->file);
                SCFree(rde);
                (void) SC_ATOMIC_SUB(num_records, 1);
                continue;
            }
        } else if (flag_added == 0) {
            /* It's matching the record. Add it to be logged and
                * update "flag_added" to add the packet once. */
            p->flags |= PKT_HAS_RECORD;
            flag_added++;
        }

        prev = iter;
        iter = iter->next;
    }
}

/**
 * \brief Search records for src and dst. Update entries of the record, remove if necessary
 *
 * \param de_ctx Detect context
 * \param det_ctx Detect thread context
 * \param p packet
 *
 */
void RecordHandlePacket(DetectEngineCtx *de_ctx,
                     DetectEngineThreadCtx *det_ctx, Packet *p)
{
    SCEnter();

    /* If there's no record, get out of here */
    unsigned int current_records = SC_ATOMIC_GET(num_records);
    if (current_records == 0)
        SCReturn;

    /* First update and get session records */
    if (p->flow != NULL) {
        RecordHandlePacketFlow(p->flow, p);
    }

    /* Then update and get ippair records */
    IPPair *ipp = IPPairGetIPPairFromHash(&p->src, &p->dst);
    if (ipp) {
        if (RecordIPPairHasRecord(ipp)) {
            RecordHandlePacketIPPair(ipp, p);
        }
        IPPairRelease(ipp);
    }

    Host *src = HostLookupHostFromHash(&p->src);
    if (src) {
        if (RecordHostHasRecord(src)) {
            RecordHandlePacketHost(src,p);
        }
        HostRelease(src);
    }
    Host *dst = HostLookupHostFromHash(&p->dst);
    if (dst) {
        if (RecordHostHasRecord(dst)) {
            RecordHandlePacketHost(dst,p);
        }
        HostRelease(dst);
    }
    SCReturn;
}

/**
 * \brief Removes the entries exceeding the max timeout value
 *
 * \param record_ctx Record context
 * \param ts the current time
 *
 * \retval 1 no records or records removed -- host is free to go (from record perspective)
 * \retval 0 still active records
 */
int RecordHostTimeoutCheck(Host *host, SCTime_t ts)
{
    DetectRecordDataEntry *rde = NULL;
    DetectRecordDataEntry *tmp = NULL;
    DetectRecordDataEntry *prev = NULL;
    int retval = 1;

    tmp = HostGetStorageById(host, host_record_id);
    if (tmp == NULL)
        return 1;

    prev = NULL;
    while (tmp != NULL) {
        SCTime_t timeout_at = SCTIME_FROM_SECS(tmp->last_ts + RECORD_MAX_LAST_TIME_SEEN);
        if (SCTIME_CMP_GTE(timeout_at, ts)) {
            prev = tmp;
            tmp = tmp->next;
            retval = 0;
            continue;
        }

        /* timed out */

        if (prev != NULL) {
            prev->next = tmp->next;

            rde = tmp;
            tmp = rde->next;

            SCFree(rde);
            (void) SC_ATOMIC_SUB(num_records, 1);
        } else {
            HostSetStorageById(host, host_record_id, tmp->next);

            rde = tmp;
            tmp = rde->next;

            SCFree(rde);
            (void) SC_ATOMIC_SUB(num_records, 1);
        }
    }
    return retval;
}

int RecordIPPairTimeoutCheck(IPPair *ipp, SCTime_t ts)
{
    DetectRecordDataEntry *rde = NULL;
    DetectRecordDataEntry *tmp = NULL;
    DetectRecordDataEntry *prev = NULL;
    int retval = 1;

    tmp = IPPairGetStorageById(ipp, ippair_record_id);
    if (tmp == NULL)
        return 1;

    prev = NULL;
    while (tmp != NULL) {
        SCTime_t timeout_at = SCTIME_FROM_SECS(tmp->last_ts + RECORD_MAX_LAST_TIME_SEEN);
        if (SCTIME_CMP_GTE(timeout_at, ts)) {
            prev = tmp;
            tmp = tmp->next;
            retval = 0;
            continue;
        }

        /* timed out */

        if (prev != NULL) {
            prev->next = tmp->next;

            rde = tmp;
            tmp = rde->next;

            SCFree(rde);
            (void) SC_ATOMIC_SUB(num_records, 1);
        } else {
            IPPairSetStorageById(ipp, ippair_record_id, tmp->next);

            rde = tmp;
            tmp = rde->next;

            SCFree(rde);
            (void) SC_ATOMIC_SUB(num_records, 1);
        }
    }
    return retval;
}

#ifdef UNITTESTS

/**
 * \test host record: packets
 */
static int DetectRecordTestPacket01 (void)
{
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint8_t *buf2 = (uint8_t *)"lalala!";
    uint16_t buf_len = strlen((char *)buf);
    uint16_t buf_len2 = strlen((char *)buf2);

    Packet *p[7];
    p[0] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[1] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[2] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.9",
                              41424, 80);
    p[3] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.9",
                              41424, 80);
    p[4] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.9",
                              41424, 80);
    p[5] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.11",
                              41424, 80);
    p[6] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.11",
                              41424, 80);

    const char *sigs[5];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing record 1\"; content:\"Hi all\"; record:host,\"aaa.pcap\",3,0,0,src; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"Hi all\"; record:host,\"aaa.pcap\",4,0,0,dst; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:3;)";
    sigs[3]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:5;)";

    uint32_t sid[5] = {1,2,3,4,5};

    int32_t results[7][5] = {
                              {1, 1, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0}
                             };
    StorageInit();
    RecordInitCtx();
    StorageFinalize();
    HostInitConfig(1);
    FlowInitConfig(1);
    IPPairInitConfig(1);

    SCLogDebug("running tests");
    FAIL_IF_NOT(UTHGenericTest(p, 7, sigs, sid, (uint32_t *)results, 5));
    SCLogDebug("running tests done");

    Host *src = HostLookupHostFromHash(&p[1]->src);
    FAIL_IF_NULL(src);
    FAIL_IF_NOT_NULL(HostGetStorageById(src, host_record_id));

    Host *dst = HostLookupHostFromHash(&p[1]->dst);
    FAIL_IF_NULL(dst);

    void *record = HostGetStorageById(dst, host_record_id);
    FAIL_IF_NULL(record);

    DetectRecordDataEntry *iter = record;

    /* check internal state */
    FAIL_IF_NOT(iter->gid == 1);
    FAIL_IF_NOT(iter->sid == 2);
    FAIL_IF_NOT(iter->packets == 4);

    HostRelease(src);
    HostRelease(dst);

    UTHFreePackets(p, 7);

    HostShutdown();
    IPPairShutdown();
    FlowShutdown();
    RecordDestroyCtx();
    StorageCleanup();
    PASS;
}

/**
 * \test host record: seconds
 */
static int DetectRecordTestPacket02 (void)
{
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint8_t *buf2 = (uint8_t *)"lalala!";
    uint16_t buf_len = strlen((char *)buf);
    uint16_t buf_len2 = strlen((char *)buf2);

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    StorageInit();
    RecordInitCtx();
    StorageFinalize();
    HostInitConfig(1);
    FlowInitConfig(1);
    IPPairInitConfig(1);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Packet *p[7];
    p[0] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[1] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[2] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.9",
                              41424, 80);
    p[3] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.9",
                              41424, 80);
    p[4] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.9",
                              41424, 80);
    p[5] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.11",
                              41424, 80);
    p[6] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.11",
                              41424, 80);

    const char *sigs[5];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing record 1\"; content:\"Hi all\"; record:host,\"aaa.pcap\",0,0,3,src; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"Hi all\"; record:host,\"aaa.pcap\",0,0,8,dst; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:3;)";
    sigs[3]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:5;)";

    uint32_t sid[5] = {1,2,3,4,5};
    int numsigs = 5;

    FAIL_IF(UTHAppendSigs(de_ctx, sigs, numsigs) == 0);

    //de_ctx->flags |= DE_QUIET;

    int32_t results[7][5] = {
                              {1, 1, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0}
                             };

    int num_packets = 7;
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int i = 0;
    for (; i < num_packets; i++) {
        SCLogDebug("packet %d", i);
        p[i]->ts = TimeGet();
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);
        FAIL_IF(UTHCheckPacketMatchResults(p[i], sid, (uint32_t *)&results[i][0], numsigs) == 0);

        TimeSetIncrementTime(2);
        SCLogDebug("packet %d flag %s", i, p[i]->flags & PKT_HAS_RECORD ? "true" : "false");

        /* see if the PKT_HAS_RECORD is set on the packet if needed */
        bool expect = (i == 0 || i == 1 || i == 4);
        FAIL_IF(((p[i]->flags & PKT_HAS_RECORD) ? true : false) != expect);
    }

    UTHFreePackets(p, 7);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    IPPairShutdown();
    FlowShutdown();
    RecordDestroyCtx();
    StorageCleanup();
    PASS;
}

/**
 * \test host record: bytes
 */
static int DetectRecordTestPacket03 (void)
{
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint8_t *buf2 = (uint8_t *)"lalala!";
    uint16_t buf_len = strlen((char *)buf);
    uint16_t buf_len2 = strlen((char *)buf2);

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    StorageInit();
    RecordInitCtx();
    StorageFinalize();
    HostInitConfig(1);
    FlowInitConfig(1);
    IPPairInitConfig(1);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    Packet *p[7];
    p[0] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[1] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[2] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.9",
                              41424, 80);
    p[3] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.9",
                              41424, 80);
    p[4] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.9",
                              41424, 80);
    p[5] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.11",
                              41424, 80);
    p[6] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.11",
                              41424, 80);

    const char *sigs[5];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing record 1\"; content:\"Hi all\"; record:host, \"aaa.pcap\" , 0 , 150, 0 , src; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"Hi all\"; record:host,\"aaa.pcap\",0,150,0, dst; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:3;)";
    sigs[3]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:5;)";

    uint32_t sid[5] = {1,2,3,4,5};
    int numsigs = 5;

    FAIL_IF(UTHAppendSigs(de_ctx, sigs, numsigs) == 0);

    int32_t results[7][5] = {
                              {1, 1, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0}
                             };

    int num_packets = 7;
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int i = 0;
    for (; i < num_packets; i++) {
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);

        FAIL_IF(UTHCheckPacketMatchResults(p[i], sid, (uint32_t *)&results[i][0], numsigs) == 0);

        SCLogDebug("packet %d flag %s", i, p[i]->flags & PKT_HAS_RECORD ? "true" : "false");

        /* see if the PKT_HAS_RECORD is set on the packet if needed */
        bool expect = (i == 0 || i == 1 || i == 2 || i == 4);
        FAIL_IF(((p[i]->flags & PKT_HAS_RECORD) ? true : false) != expect);
    }

    UTHFreePackets(p, 7);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    IPPairShutdown();
    FlowShutdown();
    RecordDestroyCtx();
    StorageCleanup();
    PASS;
}

/**
 * \test session record: packets
 */
static int DetectRecordTestPacket04 (void)
{
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint8_t *buf2 = (uint8_t *)"lalala!";
    uint16_t buf_len = strlen((char *)buf);
    uint16_t buf_len2 = strlen((char *)buf2);

    Flow *f = NULL;
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    StorageInit();
    RecordInitCtx();
    StorageFinalize();
    HostInitConfig(1);
    FlowInitConfig(1);
    IPPairInitConfig(1);

    f = FlowAlloc();
    FAIL_IF_NULL(f);
    FLOW_INITIALIZE(f);
    f->protoctx = (void *)&ssn;
    f->flags |= FLOW_IPV4;
    FAIL_IF(inet_pton(AF_INET, "192.168.1.5", f->src.addr_data32) != 1);
    FAIL_IF(inet_pton(AF_INET, "192.168.1.1", f->dst.addr_data32) != 1);

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Packet *p[7];
    p[0] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[1] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[2] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[3] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[4] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[5] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[6] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              80, 41424);

    const char *sigs[5];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing record 1\"; content:\"Hi all\"; record:session,\"aaa.pcap\",4,0,0; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"blahblah\"; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:3;)";
    sigs[3]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:5;)";

    uint32_t sid[5] = {1,2,3,4,5};
    int numsigs = 5;

    FAIL_IF(UTHAppendSigs(de_ctx, sigs, numsigs) == 0);

    int32_t results[7][5] = {
                              {1, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0}
                             };

    int num_packets = 7;
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int i = 0;
    for (; i < num_packets; i++) {
        p[i]->flow = f;
        p[i]->flow->protoctx = &ssn;
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);

        FAIL_IF(UTHCheckPacketMatchResults(p[i], sid, (uint32_t *)&results[i][0], numsigs) == 0);

        SCLogDebug("packet %d flag %s", i, p[i]->flags & PKT_HAS_RECORD ? "true" : "false");
        /* see if the PKT_HAS_RECORD is set on the packet if needed */
        bool expect = (i == 0 || i == 1 || i == 2 || i == 3);
        FAIL_IF(((p[i]->flags & PKT_HAS_RECORD) ? true : false) != expect);
    }

    UTHFreePackets(p, 7);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    /* clean up flow */
    uint8_t proto_map = FlowGetProtoMapping(f->proto);
    FlowClearMemory(f, proto_map);
    FLOW_DESTROY(f);
    FlowFree(f);

    IPPairShutdown();
    FlowShutdown();
    HostShutdown();
    RecordDestroyCtx();
    StorageCleanup();
    PASS;
}

/**
 * \test session record: seconds
 */
static int DetectRecordTestPacket05 (void)
{
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint8_t *buf2 = (uint8_t *)"lalala!";
    uint16_t buf_len = strlen((char *)buf);
    uint16_t buf_len2 = strlen((char *)buf2);

    Flow *f = NULL;
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    StorageInit();
    RecordInitCtx();
    StorageFinalize();
    HostInitConfig(1);
    FlowInitConfig(1);
    IPPairInitConfig(1);

    f = FlowAlloc();
    FAIL_IF_NULL(f);
    FLOW_INITIALIZE(f);
    f->protoctx = (void *)&ssn;
    f->flags |= FLOW_IPV4;
    FAIL_IF(inet_pton(AF_INET, "192.168.1.5", f->src.addr_data32) != 1);
    FAIL_IF(inet_pton(AF_INET, "192.168.1.1", f->dst.addr_data32) != 1);

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Packet *p[7];
    p[0] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[1] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[2] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[3] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[4] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[5] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[6] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              80, 41424);

    const char *sigs[5];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing record 1\"; content:\"Hi all\"; record:session,\"abc.pcap\",0,0,8; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"blahblah\"; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:3;)";
    sigs[3]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:5;)";

    uint32_t sid[5] = {1,2,3,4,5};
    int numsigs = 5;

    FAIL_IF(UTHAppendSigs(de_ctx, sigs, numsigs) == 0);

    int32_t results[7][5] = {
                              {1, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0}
                             };

    int num_packets = 7;
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int i = 0;
    for (; i < num_packets; i++) {
        p[i]->flow = f;
        p[i]->flow->protoctx = &ssn;

        SCLogDebug("packet %d", i);
        p[i]->ts = TimeGet();
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);

        FAIL_IF(UTHCheckPacketMatchResults(p[i], sid, (uint32_t *)&results[i][0], numsigs) == 0);

        TimeSetIncrementTime(2);

        SCLogDebug("packet %d flag %s", i, p[i]->flags & PKT_HAS_RECORD ? "true" : "false");
        /* see if the PKT_HAS_RECORD is set on the packet if needed */
        bool expect = (i == 0 || i == 1 || i == 2 || i == 3 || i == 4);
        FAIL_IF(((p[i]->flags & PKT_HAS_RECORD) ? true : false) != expect);
    }

    UTHFreePackets(p, 7);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    /* clean up flow */
    uint8_t proto_map = FlowGetProtoMapping(f->proto);
    FlowClearMemory(f, proto_map);
    FLOW_DESTROY(f);
    FlowFree(f);

    IPPairShutdown();
    FlowShutdown();
    HostShutdown();
    RecordDestroyCtx();
    StorageCleanup();
    PASS;
}

/**
 * \test session record: bytes
 */
static int DetectRecordTestPacket06 (void)
{
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint8_t *buf2 = (uint8_t *)"lalala!";
    uint16_t buf_len = strlen((char *)buf);
    uint16_t buf_len2 = strlen((char *)buf2);

    Flow *f = NULL;
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    StorageInit();
    RecordInitCtx();
    StorageFinalize();
    HostInitConfig(1);
    FlowInitConfig(1);
    IPPairInitConfig(1);

    f = FlowAlloc();
    FAIL_IF_NULL(f);
    FLOW_INITIALIZE(f);
    f->protoctx = (void *)&ssn;
    f->flags |= FLOW_IPV4;
    FAIL_IF(inet_pton(AF_INET, "192.168.1.5", f->src.addr_data32) != 1);
    FAIL_IF(inet_pton(AF_INET, "192.168.1.1", f->dst.addr_data32) != 1);

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Packet *p[7];
    p[0] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[1] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[2] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[3] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[4] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[5] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[6] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              80, 41424);

    const char *sigs[5];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing record 1\"; content:\"Hi all\"; record:session,\"abc.pcap\",0,150,0; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"blahblah\"; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:3;)";
    sigs[3]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:5;)";

    uint32_t sid[5] = {1,2,3,4,5};
    int numsigs = 5;

    FAIL_IF(UTHAppendSigs(de_ctx, sigs, numsigs) == 0);

    int32_t results[7][5] = {
                              {1, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0}
                             };

    int num_packets = 7;
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int i = 0;
    for (; i < num_packets; i++) {
        p[i]->flow = f;
        p[i]->flow->protoctx = &ssn;
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);

        FAIL_IF(UTHCheckPacketMatchResults(p[i], sid, (uint32_t *)&results[i][0], numsigs) == 0);

        SCLogDebug("packet %d flag %s", i, p[i]->flags & PKT_HAS_RECORD ? "true" : "false");

        /* see if the PKT_HAS_RECORD is set on the packet if needed */
        bool expect = (i == 0 || i == 1 || i == 2);
        FAIL_IF(((p[i]->flags & PKT_HAS_RECORD) ? true : false) != expect);
    }

    UTHFreePackets(p, 7);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    /* clean up flow */
    uint8_t proto_map = FlowGetProtoMapping(f->proto);
    FlowClearMemory(f, proto_map);
    FLOW_DESTROY(f);
    FlowFree(f);

    IPPairShutdown();
    FlowShutdown();
    HostShutdown();
    RecordDestroyCtx();
    StorageCleanup();
    PASS;
}

/**
 * \test session record: bytes, where a 2nd match makes us record more
 */
static int DetectRecordTestPacket07 (void)
{
    uint8_t *buf = (uint8_t *)"Hi all!";
    uint8_t *buf2 = (uint8_t *)"lalala!";
    uint16_t buf_len = strlen((char *)buf);
    uint16_t buf_len2 = strlen((char *)buf2);

    Flow *f = NULL;
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    StorageInit();
    RecordInitCtx();
    StorageFinalize();
    HostInitConfig(1);
    FlowInitConfig(1);
    IPPairInitConfig(1);

    f = FlowAlloc();
    FAIL_IF_NULL(f);
    FLOW_INITIALIZE(f);
    f->protoctx = (void *)&ssn;
    f->flags |= FLOW_IPV4;
    FAIL_IF(inet_pton(AF_INET, "192.168.1.5", f->src.addr_data32) != 1);
    FAIL_IF(inet_pton(AF_INET, "192.168.1.1", f->dst.addr_data32) != 1);

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Packet *p[7];
    p[0] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[1] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[2] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[3] = UTHBuildPacketReal(buf, buf_len, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              41424, 80);
    p[4] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[5] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.1", "192.168.1.5",
                              80, 41424);
    p[6] = UTHBuildPacketReal(buf2, buf_len2, IPPROTO_TCP,
                              "192.168.1.5", "192.168.1.1",
                              80, 41424);

    const char *sigs[5];
    sigs[0]= "alert tcp any any -> any any (msg:\"Testing record 1\"; content:\"Hi all\"; record:session,\"aaa.pcap\",0,150,0; sid:1;)";
    sigs[1]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"blahblah\"; sid:2;)";
    sigs[2]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:3;)";
    sigs[3]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:4;)";
    sigs[4]= "alert tcp any any -> any any (msg:\"Testing record 2\"; content:\"no match\"; sid:5;)";

    uint32_t sid[5] = {1,2,3,4,5};
    int numsigs = 5;

    FAIL_IF(UTHAppendSigs(de_ctx, sigs, numsigs) == 0);
    int32_t results[7][5] = {
                              {1, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {1, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0},
                              {0, 0, 0, 0, 0}
                             };

    int num_packets = 7;
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int i = 0;
    for (; i < num_packets; i++) {
        p[i]->flow = f;
        p[i]->flow->protoctx = &ssn;
        SigMatchSignatures(&th_v, de_ctx, det_ctx, p[i]);

        FAIL_IF(UTHCheckPacketMatchResults(p[i], sid, (uint32_t *)&results[i][0], numsigs) == 0);

        SCLogDebug("packet %d flag %s", i, p[i]->flags & PKT_HAS_RECORD ? "true" : "false");

        /* see if the PKT_HAS_RECORD is set on the packet if needed */
        bool expect = (i == 0 || i == 1 || i == 2 || i == 3 || i == 4 || i == 5);
        FAIL_IF(((p[i]->flags & PKT_HAS_RECORD) ? true : false) != expect);
    }

    UTHFreePackets(p, 7);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    /* clean up flow */
    uint8_t proto_map = FlowGetProtoMapping(f->proto);
    FlowClearMemory(f, proto_map);
    FLOW_DESTROY(f);
    FlowFree(f);

    IPPairShutdown();
    FlowShutdown();
    HostShutdown();
    RecordDestroyCtx();
    StorageCleanup();
    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectRecord
 */
void DetectEngineRecordRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectRecordTestPacket01", DetectRecordTestPacket01);
    UtRegisterTest("DetectRecordTestPacket02", DetectRecordTestPacket02);
    UtRegisterTest("DetectRecordTestPacket03", DetectRecordTestPacket03);
    UtRegisterTest("DetectRecordTestPacket04", DetectRecordTestPacket04);
    UtRegisterTest("DetectRecordTestPacket05", DetectRecordTestPacket05);
    UtRegisterTest("DetectRecordTestPacket06", DetectRecordTestPacket06);
    UtRegisterTest("DetectRecordTestPacket07", DetectRecordTestPacket07);
#endif /* UNITTESTS */
}
