#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-record.h"
#include "detect-engine-record.h"
#include "detect-engine.h"
#include "detect-engine-state.h"
#include "app-layer-parser.h"

#include "decode.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"
#include "stream-tcp-private.h"

#include "util-time.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"
#include "threads.h"

SC_ATOMIC_EXTERN(unsigned int, num_records);

/* format: record: <type>, <file>, <packets>, <bytes>, <seconds>, [direction]; */
#define PARSE_REGEX  "^\\s*(host|ippairs|session)\\s*,\\s*(\".*\")\\s*,\\s*(\\d*)\\s*,\\s*(\\d*)\\s*,\\s*(\\d*)\\s*(,\\s*(src|dst))?\\s*$"
static DetectParseRegex parse_regex;

static int DetectRecordMatch(DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectRecordSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectRecordRegisterTests(void);
#endif
void DetectRecordDataFree(DetectEngineCtx *, void *);

/**
 * \brief Registration function for keyword record
 */
void DetectRecordRegister(void)
{
    sigmatch_table[DETECT_RECORD].name = "record";
    sigmatch_table[DETECT_RECORD].Match = DetectRecordMatch;
    sigmatch_table[DETECT_RECORD].Setup = DetectRecordSetup;
    sigmatch_table[DETECT_RECORD].Free  = DetectRecordDataFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_RECORD].RegisterTests = DetectRecordRegisterTests;
#endif
    sigmatch_table[DETECT_RECORD].flags |= SIGMATCH_IPONLY_COMPAT;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief This function is used to setup a record for session/host
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectRecordData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectRecordMatch(DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    const DetectRecordData *rd = (const DetectRecordData *)ctx;
    DetectRecordDataEntry rde;
    memset(&rde, 0, sizeof(DetectRecordDataEntry));

    rde.sid = s->id;
    rde.gid = s->gid;
    rde.last_ts = rde.first_ts = SCTIME_SECS(p->ts);
    rde.packet_limit = rd->packets;
    rde.byte_limit = rd->bytes;
    rde.time_limit = rd->seconds;
    rde.file = strdup(rd->file);

    switch (rd->type) {
        case DETECT_RECORD_TYPE_SESSION:
            if (p->flow != NULL) {
                RecordFlowAdd(&rde, p);
            } else {
                SCLogDebug("No flow to append the session record");
            }
            break;
        case DETECT_RECORD_TYPE_IPPAIRS:
            RecordIPPairAdd(&rde, p);
            break;
        case DETECT_RECORD_TYPE_HOST:
#ifdef DEBUG
            BUG_ON(!(rd->direction == DETECT_RECORD_DIR_SRC || rd->direction == DETECT_RECORD_DIR_DST));
#endif
            if (rd->direction == DETECT_RECORD_DIR_SRC)
                rde.flags |= RECORD_ENTRY_FLAG_DIR_SRC;
            else if (rd->direction == DETECT_RECORD_DIR_DST)
                rde.flags |= RECORD_ENTRY_FLAG_DIR_DST;

            RecordHostAdd(&rde, p);
            break;
#ifdef DEBUG
        default:
            SCLogDebug("unknown type of a record keyword (not session nor host)");
            BUG_ON(1);
            break;
#endif
    }

    return 1;
}

/**
 * \brief This function is used to parse record options passed to record keyword
 *
 * \param recordstr Pointer to the user provided record options
 *
 * \retval rd pointer to DetectRecordData on success
 * \retval NULL on failure
 */
static DetectRecordData *DetectRecordParse(const char *recordstr)
{
    DetectRecordData rd = {0};
    size_t pcre2_len;
    const char *str_ptr = NULL;

    pcre2_match_data *match = NULL;
    int ret = DetectParsePcreExec(&parse_regex, &match, recordstr, 0, 0);
    if (ret < 5) {
        SCLogError("parse error, ret %" PRId32 ", string %s", ret, recordstr);
        goto error;
    }

    int res = pcre2_substring_get_bynumber(match, 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0 || str_ptr == NULL) {
        SCLogError("pcre2_substring_get_bynumber 1 failed");
        goto error;
    }
    /* Type */
    if (strcasecmp("session", str_ptr) == 0) {
        rd.type = DETECT_RECORD_TYPE_SESSION;
    } else if (strcasecmp("ippairs", str_ptr) == 0) {
        rd.type = DETECT_RECORD_TYPE_IPPAIRS;
    } else if (strcasecmp("host", str_ptr) == 0) {
        rd.type = DETECT_RECORD_TYPE_HOST;
    } else {
        SCLogError("Invalid argument type. Must be session or host (%s)", recordstr);
        goto error;
    }
    pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
    str_ptr = NULL;

    res = pcre2_substring_get_bynumber(match, 2, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0 || str_ptr == NULL) {
        SCLogError("pcre2_substring_get_bynumber 2 failed");
        goto error;
    }
    rd.file = strdup(str_ptr);
    pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
    str_ptr = NULL;

    res = pcre2_substring_get_bynumber(match, 3, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0 || str_ptr == NULL) {
        SCLogError("pcre2_substring_get_bynumber 3 failed");
        goto error;
    }
    /* packets */
    if (StringParseUint32(&rd.packets, 10, strlen(str_ptr),
                str_ptr) <= 0) {
        SCLogError("Invalid argument for packets. Must be a value in the range of 0 to %" PRIu32
                    " (%s)",
                UINT32_MAX, recordstr);
        goto error;
    }
    pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
    str_ptr = NULL;

    res = pcre2_substring_get_bynumber(match, 4, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0 || str_ptr == NULL) {
        SCLogError("pcre2_substring_get_bynumber 4 failed");
        goto error;
    }
    /* bytes */
    if (StringParseUint32(&rd.bytes, 10, strlen(str_ptr),
                str_ptr) <= 0) {
        SCLogError("Invalid argument for bytes. Must be a value in the range of 0 to %" PRIu32
                    " (%s)",
                UINT32_MAX, recordstr);
        goto error;
    }
    pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
    str_ptr = NULL;

    res = pcre2_substring_get_bynumber(match, 5, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0 || str_ptr == NULL) {
        SCLogError("pcre2_substring_get_bynumber 5 failed");
        goto error;
    }
    /* seconds */
    if (StringParseUint32(&rd.seconds, 10, strlen(str_ptr),
                str_ptr) <= 0) {
        SCLogError("Invalid argument for seconds. Must be a value in the range of 0 to %" PRIu32
                    " (%s)",
                UINT32_MAX, recordstr);
        goto error;
    }
    pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
    str_ptr = NULL;

    rd.direction = DETECT_RECORD_DIR_DST;

    if (ret == 8) {
        res = pcre2_substring_get_bynumber(match, 7, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0 || str_ptr == NULL) {
            SCLogError("pcre2_substring_get_bynumber 7 failed");
            goto error;
        }
        if (strcasecmp("src", str_ptr) == 0) {
            rd.direction = DETECT_RECORD_DIR_SRC;
        } else if (strcasecmp("dst", str_ptr) == 0) {
            rd.direction = DETECT_RECORD_DIR_DST;
        } else {
            SCLogError(
                    "Invalid argument direction. Must be one of \"src\" or \"dst\" (only valid "
                    "for record host type, not sessions) (%s)",
                    recordstr);
            goto error;
        }
        if (rd.type != DETECT_RECORD_TYPE_HOST) {
            SCLogWarning(
                    "Argument direction only make sense for type \"host\" (%s [%" PRIu8
                    "])",
                    recordstr, rd.type);
        }
        pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
        str_ptr = NULL;
    }
    SCLogDebug("Record: %d %s %u %u %u %u %d", rd.type, rd.file, rd.packets, rd.bytes, rd.seconds, rd.direction, ret);

    DetectRecordData *real_rd = SCMalloc(sizeof(DetectRecordData));
    if (unlikely(real_rd == NULL)) {
        SCLogError("Error allocating memory");
        goto error;
    }

    memcpy(real_rd, &rd, sizeof(DetectRecordData));
    pcre2_match_data_free(match);
    return real_rd;

error:
    if (match) {
        pcre2_match_data_free(match);
    }
    if (str_ptr != NULL)
        pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
    return NULL;
}

/**
 * \brief this function is used to add the parsed record data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param recordstr pointer to the user provided record options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
int DetectRecordSetup(DetectEngineCtx *de_ctx, Signature *s, const char *recordstr)
{
    DetectRecordData *rd = DetectRecordParse(recordstr);
    if (rd == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectRecordDataFree(de_ctx, rd);
        return -1;
    }

    sm->type = DETECT_RECORD;
    sm->ctx = (SigMatchCtx *)rd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_TMATCH);
    return 0;
}

/** \internal
 *  \brief this function will free memory associated with
 *        DetectRecordDataEntry
 *
 *  \param rd pointer to DetectRecordDataEntry
 */
static void DetectRecordDataEntryFree(void *ptr)
{
    if (ptr != NULL) {
        DetectRecordDataEntry *dte = (DetectRecordDataEntry *)ptr;
        if (dte->file) {
            SCFree(dte->file);
        }
        SCFree(dte);
    }
}


/**
 * \brief this function will free all the entries of a list
 *        DetectRecordDataEntry
 *
 * \param rd pointer to DetectRecordDataEntryList
 */
void DetectRecordDataListFree(void *ptr)
{
    if (ptr != NULL) {
        DetectRecordDataEntry *entry = ptr;

        while (entry != NULL) {
            DetectRecordDataEntry *next_entry = entry->next;
            DetectRecordDataEntryFree(entry);
            (void) SC_ATOMIC_SUB(num_records, 1);
            entry = next_entry;
        }
    }
}

/**
 * \brief this function will free memory associated with DetectRecordData
 *
 * \param rd pointer to DetectRecordData
 */
void DetectRecordDataFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectRecordData *rd = (DetectRecordData *)ptr;
    if (rd->file) {
        SCFree(rd->file);
    }
    SCFree(rd);
}

#ifdef UNITTESTS

/**
 * \test DetectRecordTestParse01 is a test to make sure that we return "something"
 *  when given valid record opt
 */
static int DetectRecordTestParse01(void)
{
    int result = 0;
    DetectRecordData *rd = NULL;
    rd = DetectRecordParse("session, \"a.pcap\", 123, 456, 789");
    if (rd != NULL && rd->type == DETECT_RECORD_TYPE_SESSION
        && strcmp(rd->file, "\"a.pcap\"") == 0
        && rd->packets == 123
        && rd->bytes == 456
        && rd->seconds == 789) {
        DetectRecordDataFree(NULL, rd);
        result = 1;
    }

    return result;
}

/**
 * \test DetectRecordTestParse02 is a test to check that we parse record correctly
 */
static int DetectRecordTestParse02(void)
{
    int result = 0;
    DetectRecordData *rd = NULL;
    rd = DetectRecordParse("host, \"a.pcap\", 200, 300, 400, src");
    if (rd != NULL && rd->type == DETECT_RECORD_TYPE_HOST
        && strcmp(rd->file, "\"a.pcap\"") == 0
        && rd->packets == 200
        && rd->bytes == 300
        && rd->seconds == 400
        && rd->direction == DETECT_RECORD_DIR_SRC) {
            result = 1;
            DetectRecordDataFree(NULL, rd);
    }

    return result;
}

/**
 * \brief this function registers unit tests for DetectRecord
 */
void DetectRecordRegisterTests(void)
{
    UtRegisterTest("DetectRecordTestParse01", DetectRecordTestParse01);
    UtRegisterTest("DetectRecordTestParse02", DetectRecordTestParse02);
    DetectEngineRecordRegisterTests();
}
#endif /* UNITTESTS */
