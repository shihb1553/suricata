#ifndef __DETECT_ENGINE_RECORD_H__
#define __DETECT_ENGINE_RECORD_H__

#include "host.h"
#include "ippair.h"
#include "detect.h"
#include "detect-record.h"

#define RECORD_MAX_LAST_TIME_SEEN 600

int RecordFlowAdd(DetectRecordDataEntry *, Packet *);
int RecordIPPairAdd(DetectRecordDataEntry *, Packet *);
int RecordHostAdd(DetectRecordDataEntry *, Packet *);

void RecordHandlePacket(DetectEngineCtx *, DetectEngineThreadCtx *, Packet *);

void RecordInitCtx(void);
void RecordDestroyCtx(void);
void RecordRestartCtx(void);

int RecordHostTimeoutCheck(Host *, SCTime_t);
int RecordHostHasRecord(Host *host);

int RecordIPPairTimeoutCheck(IPPair *, SCTime_t);
int RecordIPPairHasRecord(IPPair *ipp);

void DetectEngineRecordRegisterTests(void);

#endif /* __DETECT_ENGINE_RECORD_H__ */
