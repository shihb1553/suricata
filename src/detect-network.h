#ifndef __DETECT_NETWORK_H__
#define __DETECT_NETWORK_H__

#include "suricata-common.h"


typedef struct DetectNetworkData_ {
    Address network;
    Address mask;
} DetectNetworkData;

void DetectNetworkRegister(void);
int DetectNetworkBufferMatch(DetectEngineThreadCtx *det_ctx,
    const DetectNetworkData *sd,
    const uint8_t *data, const uint32_t data_len);
#endif /* __DETECT_NETWORK_H__ */
