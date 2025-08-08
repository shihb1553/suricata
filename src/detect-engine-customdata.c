#include "suricata-common.h"
#include "detect-engine.h"
#include "detect-engine-customdata.h"


int CustomdataAdd(DetectEngineThreadCtx *det_ctx, const char *key, const char *val, uint16_t key_len, uint16_t val_len)
{
    DetectCustomdataList *customdata = SCCalloc(1, sizeof(*customdata));
    if (unlikely(customdata == NULL))
        return -1;

    customdata->key_len = key_len;
    customdata->value_len = val_len;
    customdata->key = (uint8_t *)strdup(key);
    customdata->value = (uint8_t *)strdup(val);

    customdata->next = det_ctx->customdatalist;
    det_ctx->customdatalist = customdata;
    return 0;
}
