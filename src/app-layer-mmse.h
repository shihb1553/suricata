#ifndef __APP_LAYER_MMSE_H__
#define __APP_LAYER_MMSE_H__

#include <htp/htp.h>

int HTPMMSFileClose(HtpState *s, const uint8_t *data, uint32_t data_len,
        uint8_t flags, uint8_t direction);

int HTPHandleMMSData(HtpState *hstate, HtpTxUserData *htud, uint8_t *data,
                     uint32_t data_len, uint8_t direction);


#endif	/* __APP_LAYER_MMSE_H__ */

