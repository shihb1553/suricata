#ifndef __USOCKET_H__
#define __USOCKET_H__

#include "suricata-common.h"

typedef struct USocketData_ {
    struct in_addr addr;
    uint16_t port;
    uint16_t len;
    char *data;
} USocketData;

void USocketSpawnThreads(void);
void TmModuleUSocketRegister (void);

int USocketEnqueue(int id, USocketData *data);

#endif /* __USOCKET_H__ */
