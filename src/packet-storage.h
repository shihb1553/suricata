#ifndef __PACKET_STORAGE_H__
#define __PACKET_STORAGE_H__

#include "decode.h"

typedef struct PacketStorageId_ {
    int id;
} PacketStorageId;

unsigned int PacketStorageSize(void);

void *PacketGetStorageById(Packet *h, PacketStorageId id);
int PacketSetStorageById(Packet *h, PacketStorageId id, void *ptr);
void *PacketAllocStorageById(Packet *h, PacketStorageId id);

void PacketFreeStorageById(Packet *h, PacketStorageId id);
void PacketFreeStorage(Packet *h);

void RegisterPacketStorageTests(void);

PacketStorageId PacketStorageRegister(const char *name, const unsigned int size,
        void *(*Alloc)(unsigned int), void (*Free)(void *));

#endif /* __PACKET_STORAGE_H__ */
