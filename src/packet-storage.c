#include "suricata-common.h"
#include "packet-storage.h"
#include "util-unittest.h"

unsigned int PacketStorageSize(void)
{
    return StorageGetSize(STORAGE_PACKET);
}

/** \defgroup packetstorage Packet storage API
 *
 * The Packet storage API is a per-packet storage. It is a mean to extend
 * the Packet structure with arbitrary data.
 *
 * You have first to register the storage via PacketStorageRegister() during
 * the init of your module. Then you can attach data via PacketSetStorageById()
 * and access them via PacketGetStorageById().
 * @{
 */

/**
 * \brief Register a Packet storage
 *
 * \param name the name of the storage
 * \param size integer coding the size of the stored value (sizeof(void *) is best choice here)
 * \param Alloc allocation function for the storage (can be null)
 * \param Free free function for the new storage
 *
 * \retval The ID of the newly register storage that will be used to access data
 *
 * It has to be called once during the init of the sub system
 */

PacketStorageId PacketStorageRegister(const char *name, const unsigned int size,
        void *(*Alloc)(unsigned int), void (*Free)(void *))
{
    int id = StorageRegister(STORAGE_PACKET, name, size, Alloc, Free);
    PacketStorageId hsi = { .id = id };
    return hsi;
}

/**
 * \brief Store a pointer in a given Packet storage
 *
 * \param h a pointer to the Packet
 * \param id the id of the storage (return of PacketStorageRegister() call)
 * \param ptr pointer to the data to store
 */

int PacketSetStorageById(Packet *h, PacketStorageId id, void *ptr)
{
    return StorageSetById((Storage *)((void *)h + sizeof(Packet) + default_packet_size), STORAGE_PACKET, id.id, ptr);
}

/**
 * \brief Get a value from a given Packet storage
 *
 * \param h a pointer to the Packet
 * \param id the id of the storage (return of PacketStorageRegister() call)
 *
 */

void *PacketGetStorageById(Packet *h, PacketStorageId id)
{
    return StorageGetById((Storage *)((void *)h + sizeof(Packet) + default_packet_size), STORAGE_PACKET, id.id);
}

/**
 * @}
 */

/* Start of "private" function */

void *PacketAllocStorageById(Packet *h, PacketStorageId id)
{
    return StorageAllocByIdPrealloc((Storage *)((void *)h + sizeof(Packet) + default_packet_size), STORAGE_PACKET, id.id);
}

void PacketFreeStorageById(Packet *h, PacketStorageId id)
{
    StorageFreeById((Storage *)((void *)h + sizeof(Packet) + default_packet_size), STORAGE_PACKET, id.id);
}

void PacketFreeStorage(Packet *h)
{
    if (PacketStorageSize() > 0)
        StorageFreeAll((Storage *)((void *)h + sizeof(Packet) + default_packet_size), STORAGE_PACKET);
}


#ifdef UNITTESTS

static void *StorageTestAlloc(unsigned int size)
{
    void *x = SCMalloc(size);
    return x;
}
static void StorageTestFree(void *x)
{
    if (x)
        SCFree(x);
}

static int PacketStorageTest01(void)
{
    StorageInit();

    PacketStorageId id1 = PacketStorageRegister("test", 8, StorageTestAlloc, StorageTestFree);
    if (id1.id < 0)
        goto error;
    PacketStorageId id2 = PacketStorageRegister("variable", 24, StorageTestAlloc, StorageTestFree);
    if (id2.id < 0)
        goto error;
    PacketStorageId id3 =
            PacketStorageRegister("store", sizeof(void *), StorageTestAlloc, StorageTestFree);
    if (id3.id < 0)
        goto error;

    if (StorageFinalize() < 0)
        goto error;

    PacketInitConfig(1);

    Address a;
    memset(&a, 0x00, sizeof(a));
    a.addr_data32[0] = 0x01020304;
    a.family = AF_INET;
    Packet *h = PacketGetPacketFromHash(&a);
    if (h == NULL) {
        printf("failed to get packet: ");
        goto error;
    }

    void *ptr = PacketGetStorageById(h, id1);
    if (ptr != NULL) {
        goto error;
    }
    ptr = PacketGetStorageById(h, id2);
    if (ptr != NULL) {
        goto error;
    }
    ptr = PacketGetStorageById(h, id3);
    if (ptr != NULL) {
        goto error;
    }

    void *ptr1a = PacketAllocStorageById(h, id1);
    if (ptr1a == NULL) {
        goto error;
    }
    void *ptr2a = PacketAllocStorageById(h, id2);
    if (ptr2a == NULL) {
        goto error;
    }
    void *ptr3a = PacketAllocStorageById(h, id3);
    if (ptr3a == NULL) {
        goto error;
    }

    void *ptr1b = PacketGetStorageById(h, id1);
    if (ptr1a != ptr1b) {
        goto error;
    }
    void *ptr2b = PacketGetStorageById(h, id2);
    if (ptr2a != ptr2b) {
        goto error;
    }
    void *ptr3b = PacketGetStorageById(h, id3);
    if (ptr3a != ptr3b) {
        goto error;
    }

    PacketRelease(h);

    PacketShutdown();
    StorageCleanup();
    return 1;
error:
    PacketShutdown();
    StorageCleanup();
    return 0;
}

static int PacketStorageTest02(void)
{
    StorageInit();

    PacketStorageId id1 = PacketStorageRegister("test", sizeof(void *), NULL, StorageTestFree);
    if (id1.id < 0)
        goto error;

    if (StorageFinalize() < 0)
        goto error;

    PacketInitConfig(1);

    Address a;
    memset(&a, 0x00, sizeof(a));
    a.addr_data32[0] = 0x01020304;
    a.family = AF_INET;
    Packet *h = PacketGetPacketFromHash(&a);
    if (h == NULL) {
        printf("failed to get packet: ");
        goto error;
    }

    void *ptr = PacketGetStorageById(h, id1);
    if (ptr != NULL) {
        goto error;
    }

    void *ptr1a = SCMalloc(128);
    if (unlikely(ptr1a == NULL)) {
        goto error;
    }
    PacketSetStorageById(h, id1, ptr1a);

    void *ptr1b = PacketGetStorageById(h, id1);
    if (ptr1a != ptr1b) {
        goto error;
    }

    PacketRelease(h);

    PacketShutdown();
    StorageCleanup();
    return 1;
error:
    PacketShutdown();
    StorageCleanup();
    return 0;
}

static int PacketStorageTest03(void)
{
    StorageInit();

    PacketStorageId id1 = PacketStorageRegister("test1", sizeof(void *), NULL, StorageTestFree);
    if (id1.id < 0)
        goto error;
    PacketStorageId id2 = PacketStorageRegister("test2", sizeof(void *), NULL, StorageTestFree);
    if (id2.id < 0)
        goto error;
    PacketStorageId id3 = PacketStorageRegister("test3", 32, StorageTestAlloc, StorageTestFree);
    if (id3.id < 0)
        goto error;

    if (StorageFinalize() < 0)
        goto error;

    PacketInitConfig(1);

    Address a;
    memset(&a, 0x00, sizeof(a));
    a.addr_data32[0] = 0x01020304;
    a.family = AF_INET;
    Packet *h = PacketGetPacketFromHash(&a);
    if (h == NULL) {
        printf("failed to get packet: ");
        goto error;
    }

    void *ptr = PacketGetStorageById(h, id1);
    if (ptr != NULL) {
        goto error;
    }

    void *ptr1a = SCMalloc(128);
    if (unlikely(ptr1a == NULL)) {
        goto error;
    }
    PacketSetStorageById(h, id1, ptr1a);

    void *ptr2a = SCMalloc(256);
    if (unlikely(ptr2a == NULL)) {
        goto error;
    }
    PacketSetStorageById(h, id2, ptr2a);

    void *ptr3a = PacketAllocStorageById(h, id3);
    if (ptr3a == NULL) {
        goto error;
    }

    void *ptr1b = PacketGetStorageById(h, id1);
    if (ptr1a != ptr1b) {
        goto error;
    }
    void *ptr2b = PacketGetStorageById(h, id2);
    if (ptr2a != ptr2b) {
        goto error;
    }
    void *ptr3b = PacketGetStorageById(h, id3);
    if (ptr3a != ptr3b) {
        goto error;
    }

    PacketRelease(h);

    PacketShutdown();
    StorageCleanup();
    return 1;
error:
    PacketShutdown();
    StorageCleanup();
    return 0;
}
#endif

void RegisterPacketStorageTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("PacketStorageTest01", PacketStorageTest01);
    UtRegisterTest("PacketStorageTest02", PacketStorageTest02);
    UtRegisterTest("PacketStorageTest03", PacketStorageTest03);
#endif
}
