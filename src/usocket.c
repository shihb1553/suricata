#include "suricata-common.h"
#include "threadvars.h"
#include "tm-threads.h"
#include "tm-modules.h"
#include "runmodes.h"
#include "util-affinity.h"
#include "util-debug.h"
#include "fifo.h"

#include "usocket.h"

// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include <unistd.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <arpa/inet.h>
// #include <fcntl.h>
// #include <errno.h>

#define USOCKET_MAX_QUEUE_SIZE      8192    // 队列最大长度


typedef struct USocketThreadData_ {
    int sockfd;
    uint32_t recv_failed;
    uint32_t send_failed;
    uint64_t send_success;
} USocketThreadData;

static int g_usocket_queue_cnt;
static struct fifo **g_usocket_queues;

void USocketSpawnThreads(void)
{
    ThreadVars *tv_sk = NULL;
    tv_sk = TmThreadCreateMgmtThreadByName(thread_name_usocket, "USocket", 0);
    if (tv_sk == NULL) {
        FatalError("ERROR: TmThreadsCreate failed\n");
    }
    if (TmThreadSpawn(tv_sk) != TM_ECODE_OK) {
        FatalError("ERROR: TmThreadSpawn failed\n");
    }
}

int USocketEnqueue(int id, USocketData *data)
{
    // Worker id 连续
    if (fifo_room(g_usocket_queues[id % g_usocket_queue_cnt]) < sizeof(USocketData)) {
        return 0;
    }
    return (int)fifo_put(g_usocket_queues[id % g_usocket_queue_cnt], data, sizeof(USocketData));
}

static int USocketSendData(ThreadVars *th_v, USocketThreadData *std, USocketData *data)
{
    struct sockaddr_in dest_addr;

    // 配置目标地址
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr = data->addr;
    dest_addr.sin_port = htons(data->port);

    // 发送数据
    ssize_t sent_bytes = sendto(std->sockfd, data->data, data->len, 0,
                                (const struct sockaddr*)&dest_addr,
                                sizeof(dest_addr));

    if (sent_bytes < 0) {
        StatsIncr(th_v, std->send_failed);
    } else {
        StatsIncr(th_v, std->send_success);
    }

    free(data->data);

    return 0;
}

static TmEcode USocketThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    USocketThreadData *std = SCCalloc(1, sizeof(USocketThreadData));
    if (std == NULL)
        return TM_ECODE_FAILED;

    *data = std;

    std->recv_failed = StatsRegisterCounter("usocket.recv_failed", t);
    std->send_failed = StatsRegisterCounter("usocket.send_failed", t);
    std->send_success = StatsRegisterCounter("usocket.send_success", t);

    g_usocket_queue_cnt = TmThreadsGetThreadNumByCPUAffinity(WORKER_CPU_SET);
    g_usocket_queues = SCCalloc(g_usocket_queue_cnt, sizeof(struct fifo *));
    for (int i = 0; i < g_usocket_queue_cnt; i++) {
        g_usocket_queues[i] = fifo_alloc(USOCKET_MAX_QUEUE_SIZE * sizeof(USocketData));
        if (g_usocket_queues[i] == NULL) {
            SCLogError("fifo_alloc failed");
            goto failed;
        }
    }

    // 创建 UDP 套接字
    if ((std->sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        SCLogError("socket creation failed");
        goto failed;
    }

    // 设置套接字为非阻塞模式
    int flags = fcntl(std->sockfd, F_GETFL, 0);
    if (flags == -1) {
        SCLogError("fcntl F_GETFL");
        goto failed;
    }

    if (fcntl(std->sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        SCLogError("fcntl F_SETFL");
        goto failed;
    }

    return TM_ECODE_OK;

failed:
    if (std->sockfd)
        close(std->sockfd);
    SCFree(std);
    return TM_ECODE_FAILED;
}

static TmEcode USocketThreadDeinit(ThreadVars *t, void *data)
{
    USocketThreadData *std = data;

    if (std) {
        if (g_usocket_queues) {
            for (int i = 0; i < g_usocket_queue_cnt; i++) {
                struct fifo *queue = g_usocket_queues[i];
                if (queue == NULL) {
                    continue;
                }

                USocketData msg;
                if (fifo_len(queue) < sizeof(msg)) {
                    continue;
                }

                if (fifo_get(queue, &msg, sizeof(msg)) != sizeof(msg)) {
                    StatsIncr(t, std->recv_failed);
                    continue;
                }
                USocketSendData(t, std, &msg);

                fifo_free(queue);
            }
            SCFree(g_usocket_queues);
        }
        if (std->sockfd)
            close(std->sockfd);

        SCFree(std);
    }
    return TM_ECODE_OK;
}

static TmEcode USocket(ThreadVars *th_v, void *thread_data)
{
    USocketThreadData *std = thread_data;
    struct timespec curtime = {0, 0};

    struct timeval tv;
    gettimeofday(&tv, NULL);
    TIMEVAL_TO_TIMESPEC(&tv, &curtime);

    TmThreadsSetFlag(th_v, THV_RUNNING);

    while (1) {
        if (TmThreadsCheckFlag(th_v, THV_PAUSE)) {
            TmThreadsSetFlag(th_v, THV_PAUSED);
            TmThreadTestThreadUnPaused(th_v);
            TmThreadsUnsetFlag(th_v, THV_PAUSED);
        }

        gettimeofday(&tv, NULL);
        TIMEVAL_TO_TIMESPEC(&tv, &curtime);

        int packet_count = 0;

        for (int i = 0; i < g_usocket_queue_cnt; i++) {
            struct fifo *queue = g_usocket_queues[i];
            if (queue == NULL) {
                continue;
            }

            USocketData msg;
            if (fifo_len(queue) < sizeof(msg)) {
                continue;
            }

            if (fifo_get(queue, &msg, sizeof(msg)) != sizeof(msg)) {
                StatsIncr(th_v, std->recv_failed);
                continue;
            }
            packet_count++;
            USocketSendData(th_v, std, &msg);
        }

        if (TmThreadsCheckFlag(th_v, THV_KILL)) {
            StatsSyncCounters(th_v);
            return TM_ECODE_OK;
        }

        if (packet_count == 0) {
            usleep(1000);
        }
    }
    return TM_ECODE_OK;
}

void TmModuleUSocketRegister (void)
{
    tmm_modules[TMM_USOCKET].name = "USocket";
    tmm_modules[TMM_USOCKET].ThreadInit = USocketThreadInit;
    tmm_modules[TMM_USOCKET].ThreadDeinit = USocketThreadDeinit;
    tmm_modules[TMM_USOCKET].Management = USocket;
    tmm_modules[TMM_USOCKET].cap_flags = 0;
    tmm_modules[TMM_USOCKET].flags = TM_FLAG_MANAGEMENT_TM;
}
