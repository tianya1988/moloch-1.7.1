/******************************************************************************/
/* reader-libpcap.c  -- Reader using libpcap
 *
 * Copyright 2012-2017 AOL Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this Software except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define _FILE_OFFSET_BITS 64
#include "moloch.h"
#include <errno.h>
#include <sys/stat.h>
#include <gio/gio.h>
#include "pcap.h"

extern MolochConfig_t        config;

LOCAL  pcap_t               *pcaps[MAX_INTERFACES];

/******************************************************************************/
int reader_libpcap_stats(MolochReaderStats_t *stats)
{
    stats->dropped = 0;
    stats->total = 0;

    int i;
    for (i = 0; i < MAX_INTERFACES && config.interface[i]; i++) {
        struct pcap_stat ps;
        if (unlikely(!pcaps[i]))
            continue;
        int rc = pcap_stats (pcaps[i], &ps);
        if (unlikely(rc))
            continue;
        stats->dropped += ps.ps_drop;
        stats->total += ps.ps_recv;
    }
    return 0;
}
/******************************************************************************/
/**
 * 参数意义
 * batch 是pcap_dispatch()的最后一个参数，当收到足够数量的包后pcap_dispatch会调用callback回调函数，同时将pcap_dispatch()的最后一个参数传递给它
 * h  是收到数据包的对应的pcap_pkthdr类型的指针
 * bytes  收到的数据包数据
 * */
void reader_libpcap_pcap_cb(u_char *batch, const struct pcap_pkthdr *h, const u_char *bytes)
{
    if (unlikely(h->caplen != h->len)) {
        LOGEXIT("ERROR - Moloch requires full packet captures caplen: %d pktlen: %d\n"
            "See https://github.com/aol/moloch/wiki/FAQ#Moloch_requires_full_packet_captures_error",
            h->caplen, h->len);
    }


    // 接下来的几行是声明了一个结构体MolochPacket_t  并对其分配内存，和初始化其属性值
    MolochPacket_t *packet = MOLOCH_TYPE_ALLOC0(MolochPacket_t);

    packet->pkt           = (u_char *)bytes;//bytes本就是指针，(u_char *)是将此指针的地址取出，然后变为u_char类型，最后赋值给pkt指针
    packet->ts            = h->ts;
    packet->pktlen        = h->len;
    packet->readerPos     = ((MolochPacketBatch_t *)batch)->readerPos;

    moloch_packet_batch((MolochPacketBatch_t *)batch, packet);
}
/******************************************************************************/
LOCAL void *reader_libpcap_thread(gpointer posv)
{
    long    pos = (long)posv;
    pcap_t *pcap = pcaps[pos];
    if (config.debug)
        LOG("THREAD %p", (gpointer)pthread_self());

    MolochPacketBatch_t   batch;
    moloch_packet_batch_init(&batch);
    batch.readerPos = pos;
    while (1) {
        // 功能：循环捕获网络数据包，直到遇到错误或者满足退出条件，每次捕获一个数据包就会调用callback指定的回调函数，所以，可以在回调函数中进行数据包的处理操作。
        // 这个函数和pcap_loop()非常类似，只是在超过to_ms毫秒后就会返回（to_ms是pcap_open_live()的第四个参数）
        int r = pcap_dispatch(pcap, 10000, reader_libpcap_pcap_cb, (u_char*)&batch);


        moloch_packet_batch_flush(&batch);

        // Some kind of failure we quit
        if (unlikely(r < 0)) {
            moloch_quit();
            pcap = 0;
            break;
        }
    }
    //ALW - Need to close after packet finishes
    //pcap_close(pcap);
    return NULL;
}
/******************************************************************************/
void reader_libpcap_start() {
    int dlt_to_linktype(int dlt);

    //ALW - Bug: assumes all linktypes are the same
    moloch_packet_set_linksnap(dlt_to_linktype(pcap_datalink(pcaps[0])) | pcap_datalink_ext(pcaps[0]), pcap_snapshot(pcaps[0]));

    int i;
    for (i = 0; i < MAX_INTERFACES && config.interface[i]; i++) {
        if (config.bpf) {
            struct bpf_program   bpf;

            if (pcap_compile(pcaps[i], &bpf, config.bpf, 1, PCAP_NETMASK_UNKNOWN) == -1) {
                LOGEXIT("ERROR - Couldn't compile filter: '%s' with %s", config.bpf, pcap_geterr(pcaps[i]));
            }

            if (pcap_setfilter(pcaps[i], &bpf) == -1) {
                LOGEXIT("ERROR - Couldn't set filter: '%s' with %s", config.bpf, pcap_geterr(pcaps[i]));
            }
            pcap_freecode(&bpf);
        }

        char name[100];
        snprintf(name, sizeof(name), "moloch-pcap%d", i);

        //每块网卡对应一个读取数据的线程
        g_thread_new(name, &reader_libpcap_thread, (gpointer)(long)i);
    }
}
/******************************************************************************/
void reader_libpcap_stop()
{
    int i;
    for (i = 0; i < MAX_INTERFACES && config.interface[i]; i++) {
        if (pcaps[i])
            pcap_breakloop(pcaps[i]);
    }
}
/******************************************************************************/
pcap_t *
reader_libpcap_open_live(const char *source, int snaplen, int promisc, int to_ms, char *errbuf)
{
    pcap_t *p;
    int status;

    p = pcap_create(source, errbuf);
    if (p == NULL)
        return (NULL);
    status = pcap_set_snaplen(p, snaplen);
    if (status < 0)
        goto fail;
    status = pcap_set_promisc(p, promisc);
    if (status < 0)
        goto fail;
    status = pcap_set_timeout(p, to_ms);
    if (status < 0)
        goto fail;
    status = pcap_set_buffer_size(p, config.pcapBufferSize);
    if (status < 0)
        goto fail;
    status = pcap_activate(p);
    if (status < 0)
        goto fail;
    status = pcap_setnonblock(p, TRUE, errbuf);
    if (status < 0) {
        pcap_close(p);
        return (NULL);
    }

    return (p);
fail:
    if (status == PCAP_ERROR)
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s", source,
            pcap_geterr(p));
    else if (status == PCAP_ERROR_NO_SUCH_DEVICE ||
        status == PCAP_ERROR_PERM_DENIED)
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s (%s)", source,
            pcap_statustostr(status), pcap_geterr(p));
    else
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s", source,
            pcap_statustostr(status));
    pcap_close(p);
    return (NULL);
}
/******************************************************************************/
void reader_libpcap_init(char *UNUSED(name))
{
    char errbuf[1024];

    int i;

    for (i = 0; i < MAX_INTERFACES && config.interface[i]; i++) {

#ifdef SNF
        pcaps[i] = pcap_open_live(config.interface[i], config.snapLen, 1, 1000, errbuf);
#else
        // 功能：打开所有用于捕获数据的网络端口，一个网卡对应一个元素
        // 返回pcap_t类型指针，后面的所有操作都要使用这个指针
        pcaps[i] = reader_libpcap_open_live(config.interface[i], config.snapLen, 1, 1000, errbuf);
#endif

        if (!pcaps[i]) {
            LOGEXIT("pcap open live failed! %s", errbuf);
        }

        pcap_setnonblock(pcaps[i], FALSE, errbuf);
    }

    if (i == MAX_INTERFACES) {
        LOGEXIT("Only support up to %d interfaces", MAX_INTERFACES);
    }

    moloch_reader_start         = reader_libpcap_start;
    moloch_reader_stop          = reader_libpcap_stop;
    moloch_reader_stats         = reader_libpcap_stats;
}
