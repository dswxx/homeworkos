/* =======================================================================
 *  recv_stack.c —— 自定义协议栈接收端
 *  环境: openEuler 24.03 / DPDK 23.11 / VMware e1000 (em) / vfio-pci
 *
 *  两核架构:
 *    收包核 (主 lcore)   : rx_burst -> 过滤(eth/ip/magic) -> mbuf 指针入 ring
 *    写盘核 (worker lcore): 从 ring 取 mbuf -> 状态机(START/DATA/END)
 *                          -> pwrite 落盘 -> END 时校验 -> free
 *
 *  编译:  make
 *  运行:  sudo ./recv_stack -l 0,1 -n 4 -a 0000:02:05.0
 *  退出:  Ctrl-C
 * ======================================================================= */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_ring.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_launch.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_random.h>

#include "cproto.h"

#define NUM_MBUFS   8191
#define MBUF_CACHE  250
#define BURST_SIZE  32
#define RING_SIZE   4096
#define NB_RXD      1024
#define NB_TXD      1024
#define NAK_MAX_SEQS 300    /* 每个 NAK 最多带这么多缺失 seq,留在 MTU 内;余量下轮再补 */

static volatile sig_atomic_t force_quit = 0;
static struct rte_ring    *rx_ring = NULL;
static struct rte_mempool *g_pool  = NULL;   /* 发 END_ACK 时从这里取 mbuf */
static uint16_t            g_port  = 0;
static struct rte_ether_addr g_mac;          /* 本端口 MAC,作回包源 MAC */

/* ---------------- CRC32 (与 zlib.crc32 完全一致) ---------------- */
static uint32_t crc_table[256];
static void crc32_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc_table[i] = c;
    }
}
/* running 初值 0xFFFFFFFF,全部喂完后再 ^ 0xFFFFFFFF 得最终值 */
static uint32_t crc32_update(uint32_t running, const uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; i++)
        running = crc_table[(running ^ buf[i]) & 0xff] ^ (running >> 8);
    return running;
}

/* 单调时钟,秒(浮点),用于计时统计 */
static double now_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* ---------------- 接收文件上下文(写盘核私有) ---------------- */
enum { ST_WAIT_START = 0, ST_RECEIVING = 1, ST_DONE = 2 };

struct file_ctx {
    int      state;
    int      fd;
    uint16_t file_id;
    uint64_t total_size;
    uint32_t total_chunks;
    uint32_t recv_count;     /* 已收到的不同块数 */
    uint64_t bytes_written;
    uint8_t *bitmap;         /* 每块 1 字节,标记是否已收到 */
    char     outname[300];
    struct rte_ether_addr peer_mac;  /* 对端 MAC(回包用) */
    uint32_t peer_ip;                /* 对端 IP,网络序 */
    uint64_t client_nonce;           /* 握手 nonce,用于识别重复 START */
    double   t_start;                /* 本次传输起始时刻(秒) */
    uint32_t data_pkts;              /* 收到的 DATA 包数(含重复/重传) */
    uint32_t dup_pkts;               /* 其中重复/重传的包数 */
    uint32_t nak_sent;               /* 发出的 NAK 次数 */
};
static struct file_ctx ctx;

/* ---------------- 报文解析:校验通过返回 cproto_hdr,否则 NULL ---------------- */
static struct cproto_hdr *
parse_cproto(struct rte_mbuf *m, uint8_t **payload_out)
{
    const uint32_t min = sizeof(struct rte_ether_hdr) +
                         sizeof(struct rte_ipv4_hdr) +
                         sizeof(struct cproto_hdr);
    if (rte_pktmbuf_pkt_len(m) < min)
        return NULL;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
        return NULL;

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)((char *)eth + sizeof(*eth));
    if (ip->next_proto_id != CPROTO_IP_PROTO)
        return NULL;

    uint8_t ihl = (ip->version_ihl & 0x0f) * 4;
    struct cproto_hdr *ch = (struct cproto_hdr *)((char *)ip + ihl);
    if (ch->magic != rte_cpu_to_be_16(CPROTO_MAGIC))
        return NULL;

    if (payload_out)
        *payload_out = (uint8_t *)ch + sizeof(*ch);
    return ch;
}

/* ---------------- 构造并发送 END_ACK(收→发) ---------------- */
static void send_end_ack(uint16_t file_id, uint8_t status, uint32_t recv_chunks,
                         const struct rte_ether_addr *peer_mac, uint32_t peer_ip)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(g_pool);
    if (!m) { printf("[警告] 无 mbuf,END_ACK 未发出\n"); return; }

    const uint16_t cplen = sizeof(struct cproto_end_ack);
    const uint16_t total = sizeof(struct rte_ether_hdr) +
                           sizeof(struct rte_ipv4_hdr) +
                           sizeof(struct cproto_hdr) + cplen;
    char *p = (char *)rte_pktmbuf_append(m, total);
    if (!p) { rte_pktmbuf_free(m); return; }

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
    rte_ether_addr_copy(peer_mac, &eth->dst_addr);
    rte_ether_addr_copy(&g_mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)((char *)eth + sizeof(*eth));
    memset(ip, 0, sizeof(*ip));
    ip->version_ihl  = 0x45;     /* v4, IHL=5 */
    ip->time_to_live = 64;
    ip->next_proto_id = CPROTO_IP_PROTO;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
                                        sizeof(struct cproto_hdr) + cplen);
    ip->src_addr = rte_cpu_to_be_32(0xC0A82889);  /* 192.168.40.137,装饰用 */
    ip->dst_addr = peer_ip;                        /* 已是网络序 */
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct cproto_hdr *ch = (struct cproto_hdr *)((char *)ip + sizeof(*ip));
    ch->magic       = rte_cpu_to_be_16(CPROTO_MAGIC);
    ch->type        = CPROTO_TYPE_END_ACK;
    ch->rsv         = 0;
    ch->seq         = 0;
    ch->payload_len = rte_cpu_to_be_16(cplen);
    ch->file_id     = rte_cpu_to_be_16(file_id);

    struct cproto_end_ack *ea = (struct cproto_end_ack *)((char *)ch + sizeof(*ch));
    ea->status      = status;
    ea->rsv         = 0;
    ea->recv_chunks = rte_cpu_to_be_32(recv_chunks);

    uint16_t sent = 0, tries = 0;
    while (sent == 0 && tries++ < 5)
        sent = rte_eth_tx_burst(g_port, 0, &m, 1);
    if (sent == 0) {
        rte_pktmbuf_free(m);
        printf("[警告] END_ACK 发送失败(TX 满)\n");
    } else {
        printf("[END_ACK] 已回送  status=%s  recv=%u\n",
               status == CPROTO_ST_PASS ? "PASS" : "FAIL", recv_chunks);
    }
}

/* ---------------- 构造并发送 START_ACK(收→发,握手) ---------------- */
static void send_start_ack(uint64_t nonce, uint16_t transfer_id,
                           const struct rte_ether_addr *peer_mac, uint32_t peer_ip)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(g_pool);
    if (!m) { printf("[警告] 无 mbuf,START_ACK 未发出\n"); return; }

    const uint16_t cplen = sizeof(struct cproto_start_ack);
    const uint16_t total = sizeof(struct rte_ether_hdr) +
                           sizeof(struct rte_ipv4_hdr) +
                           sizeof(struct cproto_hdr) + cplen;
    char *p = (char *)rte_pktmbuf_append(m, total);
    if (!p) { rte_pktmbuf_free(m); return; }

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
    rte_ether_addr_copy(peer_mac, &eth->dst_addr);
    rte_ether_addr_copy(&g_mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)((char *)eth + sizeof(*eth));
    memset(ip, 0, sizeof(*ip));
    ip->version_ihl  = 0x45;
    ip->time_to_live = 64;
    ip->next_proto_id = CPROTO_IP_PROTO;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
                                        sizeof(struct cproto_hdr) + cplen);
    ip->src_addr = rte_cpu_to_be_32(0xC0A82889);
    ip->dst_addr = peer_ip;
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct cproto_hdr *ch = (struct cproto_hdr *)((char *)ip + sizeof(*ip));
    ch->magic       = rte_cpu_to_be_16(CPROTO_MAGIC);
    ch->type        = CPROTO_TYPE_START_ACK;
    ch->rsv         = 0;
    ch->seq         = 0;
    ch->payload_len = rte_cpu_to_be_16(cplen);
    ch->file_id     = rte_cpu_to_be_16(transfer_id);

    struct cproto_start_ack *sa = (struct cproto_start_ack *)((char *)ch + sizeof(*ch));
    sa->client_nonce = rte_cpu_to_be_64(nonce);
    sa->transfer_id  = rte_cpu_to_be_16(transfer_id);
    sa->rsv          = 0;

    uint16_t sent = 0, tries = 0;
    while (sent == 0 && tries++ < 5)
        sent = rte_eth_tx_burst(g_port, 0, &m, 1);
    if (sent == 0) {
        rte_pktmbuf_free(m);
        printf("[警告] START_ACK 发送失败(TX 满)\n");
    }
}

/* ---------------- 构造并发送 NAK(收→发,携带缺失 seq 列表) ---------------- */
static void send_nak(uint16_t file_id, const uint8_t *bitmap, uint32_t total_chunks,
                     const struct rte_ether_addr *peer_mac, uint32_t peer_ip)
{
    /* 先收集缺失 seq(上限 NAK_MAX_SEQS) */
    uint32_t miss[NAK_MAX_SEQS];
    uint16_t cnt = 0;
    for (uint32_t i = 0; i < total_chunks && cnt < NAK_MAX_SEQS; i++)
        if (!bitmap[i]) miss[cnt++] = i;
    if (cnt == 0) return;

    struct rte_mbuf *m = rte_pktmbuf_alloc(g_pool);
    if (!m) { printf("[警告] 无 mbuf,NAK 未发出\n"); return; }

    const uint16_t cplen = sizeof(struct cproto_nak) + cnt * 4;
    const uint16_t total = sizeof(struct rte_ether_hdr) +
                           sizeof(struct rte_ipv4_hdr) +
                           sizeof(struct cproto_hdr) + cplen;
    char *p = (char *)rte_pktmbuf_append(m, total);
    if (!p) { rte_pktmbuf_free(m); return; }

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)p;
    rte_ether_addr_copy(peer_mac, &eth->dst_addr);
    rte_ether_addr_copy(&g_mac, &eth->src_addr);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)((char *)eth + sizeof(*eth));
    memset(ip, 0, sizeof(*ip));
    ip->version_ihl  = 0x45;
    ip->time_to_live = 64;
    ip->next_proto_id = CPROTO_IP_PROTO;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
                                        sizeof(struct cproto_hdr) + cplen);
    ip->src_addr = rte_cpu_to_be_32(0xC0A82889);
    ip->dst_addr = peer_ip;
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct cproto_hdr *ch = (struct cproto_hdr *)((char *)ip + sizeof(*ip));
    ch->magic       = rte_cpu_to_be_16(CPROTO_MAGIC);
    ch->type        = CPROTO_TYPE_NAK;
    ch->rsv         = 0;
    ch->seq         = 0;
    ch->payload_len = rte_cpu_to_be_16(cplen);
    ch->file_id     = rte_cpu_to_be_16(file_id);

    struct cproto_nak *nk = (struct cproto_nak *)((char *)ch + sizeof(*ch));
    nk->count = rte_cpu_to_be_16(cnt);
    uint32_t *seqs = (uint32_t *)((char *)nk + sizeof(*nk));
    for (uint16_t i = 0; i < cnt; i++)
        seqs[i] = rte_cpu_to_be_32(miss[i]);

    uint16_t sent = 0, tries = 0;
    while (sent == 0 && tries++ < 5)
        sent = rte_eth_tx_burst(g_port, 0, &m, 1);
    if (sent == 0) {
        rte_pktmbuf_free(m);
        printf("[警告] NAK 发送失败(TX 满)\n");
    } else {
        printf("[NAK] 已请求重传 %u 块%s\n", cnt,
               cnt == NAK_MAX_SEQS ? "(本轮上限,余量下轮再补)" : "");
    }
}

/* ---------------- 状态机:START(握手 + 分配 transfer_id) ---------------- */
static void handle_start(struct cproto_hdr *ch, uint8_t *payload, uint16_t plen,
                         struct rte_ether_hdr *eth, struct rte_ipv4_hdr *ip)
{
    (void)ch;
    if (plen < sizeof(struct cproto_start))
        return;

    struct cproto_start *st = (struct cproto_start *)payload;
    uint64_t nonce = rte_be_to_cpu_64(st->client_nonce);

    /* 同一 nonce 的重复 START(上次 START_ACK 丢了)→ 重发 START_ACK,不重建 */
    if (ctx.state == ST_RECEIVING && ctx.client_nonce == nonce) {
        rte_ether_addr_copy(&eth->src_addr, &ctx.peer_mac);
        ctx.peer_ip = ip->src_addr;
        send_start_ack(nonce, ctx.file_id, &ctx.peer_mac, ctx.peer_ip);
        return;
    }
    /* 其它情况下若有旧上下文,丢弃重建 */
    if (ctx.state != ST_WAIT_START) {
        if (ctx.state == ST_RECEIVING)
            printf("[警告] 上一个文件还没结束又收到新 START,丢弃旧上下文\n");
        if (ctx.fd >= 0) close(ctx.fd);
        free(ctx.bitmap);
        memset(&ctx, 0, sizeof(ctx));
        ctx.fd = -1;
    }

    ctx.client_nonce = nonce;
    ctx.total_size   = rte_be_to_cpu_64(st->total_size);
    ctx.total_chunks = rte_be_to_cpu_32(st->total_chunks);

    /* 接收端分配 transfer_id(随机非 0,填入后续包头 file_id) */
    uint16_t tid = (uint16_t)rte_rand();
    if (tid == 0) tid = 1;
    ctx.file_id = tid;

    uint16_t namelen = plen - sizeof(struct cproto_start);
    char fname[256];
    if (namelen >= sizeof(fname)) namelen = sizeof(fname) - 1;
    memcpy(fname, payload + sizeof(struct cproto_start), namelen);
    fname[namelen] = '\0';

    snprintf(ctx.outname, sizeof(ctx.outname), "recv_%s", fname);
    ctx.fd = open(ctx.outname, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (ctx.fd < 0) {
        printf("[错误] 创建文件 %s 失败: %s\n", ctx.outname, strerror(errno));
        return;
    }
    ctx.bitmap        = calloc(ctx.total_chunks ? ctx.total_chunks : 1, 1);
    ctx.recv_count    = 0;
    ctx.bytes_written = 0;
    ctx.state         = ST_RECEIVING;
    rte_ether_addr_copy(&eth->src_addr, &ctx.peer_mac);
    ctx.peer_ip = ip->src_addr;

    ctx.t_start   = now_sec();        /* 计时起点 */
    ctx.data_pkts = 0;
    ctx.dup_pkts  = 0;
    ctx.nak_sent  = 0;
    rte_eth_stats_reset(g_port);      /* 网卡计数清零,使本次统计为单次传输 */

    printf("[START] file=%s  size=%lu  chunks=%u  "
           "握手: nonce=0x%016lx → 分配 transfer_id=%u\n",
           ctx.outname, (unsigned long)ctx.total_size, ctx.total_chunks,
           (unsigned long)nonce, ctx.file_id);

    send_start_ack(nonce, ctx.file_id, &ctx.peer_mac, ctx.peer_ip);
}

/* ---------------- 状态机:DATA ---------------- */
static void handle_data(uint16_t fid, uint32_t seq, uint8_t *payload, uint16_t plen)
{
    if (ctx.state != ST_RECEIVING) return;
    if (fid != ctx.file_id)        return;   /* 不属于本次传输,丢弃 */
    if (seq >= ctx.total_chunks)   return;

    off_t off = (off_t)seq * CPROTO_CHUNK_SIZE;
    if (pwrite(ctx.fd, payload, plen, off) != plen) {
        printf("[错误] pwrite seq=%u 失败: %s\n", seq, strerror(errno));
        return;
    }
    ctx.data_pkts++;
    if (ctx.bitmap[seq] == 0) {       /* 幂等:重复块不重复计数 */
        ctx.bitmap[seq] = 1;
        ctx.recv_count++;
        ctx.bytes_written += plen;
    } else {
        ctx.dup_pkts++;               /* 重传/重复到达 */
    }
}

/* ---------------- 状态机:END(缺块→NAK;齐了→校验+END_ACK) ---------------- */
static void handle_end(uint16_t fid, uint8_t *payload, uint16_t plen)
{
    if (ctx.state == ST_DONE) {
        /* 重复 END(上一轮 END_ACK 丢了,发端重发)→ 再确认一次 */
        if (fid == ctx.file_id)
            send_end_ack(ctx.file_id, CPROTO_ST_PASS, ctx.recv_count,
                         &ctx.peer_mac, ctx.peer_ip);
        return;
    }
    if (ctx.state != ST_RECEIVING) return;
    if (fid != ctx.file_id) return;          /* 不属于本次传输,丢弃 */
    if (plen < sizeof(struct cproto_end)) return;

    uint32_t missing = ctx.total_chunks - ctx.recv_count;

    /* 还有缺块 → 发 NAK 请求重传,保持 RECEIVING(不关文件、不重置) */
    if (missing > 0) {
        printf("[END] 收到,但缺 %u/%u 块 → 发 NAK\n", missing, ctx.total_chunks);
        send_nak(ctx.file_id, ctx.bitmap, ctx.total_chunks,
                 &ctx.peer_mac, ctx.peer_ip);
        ctx.nak_sent++;
        return;
    }

    /* 全部到齐 → 收尾并校验 CRC */
    struct cproto_end *en = (struct cproto_end *)payload;
    uint32_t expect_crc = rte_be_to_cpu_32(en->crc32);

    ftruncate(ctx.fd, ctx.total_size);
    fsync(ctx.fd);
    uint32_t running = 0xFFFFFFFFu;
    uint8_t  buf[4096];
    off_t    off = 0;
    ssize_t  n;
    while ((n = pread(ctx.fd, buf, sizeof(buf), off)) > 0) {
        running = crc32_update(running, buf, (size_t)n);
        off += n;
    }
    uint32_t actual_crc = running ^ 0xFFFFFFFFu;

    printf("\n========== [END] 传输结束: %s ==========\n", ctx.outname);
    printf("  块  : 收到 %u / %u\n", ctx.recv_count, ctx.total_chunks);
    printf("  字节: 写入 %lu / 期望 %lu\n",
           (unsigned long)ctx.bytes_written, (unsigned long)ctx.total_size);
    printf("  CRC : 收到 0x%08x  实算 0x%08x\n", expect_crc, actual_crc);

    /* ---- 统计 ---- */
    double dur  = now_sec() - ctx.t_start;
    double mbps = dur > 0 ? (ctx.total_size / 1e6) / dur : 0.0;
    printf("  用时: %.3f s   吞吐(goodput): %.2f MB/s\n", dur, mbps);
    printf("  收 DATA 包: %u(其中重传/重复 %u)   发 NAK: %u 次\n",
           ctx.data_pkts, ctx.dup_pkts, ctx.nak_sent);
    struct rte_eth_stats es;
    if (rte_eth_stats_get(g_port, &es) == 0)
        printf("  网卡: ipackets=%lu imissed=%lu ierrors=%lu rx_nombuf=%lu opackets=%lu\n",
               (unsigned long)es.ipackets, (unsigned long)es.imissed,
               (unsigned long)es.ierrors, (unsigned long)es.rx_nombuf,
               (unsigned long)es.opackets);

    uint8_t status;
    if (actual_crc == expect_crc) {
        printf("  结果: ✓ PASS  文件完整\n");
        status = CPROTO_ST_PASS;
    } else {
        printf("  结果: ✗ FAIL  CRC 不符(数据损坏,NAK 无法定位,放弃)\n");
        status = CPROTO_ST_FAIL;
    }
    printf("===========================================\n\n");

    send_end_ack(ctx.file_id, status, ctx.recv_count, &ctx.peer_mac, ctx.peer_ip);

    close(ctx.fd);
    ctx.fd = -1;
    free(ctx.bitmap);
    ctx.bitmap = NULL;
    if (status == CPROTO_ST_PASS) {
        ctx.state = ST_DONE;      /* 保留 file_id/对端信息,应对重复 END */
    } else {
        memset(&ctx, 0, sizeof(ctx));
        ctx.fd = -1;
        ctx.state = ST_WAIT_START;
    }
}

/* ---------------- 写盘核主函数 (worker lcore) ---------------- */
static int writer_loop(__rte_unused void *arg)
{
    printf("[写盘核] 启动于 lcore %u\n", rte_lcore_id());
    ctx.fd    = -1;
    ctx.state = ST_WAIT_START;

    while (!force_quit || !rte_ring_empty(rx_ring)) {
        void *obj;
        if (rte_ring_dequeue(rx_ring, &obj) < 0) {
            rte_pause();
            continue;
        }
        struct rte_mbuf *m = (struct rte_mbuf *)obj;
        uint8_t *payload = NULL;
        struct cproto_hdr *ch = parse_cproto(m, &payload);
        if (ch) {
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
            struct rte_ipv4_hdr  *ip  =
                (struct rte_ipv4_hdr *)((char *)eth + sizeof(*eth));
            uint16_t plen = rte_be_to_cpu_16(ch->payload_len);
            uint32_t seq  = rte_be_to_cpu_32(ch->seq);
            uint16_t fid  = rte_be_to_cpu_16(ch->file_id);
            switch (ch->type) {
            case CPROTO_TYPE_START: handle_start(ch, payload, plen, eth, ip); break;
            case CPROTO_TYPE_DATA:  handle_data(fid, seq, payload, plen);      break;
            case CPROTO_TYPE_END:   handle_end(fid, payload, plen);            break;
            default: break;
            }
        }
        rte_pktmbuf_free(m);
    }
    if (ctx.fd >= 0) close(ctx.fd);
    printf("[写盘核] 退出\n");
    return 0;
}

/* ---------------- 收包核循环 (主 lcore) ---------------- */
static void rx_loop(void)
{
    printf("[收包核] 启动于 lcore %u,端口 %u 轮询中...\n",
           rte_lcore_id(), g_port);
    uint64_t dropped = 0;

    while (!force_quit) {
        struct rte_mbuf *bufs[BURST_SIZE];
        uint16_t nb = rte_eth_rx_burst(g_port, 0, bufs, BURST_SIZE);
        for (uint16_t i = 0; i < nb; i++) {
            struct rte_mbuf *m = bufs[i];
            if (parse_cproto(m, NULL) == NULL) {     /* 不是我们的包 */
                rte_pktmbuf_free(m);
                continue;
            }
            if (rte_ring_enqueue(rx_ring, m) < 0) {  /* ring 满 -> 丢 */
                rte_pktmbuf_free(m);
                dropped++;
            }
        }
    }
    if (dropped)
        printf("[收包核] ring 满丢弃 %lu 包(放慢发送端或增大 RING_SIZE)\n",
               (unsigned long)dropped);
}

/* ---------------- 端口初始化 ---------------- */
static int port_init(uint16_t port, struct rte_mempool *pool)
{
    struct rte_eth_conf port_conf;
    struct rte_eth_dev_info dev_info;
    uint16_t nb_rxd = NB_RXD, nb_txd = NB_TXD;

    memset(&port_conf, 0, sizeof(port_conf));
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;

    if (rte_eth_dev_info_get(port, &dev_info) != 0)            return -1;
    if (rte_eth_dev_configure(port, 1, 1, &port_conf) != 0)    return -1;
    if (rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd) != 0) return -1;

    if (rte_eth_rx_queue_setup(port, 0, nb_rxd,
            rte_eth_dev_socket_id(port), NULL, pool) < 0)      return -1;

    struct rte_eth_txconf txconf = dev_info.default_txconf;
    if (rte_eth_tx_queue_setup(port, 0, nb_txd,
            rte_eth_dev_socket_id(port), &txconf) < 0)         return -1;

    if (rte_eth_dev_start(port) < 0)                           return -1;
    rte_eth_promiscuous_enable(port);

    rte_eth_macaddr_get(port, &g_mac);
    printf("[端口 %u] 启动完成  MAC %02x:%02x:%02x:%02x:%02x:%02x  混杂模式已开\n",
           port, g_mac.addr_bytes[0], g_mac.addr_bytes[1], g_mac.addr_bytes[2],
           g_mac.addr_bytes[3], g_mac.addr_bytes[4], g_mac.addr_bytes[5]);
    return 0;
}

static void signal_handler(int sig)
{
    (void)sig;
    force_quit = 1;
}

int main(int argc, char **argv)
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "EAL 初始化失败\n");

    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    crc32_init();

    if (rte_eth_dev_count_avail() == 0)
        rte_exit(EXIT_FAILURE, "找不到可用的 DPDK 端口(重启后请先跑 setup_dpdk.sh)\n");
    RTE_ETH_FOREACH_DEV(g_port) break;      /* 取第一个可用端口 */

    if (rte_lcore_count() < 2)
        rte_exit(EXIT_FAILURE, "需要至少 2 个 lcore,请用 -l 0,1\n");

    g_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS, MBUF_CACHE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!g_pool) rte_exit(EXIT_FAILURE, "mbuf 池创建失败: %s\n",
                          rte_strerror(rte_errno));

    if (port_init(g_port, g_pool) != 0)
        rte_exit(EXIT_FAILURE, "端口初始化失败\n");

    rx_ring = rte_ring_create("RX2WR", RING_SIZE, rte_socket_id(),
                              RING_F_SP_ENQ | RING_F_SC_DEQ);
    if (!rx_ring) rte_exit(EXIT_FAILURE, "ring 创建失败: %s\n",
                           rte_strerror(rte_errno));

    unsigned wlcore = RTE_MAX_LCORE, lc;
    RTE_LCORE_FOREACH_WORKER(lc) { wlcore = lc; break; }
    rte_eal_remote_launch(writer_loop, NULL, wlcore);   /* 写盘核 */

    rx_loop();                    /* 收包核跑在主 lcore */

    rte_eal_mp_wait_lcore();      /* 等写盘核把 ring 排空收尾 */

    rte_eth_dev_stop(g_port);
    rte_eth_dev_close(g_port);
    rte_ring_free(rx_ring);
    rte_eal_cleanup();
    printf("已干净退出。\n");
    return 0;
}