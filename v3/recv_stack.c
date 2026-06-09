/* =======================================================================
 *  recv_stack.c —— 自定义协议栈接收端 (v3: 并发多文件 / 多连接复用)
 *  环境: openEuler 24.03 / DPDK 23.11 / VMware e1000 (em) / vfio-pci
 *
 *  两核架构:
 *    收包核 (主 lcore)   : rx_burst -> 过滤(eth/ip/magic) -> mbuf 指针入 ring
 *    写盘核 (worker lcore): 从 ring 取 mbuf -> 按 connection_id 定位 ctx
 *                          -> 状态机(START/DATA/END) -> pwrite -> 校验 -> free
 *
 *  v3 要点:
 *    · 支持同时接收多个文件:每条传输一个 conn_ctx,按 connection_id 解复用
 *    · client_conn_id(客户端自选)用于握手配对与识别重复 START
 *    · DATA/END 校验来包对端地址(connection_id 标识 + 地址校验)
 *    · bitmap 真 1bit/块
 *  注意:多连接并发后,网卡统计无法按 ctx 归属,改为全局累计打印
 *
 *  编译:  make
 *  运行:  sudo ./recv_stack -l 0,1 -n 4 -d ...(见 Makefile run)
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

#define NUM_MBUFS    8191
#define MBUF_CACHE   250
#define BURST_SIZE   32
#define RING_SIZE    4096
#define NB_RXD       1024
#define NB_TXD       1024
#define NAK_MAX_CHUNKS 300  /* 每个 NAK 最多带这么多缺失 chunk,留在 MTU 内;余量下轮补 */
#define MAX_CONN     64     /* 同时支持的并发传输数 */

static volatile sig_atomic_t force_quit = 0;
static struct rte_ring    *rx_ring = NULL;
static struct rte_mempool *g_pool  = NULL;   /* 发回包时从这里取 mbuf */
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

/* ---------------- 位图(1 bit / 块) ---------------- */
#define BM_BYTES(n)  (((n) + 7) / 8)
#define BM_SET(bm,i) ((bm)[(i) >> 3] |=  (uint8_t)(1u << ((i) & 7)))
#define BM_GET(bm,i) (((bm)[(i) >> 3] >> ((i) & 7)) & 1u)

/* ---------------- 接收文件上下文表(写盘核私有,无需加锁) ---------------- */
enum { ST_FREE = 0, ST_RECEIVING = 1, ST_DONE = 2 };

struct conn_ctx {
    int      state;
    int      fd;
    uint16_t connection_id;   /* 服务端分配的连接 id(解复用键) */
    uint64_t client_conn_id;  /* 客户端自选 id,识别重复 START */
    uint64_t total_size;
    uint32_t total_chunks;
    uint32_t recv_count;
    uint64_t bytes_written;
    uint8_t *bitmap;          /* 1 bit/块 */
    char     outname[300];
    struct rte_ether_addr peer_mac;
    uint32_t peer_ip;
    double   t_start;
    uint32_t data_pkts;
    uint32_t dup_pkts;
    uint32_t nak_sent;
    uint64_t last_active;     /* 单调序,用于回收最老的 DONE */
};
static struct conn_ctx conns[MAX_CONN];
static uint64_t g_tick = 0;

/* ---- 上下文表查找(全在写盘核单线程内) ---- */
static struct conn_ctx *conn_by_cid(uint16_t cid)
{
    for (int i = 0; i < MAX_CONN; i++)
        if (conns[i].state != ST_FREE && conns[i].connection_id == cid)
            return &conns[i];
    return NULL;
}
static struct conn_ctx *conn_by_client(uint64_t client_cid)
{
    for (int i = 0; i < MAX_CONN; i++)
        if (conns[i].state != ST_FREE && conns[i].client_conn_id == client_cid)
            return &conns[i];
    return NULL;
}
static struct conn_ctx *conn_alloc(void)
{
    for (int i = 0; i < MAX_CONN; i++)
        if (conns[i].state == ST_FREE) return &conns[i];
    /* 没空槽 → 回收最老的 DONE(TIME_WAIT 式保留之后的复用) */
    struct conn_ctx *oldest = NULL;
    for (int i = 0; i < MAX_CONN; i++)
        if (conns[i].state == ST_DONE &&
            (!oldest || conns[i].last_active < oldest->last_active))
            oldest = &conns[i];
    if (oldest) {
        if (oldest->fd >= 0) close(oldest->fd);
        free(oldest->bitmap);
        memset(oldest, 0, sizeof(*oldest));
        oldest->fd = -1;
        return oldest;
    }
    return NULL;   /* 全在 RECEIVING,满了 */
}
static uint16_t gen_unique_cid(void)
{
    for (int tries = 0; tries < 1000; tries++) {
        uint16_t c = (uint16_t)rte_rand();
        if (c == 0) continue;
        if (!conn_by_cid(c)) return c;
    }
    return 0;
}

/* 地址校验:来包源 MAC/IP 是否与本 ctx 记录的对端一致 */
static int peer_ok(const struct conn_ctx *c,
                   const struct rte_ether_hdr *eth, const struct rte_ipv4_hdr *ip)
{
    return rte_is_same_ether_addr(&eth->src_addr, &c->peer_mac) &&
           ip->src_addr == c->peer_ip;
}

/* ---------------- 报文解析:校验通过返回 cproto_hdr,否则 NULL ---------------- */
static struct cproto_hdr *
parse_cproto(struct rte_mbuf *m, uint8_t **payload_out)
{
    const uint32_t pkt_len = rte_pktmbuf_pkt_len(m);
    const uint32_t eth_len = sizeof(struct rte_ether_hdr);

    if (pkt_len < eth_len + sizeof(struct rte_ipv4_hdr))
        return NULL;

    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    if (eth->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
        return NULL;

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)((char *)eth + sizeof(*eth));
    if ((ip->version_ihl >> 4) != 4)
        return NULL;
    if (ip->next_proto_id != CPROTO_IP_PROTO)
        return NULL;

    uint8_t ihl = (ip->version_ihl & 0x0f) * 4;
    if (ihl < sizeof(struct rte_ipv4_hdr))
        return NULL;
    if (pkt_len < eth_len + ihl + sizeof(struct cproto_hdr))
        return NULL;

    struct cproto_hdr *ch = (struct cproto_hdr *)((char *)ip + ihl);
    if (ch->magic != rte_cpu_to_be_16(CPROTO_MAGIC))
        return NULL;

    uint16_t plen = rte_be_to_cpu_16(ch->payload_len);
    uint32_t cproto_off = eth_len + ihl;
    if (pkt_len < cproto_off + sizeof(struct cproto_hdr) + plen)
        return NULL;

    if (payload_out)
        *payload_out = (uint8_t *)ch + sizeof(*ch);
    return ch;
}

/* ---------------- 构造并发送 END_ACK(收→发) ---------------- */
static void send_end_ack(uint16_t connection_id, uint8_t status, uint32_t recv_chunks,
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
    ip->version_ihl  = 0x45;
    ip->time_to_live = 64;
    ip->next_proto_id = CPROTO_IP_PROTO;
    ip->total_length = rte_cpu_to_be_16(sizeof(struct rte_ipv4_hdr) +
                                        sizeof(struct cproto_hdr) + cplen);
    ip->src_addr = rte_cpu_to_be_32(0xC0A82889);  /* 192.168.40.137,装饰用 */
    ip->dst_addr = peer_ip;
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    struct cproto_hdr *ch = (struct cproto_hdr *)((char *)ip + sizeof(*ip));
    ch->magic         = rte_cpu_to_be_16(CPROTO_MAGIC);
    ch->type          = CPROTO_TYPE_END_ACK;
    ch->rsv           = 0;
    ch->chunk_index   = 0;
    ch->payload_len   = rte_cpu_to_be_16(cplen);
    ch->connection_id = rte_cpu_to_be_16(connection_id);

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
        printf("[END_ACK][cid=%u] 已回送  status=%s  recv=%u\n",
               connection_id, status == CPROTO_ST_PASS ? "PASS" : "FAIL", recv_chunks);
    }
}

/* ---------------- 构造并发送 START_ACK(收→发,握手) ---------------- */
static void send_start_ack(uint64_t client_cid, uint16_t connection_id,
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
    ch->magic         = rte_cpu_to_be_16(CPROTO_MAGIC);
    ch->type          = CPROTO_TYPE_START_ACK;
    ch->rsv           = 0;
    ch->chunk_index   = 0;
    ch->payload_len   = rte_cpu_to_be_16(cplen);
    ch->connection_id = rte_cpu_to_be_16(connection_id);

    struct cproto_start_ack *sa = (struct cproto_start_ack *)((char *)ch + sizeof(*ch));
    sa->client_conn_id = rte_cpu_to_be_64(client_cid);
    sa->connection_id  = rte_cpu_to_be_16(connection_id);
    sa->rsv            = 0;

    uint16_t sent = 0, tries = 0;
    while (sent == 0 && tries++ < 5)
        sent = rte_eth_tx_burst(g_port, 0, &m, 1);
    if (sent == 0) {
        rte_pktmbuf_free(m);
        printf("[警告] START_ACK 发送失败(TX 满)\n");
    }
}

/* ---------------- 构造并发送 NAK(收→发,携带缺失 chunk 列表) ---------------- */
static void send_nak(uint16_t connection_id, const uint8_t *bitmap, uint32_t total_chunks,
                     const struct rte_ether_addr *peer_mac, uint32_t peer_ip)
{
    uint32_t miss[NAK_MAX_CHUNKS];
    uint16_t cnt = 0;
    for (uint32_t i = 0; i < total_chunks && cnt < NAK_MAX_CHUNKS; i++)
        if (!BM_GET(bitmap, i)) miss[cnt++] = i;
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
    ch->magic         = rte_cpu_to_be_16(CPROTO_MAGIC);
    ch->type          = CPROTO_TYPE_NAK;
    ch->rsv           = 0;
    ch->chunk_index   = 0;
    ch->payload_len   = rte_cpu_to_be_16(cplen);
    ch->connection_id = rte_cpu_to_be_16(connection_id);

    struct cproto_nak *nk = (struct cproto_nak *)((char *)ch + sizeof(*ch));
    nk->count = rte_cpu_to_be_16(cnt);
    uint32_t *chunks = (uint32_t *)((char *)nk + sizeof(*nk));
    for (uint16_t i = 0; i < cnt; i++)
        chunks[i] = rte_cpu_to_be_32(miss[i]);

    uint16_t sent = 0, tries = 0;
    while (sent == 0 && tries++ < 5)
        sent = rte_eth_tx_burst(g_port, 0, &m, 1);
    if (sent == 0) {
        rte_pktmbuf_free(m);
        printf("[警告] NAK 发送失败(TX 满)\n");
    } else {
        printf("[NAK][cid=%u] 已请求重传 %u 块%s\n", connection_id, cnt,
               cnt == NAK_MAX_CHUNKS ? "(本轮上限,余量下轮再补)" : "");
    }
}

/* ---------------- 状态机:START(握手 + 分配 connection_id) ---------------- */
static void handle_start(uint8_t *payload, uint16_t plen,
                         struct rte_ether_hdr *eth, struct rte_ipv4_hdr *ip)
{
    if (plen < sizeof(struct cproto_start))
        return;

    struct cproto_start *st = (struct cproto_start *)payload;
    uint64_t client_cid = rte_be_to_cpu_64(st->client_conn_id);

    /* 同一 client_conn_id 的重复 START(上次 START_ACK 丢了)→ 回同一个 cid,不重建 */
    struct conn_ctx *c = conn_by_client(client_cid);
    if (c) {
        rte_ether_addr_copy(&eth->src_addr, &c->peer_mac);
        c->peer_ip     = ip->src_addr;
        c->last_active = ++g_tick;
        send_start_ack(client_cid, c->connection_id, &c->peer_mac, c->peer_ip);
        return;
    }

    c = conn_alloc();
    if (!c) { printf("[警告] 连接槽已满(%d),拒绝新 START\n", MAX_CONN); return; }

    c->client_conn_id = client_cid;
    c->total_size     = rte_be_to_cpu_64(st->total_size);
    c->total_chunks   = rte_be_to_cpu_32(st->total_chunks);
    c->connection_id  = gen_unique_cid();
    uint32_t expect_chunks = (uint32_t)((c->total_size + CPROTO_CHUNK_SIZE - 1) /
                                        CPROTO_CHUNK_SIZE);
    if (c->total_size == 0 || c->total_chunks == 0 || c->total_chunks != expect_chunks) {
        printf("[警告] START 元信息非法: size=%lu chunks=%u expect=%u\n",
               (unsigned long)c->total_size, c->total_chunks, expect_chunks);
        memset(c, 0, sizeof(*c));
        c->fd = -1;
        c->state = ST_FREE;
        return;
    }
    if (c->connection_id == 0) {
        printf("[警告] connection_id 分配失败,拒绝新 START\n");
        memset(c, 0, sizeof(*c));
        c->fd = -1;
        c->state = ST_FREE;
        return;
    }

    uint16_t namelen = plen - sizeof(struct cproto_start);
    char fname[256];
    if (namelen >= sizeof(fname)) namelen = sizeof(fname) - 1;
    memcpy(fname, payload + sizeof(struct cproto_start), namelen);
    fname[namelen] = '\0';
    for (uint16_t i = 0; i < namelen; i++)
        if (fname[i] == '/' || fname[i] == '\\') fname[i] = '_';

    /* 输出名带 connection_id,避免并发同名文件互相覆盖 */
    snprintf(c->outname, sizeof(c->outname), "recv_%u_%s", c->connection_id, fname);
    c->fd = open(c->outname, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (c->fd < 0) {
        printf("[错误] 创建文件 %s 失败: %s\n", c->outname, strerror(errno));
        memset(c, 0, sizeof(*c));
        c->fd = -1;
        c->state = ST_FREE;
        return;
    }
    c->bitmap        = calloc(BM_BYTES(c->total_chunks ? c->total_chunks : 1), 1);
    if (!c->bitmap) {
        printf("[错误] bitmap 分配失败: chunks=%u\n", c->total_chunks);
        close(c->fd);
        memset(c, 0, sizeof(*c));
        c->fd = -1;
        c->state = ST_FREE;
        return;
    }
    c->recv_count    = 0;
    c->bytes_written = 0;
    c->state         = ST_RECEIVING;
    rte_ether_addr_copy(&eth->src_addr, &c->peer_mac);
    c->peer_ip     = ip->src_addr;
    c->t_start     = now_sec();
    c->data_pkts   = 0;
    c->dup_pkts    = 0;
    c->nak_sent    = 0;
    c->last_active = ++g_tick;

    printf("[START] file=%s  size=%lu  chunks=%u  "
           "client_cid=0x%016lx → 分配 connection_id=%u\n",
           c->outname, (unsigned long)c->total_size, c->total_chunks,
           (unsigned long)client_cid, c->connection_id);

    send_start_ack(client_cid, c->connection_id, &c->peer_mac, c->peer_ip);
}

/* ---------------- 状态机:DATA ---------------- */
static void handle_data(uint16_t cid, uint32_t idx, uint8_t *payload, uint16_t plen,
                        struct rte_ether_hdr *eth, struct rte_ipv4_hdr *ip)
{
    struct conn_ctx *c = conn_by_cid(cid);
    if (!c || c->state != ST_RECEIVING) return;
    if (!peer_ok(c, eth, ip))           return;   /* 地址校验 */
    if (idx >= c->total_chunks)         return;

    uint64_t file_off = (uint64_t)idx * CPROTO_CHUNK_SIZE;
    uint16_t expect_len = CPROTO_CHUNK_SIZE;
    if (idx == c->total_chunks - 1)
        expect_len = (uint16_t)(c->total_size - file_off);
    if (plen != expect_len) {
        printf("[警告][cid=%u] chunk=%u 长度异常: plen=%u expect=%u,丢弃\n",
               c->connection_id, idx, plen, expect_len);
        return;
    }

    if (BM_GET(c->bitmap, idx)) {        /* 幂等:重复块不重复写盘 */
        c->data_pkts++;
        c->dup_pkts++;
        c->last_active = ++g_tick;
        return;
    }

    off_t off = (off_t)idx * CPROTO_CHUNK_SIZE;
    if (pwrite(c->fd, payload, plen, off) != plen) {
        printf("[错误] pwrite chunk=%u 失败: %s\n", idx, strerror(errno));
        return;
    }
    c->data_pkts++;
    BM_SET(c->bitmap, idx);
    c->recv_count++;
    c->bytes_written += plen;
    c->last_active = ++g_tick;
}

/* ---------------- 状态机:END(缺块→NAK;齐了→校验+END_ACK) ---------------- */
static void handle_end(uint16_t cid, uint8_t *payload, uint16_t plen,
                       struct rte_ether_hdr *eth, struct rte_ipv4_hdr *ip)
{
    struct conn_ctx *c = conn_by_cid(cid);
    if (!c) return;                         /* 未知/已回收的连接 → 忽略 */
    if (!peer_ok(c, eth, ip)) return;

    if (c->state == ST_DONE) {              /* 重复 END → 再确认一次 */
        send_end_ack(c->connection_id, CPROTO_ST_PASS, c->recv_count,
                     &c->peer_mac, c->peer_ip);
        return;
    }
    if (c->state != ST_RECEIVING) return;
    if (plen < sizeof(struct cproto_end)) return;

    uint32_t missing = c->total_chunks - c->recv_count;

    if (missing > 0) {
        printf("[END][cid=%u] 收到,但缺 %u/%u 块 → 发 NAK\n",
               c->connection_id, missing, c->total_chunks);
        send_nak(c->connection_id, c->bitmap, c->total_chunks, &c->peer_mac, c->peer_ip);
        c->nak_sent++;
        c->last_active = ++g_tick;
        return;
    }

    struct cproto_end *en = (struct cproto_end *)payload;
    uint32_t expect_crc = rte_be_to_cpu_32(en->crc32);

    if (ftruncate(c->fd, c->total_size) != 0)
        printf("[警告] ftruncate 失败: %s\n", strerror(errno));
    if (fsync(c->fd) != 0)
        printf("[警告] fsync 失败: %s\n", strerror(errno));
    uint32_t running = 0xFFFFFFFFu;
    uint8_t  buf[4096];
    off_t    off = 0;
    ssize_t  n;
    while ((n = pread(c->fd, buf, sizeof(buf), off)) > 0) {
        running = crc32_update(running, buf, (size_t)n);
        off += n;
    }
    uint32_t actual_crc = running ^ 0xFFFFFFFFu;

    printf("\n========== [END] 传输结束: %s (cid=%u) ==========\n",
           c->outname, c->connection_id);
    printf("  块  : 收到 %u / %u\n", c->recv_count, c->total_chunks);
    printf("  字节: 写入 %lu / 期望 %lu\n",
           (unsigned long)c->bytes_written, (unsigned long)c->total_size);
    printf("  CRC : 收到 0x%08x  实算 0x%08x\n", expect_crc, actual_crc);

    double dur  = now_sec() - c->t_start;
    double mbps = dur > 0 ? (c->total_size / 1e6) / dur : 0.0;
    printf("  用时: %.3f s   吞吐(goodput): %.2f MB/s\n", dur, mbps);
    printf("  收 DATA 包: %u(其中重传/重复 %u)   发 NAK: %u 次\n",
           c->data_pkts, c->dup_pkts, c->nak_sent);
    struct rte_eth_stats es;
    if (rte_eth_stats_get(g_port, &es) == 0)
        printf("  网卡(全局累计): ipackets=%lu imissed=%lu ierrors=%lu rx_nombuf=%lu opackets=%lu\n",
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

    send_end_ack(c->connection_id, status, c->recv_count, &c->peer_mac, c->peer_ip);

    close(c->fd);
    c->fd = -1;
    free(c->bitmap);
    c->bitmap = NULL;
    c->last_active = ++g_tick;
    if (status == CPROTO_ST_PASS) {
        c->state = ST_DONE;     /* 保留 cid/对端,应对重复 END(TIME_WAIT 式) */
    } else {
        memset(c, 0, sizeof(*c));
        c->fd = -1;
        c->state = ST_FREE;
    }
}

/* ---------------- 写盘核主函数 (worker lcore) ---------------- */
static int writer_loop(__rte_unused void *arg)
{
    printf("[写盘核] 启动于 lcore %u\n", rte_lcore_id());
    for (int i = 0; i < MAX_CONN; i++) {
        conns[i].state = ST_FREE;
        conns[i].fd    = -1;
    }

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
            uint32_t idx  = rte_be_to_cpu_32(ch->chunk_index);
            uint16_t cid  = rte_be_to_cpu_16(ch->connection_id);
            switch (ch->type) {
            case CPROTO_TYPE_START: handle_start(payload, plen, eth, ip);         break;
            case CPROTO_TYPE_DATA:  handle_data(cid, idx, payload, plen, eth, ip); break;
            case CPROTO_TYPE_END:   handle_end(cid, payload, plen, eth, ip);       break;
            default: break;
            }
        }
        rte_pktmbuf_free(m);
    }
    for (int i = 0; i < MAX_CONN; i++)
        if (conns[i].fd >= 0) close(conns[i].fd);
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
