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
 *  运行:  sudo ./recv_stack -l 0,1 -n 4 --iova-mode=pa \
 *             -d /usr/lib64/librte_mempool_ring.so \
 *             -d /usr/lib64/librte_net_e1000.so
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

#include "cproto.h"

#define NUM_MBUFS   8191
#define MBUF_CACHE  250
#define BURST_SIZE  32
#define RING_SIZE   4096
#define NB_RXD      1024
#define NB_TXD      1024

static volatile sig_atomic_t force_quit = 0;
static struct rte_ring *rx_ring = NULL;
static uint16_t         g_port  = 0;

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

/* ---------------- 接收文件上下文(写盘核私有) ---------------- */
enum { ST_WAIT_START = 0, ST_RECEIVING = 1 };

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

/* ---------------- 状态机:START ---------------- */
static void handle_start(struct cproto_hdr *ch, uint8_t *payload, uint16_t plen)
{
    if (ctx.state == ST_RECEIVING) {
        printf("[警告] 上一个文件还没结束又收到 START,丢弃旧上下文\n");
        if (ctx.fd >= 0) close(ctx.fd);
        free(ctx.bitmap);
        memset(&ctx, 0, sizeof(ctx));
        ctx.fd = -1;
    }
    if (plen < sizeof(struct cproto_start))
        return;

    struct cproto_start *st = (struct cproto_start *)payload;
    ctx.file_id      = rte_be_to_cpu_16(ch->file_id);
    ctx.total_size   = rte_be_to_cpu_64(st->total_size);
    ctx.total_chunks = rte_be_to_cpu_32(st->total_chunks);

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

    printf("[START] file=%s  size=%lu  chunks=%u  file_id=%u\n",
           ctx.outname, (unsigned long)ctx.total_size,
           ctx.total_chunks, ctx.file_id);
}

/* ---------------- 状态机:DATA ---------------- */
static void handle_data(uint32_t seq, uint8_t *payload, uint16_t plen)
{
    if (ctx.state != ST_RECEIVING) return;
    if (seq >= ctx.total_chunks)   return;

    off_t off = (off_t)seq * CPROTO_CHUNK_SIZE;
    if (pwrite(ctx.fd, payload, plen, off) != plen) {
        printf("[错误] pwrite seq=%u 失败: %s\n", seq, strerror(errno));
        return;
    }
    if (ctx.bitmap[seq] == 0) {       /* 幂等:重复块不重复计数 */
        ctx.bitmap[seq] = 1;
        ctx.recv_count++;
        ctx.bytes_written += plen;
    }
}

/* ---------------- 状态机:END(收尾 + 校验 + 报告) ---------------- */
static void handle_end(uint8_t *payload, uint16_t plen)
{
    if (ctx.state != ST_RECEIVING) return;
    if (plen < sizeof(struct cproto_end)) return;

    struct cproto_end *en = (struct cproto_end *)payload;
    uint32_t expect_crc = rte_be_to_cpu_32(en->crc32);

    ftruncate(ctx.fd, ctx.total_size);   /* 保证文件精确大小(末块若丢则补零) */
    fsync(ctx.fd);

    /* 读回整文件算 CRC32 */
    uint32_t running = 0xFFFFFFFFu;
    uint8_t  buf[4096];
    off_t    off = 0;
    ssize_t  n;
    while ((n = pread(ctx.fd, buf, sizeof(buf), off)) > 0) {
        running = crc32_update(running, buf, (size_t)n);
        off += n;
    }
    uint32_t actual_crc = running ^ 0xFFFFFFFFu;
    close(ctx.fd);
    ctx.fd = -1;

    uint32_t missing = ctx.total_chunks - ctx.recv_count;

    printf("\n========== [END] 传输结束: %s ==========\n", ctx.outname);
    printf("  块  : 收到 %u / %u", ctx.recv_count, ctx.total_chunks);
    if (missing) {
        printf("   缺失 %u 块 ->", missing);
        uint32_t shown = 0;
        for (uint32_t i = 0; i < ctx.total_chunks && shown < 20; i++)
            if (!ctx.bitmap[i]) { printf(" %u", i); shown++; }
        if (missing > 20) printf(" ...");
    }
    printf("\n");
    printf("  字节: 写入 %lu / 期望 %lu\n",
           (unsigned long)ctx.bytes_written, (unsigned long)ctx.total_size);
    printf("  CRC : 收到 0x%08x  实算 0x%08x\n", expect_crc, actual_crc);
    if (missing == 0 && actual_crc == expect_crc)
        printf("  结果: ✓ PASS  文件完整\n");
    else
        printf("  结果: ✗ FAIL  文件不完整或损坏\n");
    printf("===========================================\n\n");

    free(ctx.bitmap);
    memset(&ctx, 0, sizeof(ctx));
    ctx.fd    = -1;
    ctx.state = ST_WAIT_START;
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
            uint16_t plen = rte_be_to_cpu_16(ch->payload_len);
            uint32_t seq  = rte_be_to_cpu_32(ch->seq);
            switch (ch->type) {
            case CPROTO_TYPE_START: handle_start(ch, payload, plen); break;
            case CPROTO_TYPE_DATA:  handle_data(seq, payload, plen); break;
            case CPROTO_TYPE_END:   handle_end(payload, plen);       break;
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

    struct rte_ether_addr mac;
    rte_eth_macaddr_get(port, &mac);
    printf("[端口 %u] 启动完成  MAC %02x:%02x:%02x:%02x:%02x:%02x  混杂模式已开\n",
           port, mac.addr_bytes[0], mac.addr_bytes[1], mac.addr_bytes[2],
           mac.addr_bytes[3], mac.addr_bytes[4], mac.addr_bytes[5]);
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

    struct rte_mempool *pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS, MBUF_CACHE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!pool) rte_exit(EXIT_FAILURE, "mbuf 池创建失败: %s\n",
                        rte_strerror(rte_errno));

    if (port_init(g_port, pool) != 0)
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
