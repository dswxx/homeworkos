#ifndef CPROTO_H
#define CPROTO_H
#include <stdint.h>

/* =======================================================================
 *  自定义协议栈实验 —— 上线格式 (wire format)
 *  接收端 (openEuler / DPDK) 与发送端 (C++) 共用本文件,格式只有一个源头。
 *  所有多字节字段一律网络序(大端)。
 *
 *  连接标识(借鉴 QUIC 的双向 Connection ID):
 *    · client_conn_id (64b):客户端自选,握手期用于配对 START_ACK
 *    · connection_id  (16b):服务端分配,之后每个包头都带,作解复用键
 * ======================================================================= */

/* ---- 链路层 / 网络层约定 ---- */
#define CPROTO_ETHERTYPE  0x0800   /* 伪装成 IPv4,接收端据此进入 IP 头解析   */
#define CPROTO_IP_PROTO   0xFD     /* 253,RFC3692 实验保留号,接收端据此筛包 */

/* ---- 自定义协议头 ---- */
#define CPROTO_MAGIC      0xD557   /* 魔数,二次确认是本协议(防误判) */

/* type 字段取值 */
enum {
    CPROTO_TYPE_START     = 0,  /* 发→收  文件开始,带元信息 */
    CPROTO_TYPE_DATA      = 1,  /* 发→收  数据块            */
    CPROTO_TYPE_END       = 2,  /* 发→收  文件结束,带校验    */
    CPROTO_TYPE_START_ACK = 3,  /* 收→发  握手确认           */
    CPROTO_TYPE_NAK       = 4,  /* 收→发  请求重传缺块        */
    CPROTO_TYPE_END_ACK   = 5,  /* 收→发  关闭确认           */
    CPROTO_TYPE_CREDIT    = 6,  /* 收→发  流控信用(可发到的累计块上限) */
};

/* END_ACK 状态 */
enum {
    CPROTO_ST_PASS = 0,
    CPROTO_ST_FAIL = 1,
};

/* 每个包都带的基础头,固定 12 字节 */
struct cproto_hdr {
    uint16_t magic;          /* = CPROTO_MAGIC                            */
    uint8_t  type;           /* CPROTO_TYPE_*                             */
    uint8_t  rsv;            /* 保留/对齐,填 0                            */
    uint32_t chunk_index;    /* 块号(= 字节偏移 / CHUNK);DATA 用,余填 0 */
    uint16_t payload_len;    /* 本包 cproto_hdr 之后的有效字节数          */
    uint16_t connection_id;  /* 服务端分配的连接 id,作解复用键           */
} __attribute__((__packed__));

/* START 包:cproto_hdr 之后跟此结构,再紧跟文件名(不定长) */
struct cproto_start {
    uint64_t client_conn_id;  /* 客户端自选的连接 id,用于配对 START_ACK */
    uint64_t total_size;      /* 文件总字节数                            */
    uint32_t total_chunks;    /* 总块数                                  */
    /* 后面紧跟文件名,长度 = payload_len - sizeof(struct cproto_start) */
} __attribute__((__packed__));

/* START_ACK 包(收→发):握手确认 */
struct cproto_start_ack {
    uint64_t client_conn_id;  /* 回显客户端的 conn id                       */
    uint16_t connection_id;   /* 服务端分配的连接 id(填入后续包头)         */
    uint16_t rsv;             /* 对齐,填 0                                  */
} __attribute__((__packed__));

/* END 包:cproto_hdr 之后跟此结构 */
struct cproto_end {
    uint32_t crc32;         /* 整个文件的 CRC32 (IEEE 802.3,与 zlib 一致) */
} __attribute__((__packed__));

/* END_ACK 包(收→发):cproto_hdr 之后跟此结构 */
struct cproto_end_ack {
    uint8_t  status;        /* CPROTO_ST_PASS / CPROTO_ST_FAIL */
    uint8_t  rsv;           /* 对齐,填 0 */
    uint32_t recv_chunks;   /* 接收端实收的块数,供发送端核对 */
} __attribute__((__packed__));

/* NAK 包(收→发):cproto_hdr 之后跟 count 个缺失 chunk_index(各 4B,网络序) */
struct cproto_nak {
    uint16_t count;         /* 本包携带的缺失 chunk_index 数 */
    /* 后面紧跟 count 个 uint32 缺失 chunk_index */
} __attribute__((__packed__));

/* CREDIT 包(收→发):QUIC 式信用流控。
 *   granted = "本连接允许发送的累计块上限(绝对值)"。
 *   发送端保证 已发块数 <= granted;接收端按写盘进度把 granted 往上抬。
 *   绝对值=幂等:丢一两个 CREDIT 无妨,后一个更大的值直接覆盖。 */
struct cproto_credit {
    uint16_t connection_id;  /* 目标连接(发送端据此过滤,只认自己的) */
    uint16_t rsv;            /* 对齐,填 0 */
    uint32_t granted;        /* 允许发送到的累计块上限(绝对块数) */
} __attribute__((__packed__));

/* ---- 参数 ---- */
#define CPROTO_CHUNK_SIZE  1400
/* 帧长: 14(eth) + 20(ip) + 12(cproto_hdr) + 1400 = 1446 <= 1514,留足余量 */

/* ---- 流量控制参数(收发两端共享) ---- */
#define CPROTO_FLOW_WINDOW   1024u  /* 单连接窗口 W:最多 W 个块"在途未落盘" */
#define CPROTO_FLOW_MAXCONN  4u     /* 设计并发上限;需保证 W*MAXCONN <= RING_SIZE */
/* 不变式: 任一时刻 ring 内某连接的块数 <= (已发 - 已落盘) <= W,
 *         故所有连接合计 <= MAXCONN*W <= RING_SIZE,ring 永不溢出。 */

#endif /* CPROTO_H */