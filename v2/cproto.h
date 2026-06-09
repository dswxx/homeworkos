#ifndef CPROTO_H
#define CPROTO_H
#include <stdint.h>

/* =======================================================================
 *  自定义协议栈实验 —— 上线格式 (wire format)
 *  接收端 (openEuler / DPDK) #include 本文件
 *  发送端 (Ubuntu / Scapy)   用 struct.pack 按相同布局打包
 *  所有多字节字段一律网络序(大端)
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
    CPROTO_TYPE_START_ACK = 3,  /* 收→发  握手确认(M3 用)   */
    CPROTO_TYPE_NAK       = 4,  /* 收→发  请求重传缺块(M2 用)*/
    CPROTO_TYPE_END_ACK   = 5,  /* 收→发  关闭确认(M1)      */
};

/* END_ACK 状态 */
enum {
    CPROTO_ST_PASS = 0,
    CPROTO_ST_FAIL = 1,
};

/* 每个包都带的基础头,固定 12 字节 */
struct cproto_hdr {
    uint16_t magic;        /* = CPROTO_MAGIC                          */
    uint8_t  type;         /* CPROTO_TYPE_*                           */
    uint8_t  rsv;          /* 保留/对齐,填 0                          */
    uint32_t seq;          /* 块序号;DATA 用,START/END 填 0          */
    uint16_t payload_len;  /* 本包 cproto_hdr 之后的有效字节数        */
    uint16_t file_id;      /* 区分不同文件传输,防串话                */
} __attribute__((__packed__));

/* START 包:cproto_hdr 之后跟此结构,再紧跟文件名(不定长) */
struct cproto_start {
    uint64_t client_nonce;  /* 发送端随机数,用于配对 START_ACK(握手) */
    uint64_t total_size;    /* 文件总字节数                            */
    uint32_t total_chunks;  /* 总块数                                  */
    /* 后面紧跟文件名,长度 = payload_len - sizeof(struct cproto_start) */
} __attribute__((__packed__));

/* START_ACK 包(收→发):握手确认 */
struct cproto_start_ack {
    uint64_t client_nonce;  /* 回显发送端的 nonce                      */
    uint16_t transfer_id;   /* 接收端分配的 id(填入后续包头 file_id)  */
    uint16_t rsv;           /* 对齐,填 0                              */
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

/* NAK 包(收→发):cproto_hdr 之后跟此结构,再紧跟 count 个缺失 seq(各 4B,网络序) */
struct cproto_nak {
    uint16_t count;         /* 本包携带的缺失 seq 数 */
    /* 后面紧跟 count 个 uint32 缺失 seq */
} __attribute__((__packed__));

/* ---- 参数 ---- */
#define CPROTO_CHUNK_SIZE  1400
/* 帧长: 14(eth) + 20(ip) + 12(cproto_hdr) + 1400 = 1446 <= 1514,留足余量 */

#endif /* CPROTO_H */