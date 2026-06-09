#ifndef _GNU_SOURCE
#define _GNU_SOURCE             // sendmmsg / struct mmsghdr 需要
#endif
// =======================================================================
//  自定义协议栈实验 —— 发送端 (C++ 版, sendmmsg 批量发送)
//
//  握手(START↔START_ACK 拿 connection_id)→ 发 DATA/END
//  → END_ACK 完成 / NAK 选择性重传 / 超时重发。
//
//  连接标识:client_conn_id(本端自选,握手配对)+ connection_id(接收端分配)
//  与接收端共用 cproto.h。单线程:开环模型,SO_RCVTIMEO + recv 即可。
//
//  编译:  g++ -O2 -std=c++17 -o sender sender.cpp     (与 cproto.h 同目录)
//  用法:  sudo ./sender <文件> [丢弃的data-chunk] [丢弃START次数]
// =======================================================================
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <ctime>
#include <string>
#include <vector>
#include <set>
#include <random>
#include <stdexcept>
#include <algorithm>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <endian.h>

#include "cproto.h"

#ifndef SOL_PACKET
#define SOL_PACKET 263
#endif
#ifndef PACKET_IGNORE_OUTGOING
#define PACKET_IGNORE_OUTGOING 23
#endif
#ifndef ETH_P_ALL
#define ETH_P_ALL 0x0003
#endif

// ---------------- 配置(与接收端约定一致) ----------------
static const char*   IFACE        = "ens37";
static const uint8_t RECV_MAC[6]  = {0x00,0x0c,0x29,0x74,0xa1,0x0d};
static const uint8_t SRC_MAC [6]  = {0x00,0x0c,0x29,0xf5,0xca,0x65};
static const char*   SRC_IP       = "192.168.40.128";
static const char*   DST_IP       = "192.168.40.137";

static const double HS_TIMEOUT   = 2.0;
static const int    MAX_HS       = 6;
static const double RESP_TIMEOUT = 3.0;
static const int    MAX_ROUNDS   = 12;
static const int    BATCH        = 64;

// ---------------- 小工具 ----------------
static double now_sec() {
    timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static uint16_t ip_checksum(const void* data, size_t len) {
    const uint16_t* p = static_cast<const uint16_t*>(data);
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *reinterpret_cast<const uint8_t*>(p);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

static uint32_t g_crc_table[256];
static void crc32_init() {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        g_crc_table[i] = c;
    }
}
static uint32_t crc32_compute(const uint8_t* buf, size_t len) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        c = g_crc_table[(c ^ buf[i]) & 0xff] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

// ---------------- RAII:raw L2 socket ----------------
class RawSocket {
    int fd_ = -1;
public:
    explicit RawSocket(const char* iface) {
        fd_ = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd_ < 0) throw std::runtime_error("socket(AF_PACKET) 失败(需 root)");
        unsigned ifidx = if_nametoindex(iface);
        if (!ifidx) throw std::runtime_error(std::string("找不到网卡 ") + iface);
        sockaddr_ll a{};
        a.sll_family   = AF_PACKET;
        a.sll_protocol = htons(ETH_P_ALL);
        a.sll_ifindex  = static_cast<int>(ifidx);
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) < 0)
            throw std::runtime_error("bind 网卡失败");
        int one = 1;
        ::setsockopt(fd_, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one));
        timeval tv{0, 100000};
        ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    ~RawSocket() { if (fd_ >= 0) ::close(fd_); }
    RawSocket(const RawSocket&) = delete;
    RawSocket& operator=(const RawSocket&) = delete;
    int     send_batch(mmsghdr* m, unsigned n) { return ::sendmmsg(fd_, m, n, 0); }
    ssize_t recv(void* b, size_t n)            { return ::recv(fd_, b, n, 0); }
};

// ---------------- RAII:只读 mmap 文件 ----------------
class FileMap {
    int            fd_   = -1;
    const uint8_t* data_ = nullptr;
    size_t         size_ = 0;
public:
    explicit FileMap(const char* path) {
        fd_ = ::open(path, O_RDONLY);
        if (fd_ < 0) throw std::runtime_error(std::string("打不开 ") + path);
        struct stat st{};
        if (fstat(fd_, &st) < 0) throw std::runtime_error("fstat 失败");
        size_ = static_cast<size_t>(st.st_size);
        if (size_ > 0) {
            void* m = mmap(nullptr, size_, PROT_READ, MAP_PRIVATE, fd_, 0);
            if (m == MAP_FAILED) throw std::runtime_error("mmap 失败");
            data_ = static_cast<const uint8_t*>(m);
        }
    }
    ~FileMap() {
        if (data_) munmap(const_cast<uint8_t*>(data_), size_);
        if (fd_ >= 0) ::close(fd_);
    }
    FileMap(const FileMap&) = delete;
    FileMap& operator=(const FileMap&) = delete;
    const uint8_t* data() const { return data_; }
    size_t         size() const { return size_; }
};

// ---------------- 回包 ----------------
struct Reply {
    uint8_t  type          = 0xFF;
    uint16_t cid           = 0;   // 回包头里的 connection_id
    uint64_t client_cid    = 0;   // START_ACK
    uint16_t connection_id = 0;   // START_ACK:服务端分配的 id
    uint8_t  status        = 0;   // END_ACK
    uint32_t recv_chunks   = 0;   // END_ACK
    std::vector<uint32_t> chunks; // NAK:缺失 chunk_index 列表
};

// ---------------- 发送端主体 ----------------
class Sender {
    RawSocket      sock_;
    const uint8_t* file_;
    size_t         total_size_;
    uint32_t       total_chunks_;
    std::string    fname_;
    uint64_t       client_cid_;     // 本端自选的连接 id(握手配对)
    uint32_t       crc_;
    uint16_t       conn_id_ = 0;    // 接收端分配的 connection_id

    uint8_t  txbuf_[BATCH][1600];
    iovec    iov_[BATCH];
    mmsghdr  msgs_[BATCH];
    int      nbatch_ = 0;

    uint64_t pkts_       = 0;
    uint64_t bytes_      = 0;
    uint64_t retx_total_ = 0;
    int      nak_rounds_ = 0;
    int      hs_attempts_= 0;

    void setup_batch() {
        memset(msgs_, 0, sizeof(msgs_));
        for (int i = 0; i < BATCH; i++) {
            iov_[i].iov_base = txbuf_[i];
            iov_[i].iov_len  = 0;
            msgs_[i].msg_hdr.msg_iov    = &iov_[i];
            msgs_[i].msg_hdr.msg_iovlen = 1;
        }
        nbatch_ = 0;
    }

    void flush() {
        if (nbatch_ == 0) return;
        int off = 0;
        while (off < nbatch_) {
            int r = sock_.send_batch(&msgs_[off], static_cast<unsigned>(nbatch_ - off));
            if (r > 0) { off += r; continue; }
            // 关键:TX 队列瞬时满时必须【等待重试,绝不丢弃】。
            // 这是背压 —— 把发送端节流到网卡能吃下的速率。一旦改成丢弃,
            // 发送端就会超出网卡速率、在源头丢包,而 NAK-only 协议无法补回大量丢失。
            // usleep 只是避免 100% 空转,不改变"绝不丢"的语义。
            if (r < 0 && (errno == ENOBUFS || errno == EAGAIN)) { usleep(50); continue; }
            break;  // 仅其它错误才放弃这批
        }
        nbatch_ = 0;
    }

    void send_pkt(uint8_t type, uint32_t chunk_index, uint16_t cid,
                  const uint8_t* payload, uint16_t plen) {
        uint8_t* buf = txbuf_[nbatch_];

        ether_header* eth = reinterpret_cast<ether_header*>(buf);
        memcpy(eth->ether_dhost, RECV_MAC, 6);
        memcpy(eth->ether_shost, SRC_MAC,  6);
        eth->ether_type = htons(CPROTO_ETHERTYPE);

        iphdr* ip = reinterpret_cast<iphdr*>(buf + sizeof(ether_header));
        memset(ip, 0, sizeof(iphdr));
        ip->version  = 4;
        ip->ihl      = 5;
        ip->ttl      = 64;
        ip->protocol = CPROTO_IP_PROTO;
        ip->tot_len  = htons(sizeof(iphdr) + sizeof(cproto_hdr) + plen);
        ip->saddr    = inet_addr(SRC_IP);
        ip->daddr    = inet_addr(DST_IP);
        ip->check    = 0;
        ip->check    = ip_checksum(ip, sizeof(iphdr));

        cproto_hdr* ch = reinterpret_cast<cproto_hdr*>(
                             buf + sizeof(ether_header) + sizeof(iphdr));
        ch->magic         = htons(CPROTO_MAGIC);
        ch->type          = type;
        ch->rsv           = 0;
        ch->chunk_index   = htonl(chunk_index);
        ch->payload_len   = htons(plen);
        ch->connection_id = htons(cid);

        if (plen)
            memcpy(reinterpret_cast<uint8_t*>(ch) + sizeof(cproto_hdr), payload, plen);

        size_t total = sizeof(ether_header) + sizeof(iphdr) + sizeof(cproto_hdr) + plen;
        iov_[nbatch_].iov_len = total;
        nbatch_++;
        pkts_++;
        bytes_ += total;

        if (nbatch_ == BATCH) flush();
    }

    void send_data(uint32_t chunk_index, uint16_t cid) {
        size_t off = static_cast<size_t>(chunk_index) * CPROTO_CHUNK_SIZE;
        size_t len = std::min<size_t>(CPROTO_CHUNK_SIZE, total_size_ - off);
        send_pkt(CPROTO_TYPE_DATA, chunk_index, cid, file_ + off, static_cast<uint16_t>(len));
    }

    void send_end() {
        cproto_end en{};
        en.crc32 = htonl(crc_);
        send_pkt(CPROTO_TYPE_END, 0, conn_id_,
                 reinterpret_cast<uint8_t*>(&en), sizeof(en));
    }

    bool parse_reply(const uint8_t* buf, ssize_t n, Reply& r) const {
        const size_t base = sizeof(ether_header) + sizeof(iphdr) + sizeof(cproto_hdr);
        if (n < static_cast<ssize_t>(base)) return false;

        const ether_header* eth = reinterpret_cast<const ether_header*>(buf);
        if (ntohs(eth->ether_type) != CPROTO_ETHERTYPE) return false;
        if (memcmp(eth->ether_dhost, SRC_MAC, 6) != 0)   return false;

        const iphdr* ip = reinterpret_cast<const iphdr*>(buf + sizeof(ether_header));
        if (ip->protocol != CPROTO_IP_PROTO)             return false;

        const cproto_hdr* ch = reinterpret_cast<const cproto_hdr*>(
                                   buf + sizeof(ether_header) + ip->ihl * 4);
        if (ntohs(ch->magic) != CPROTO_MAGIC)            return false;

        const uint8_t* pl = reinterpret_cast<const uint8_t*>(ch) + sizeof(cproto_hdr);
        uint16_t plen = ntohs(ch->payload_len);
        r.type = ch->type;
        r.cid  = ntohs(ch->connection_id);

        switch (r.type) {
        case CPROTO_TYPE_START_ACK: {
            if (plen < sizeof(cproto_start_ack)) return false;
            auto* sa = reinterpret_cast<const cproto_start_ack*>(pl);
            r.client_cid    = be64toh(sa->client_conn_id);
            r.connection_id = ntohs(sa->connection_id);
            return true;
        }
        case CPROTO_TYPE_END_ACK: {
            if (plen < sizeof(cproto_end_ack)) return false;
            auto* ea = reinterpret_cast<const cproto_end_ack*>(pl);
            r.status      = ea->status;
            r.recv_chunks = ntohl(ea->recv_chunks);
            return true;
        }
        case CPROTO_TYPE_NAK: {
            if (plen < sizeof(cproto_nak)) return false;
            auto* nk = reinterpret_cast<const cproto_nak*>(pl);
            uint16_t cnt = ntohs(nk->count);
            const uint8_t* sp = pl + sizeof(cproto_nak);
            r.chunks.clear();
            for (uint16_t i = 0; i < cnt; i++) {
                uint32_t s;
                memcpy(&s, sp + i * 4, 4);
                r.chunks.push_back(ntohl(s));
            }
            return true;
        }
        default:
            return false;
        }
    }

    bool wait_reply(double timeout_s, Reply& out) {
        double deadline = now_sec() + timeout_s;
        uint8_t buf[2048];
        while (now_sec() < deadline) {
            ssize_t n = sock_.recv(buf, sizeof(buf));
            if (n <= 0) continue;
            if (!parse_reply(buf, n, out)) continue;
            // 只接受属于本连接的回包(并发时两个 sender 同 MAC,会收到对方的回包):
            //   · START_ACK 此时 conn_id_ 尚未分配,用 client_cid 配对
            //   · END_ACK/NAK 用 connection_id 配对
            if (out.type == CPROTO_TYPE_START_ACK) {
                if (out.client_cid == client_cid_) return true;
            } else if (conn_id_ != 0 && out.cid == conn_id_) {
                return true;
            }
            // 不属于本连接 → 忽略,继续等到 deadline
        }
        return false;
    }

    bool handshake(int drop_starts) {
        uint8_t pl[sizeof(cproto_start) + 256];
        auto* st = reinterpret_cast<cproto_start*>(pl);
        st->client_conn_id = htobe64(client_cid_);
        st->total_size     = htobe64(total_size_);
        st->total_chunks   = htonl(total_chunks_);
        size_t nl = std::min<size_t>(fname_.size(), 255);
        memcpy(pl + sizeof(cproto_start), fname_.data(), nl);
        uint16_t plen = static_cast<uint16_t>(sizeof(cproto_start) + nl);

        int suppressed = 0;
        for (int attempt = 1; attempt <= MAX_HS; attempt++) {
            if (suppressed < drop_starts) {
                suppressed++;
                printf("[握手] 第%d次 START 被故意丢弃(测试)\n", attempt);
            } else {
                send_pkt(CPROTO_TYPE_START, 0, 0, pl, plen);
                flush();
                printf("[握手] 发送 START(第%d次)...\n", attempt);
            }
            Reply r;
            if (wait_reply(HS_TIMEOUT, r) &&
                r.type == CPROTO_TYPE_START_ACK && r.client_cid == client_cid_) {
                conn_id_     = r.connection_id;
                hs_attempts_ = attempt;
                printf("[握手] ✓ 收到 START_ACK,接收端分配 connection_id=%u\n", conn_id_);
                return true;
            }
            printf("[握手] 超时未收到 START_ACK,重试\n");
        }
        return false;
    }

public:
    Sender(const char* iface, const FileMap& fm, std::string fname)
        : sock_(iface),
          file_(fm.data()),
          total_size_(fm.size()),
          fname_(std::move(fname)) {
        total_chunks_ = static_cast<uint32_t>(
                            (total_size_ + CPROTO_CHUNK_SIZE - 1) / CPROTO_CHUNK_SIZE);
        std::random_device rd;
        std::mt19937_64 gen(((uint64_t)rd() << 32) ^ rd());
        client_cid_ = gen();
        crc_        = crc32_compute(file_, total_size_);
        setup_batch();
    }

    void banner(const std::set<uint32_t>& drop_first, int drop_starts) const {
        printf("       大小 %zu 字节 | %u 块 | crc32=0x%08x | client_cid=0x%016llx\n",
               total_size_, total_chunks_, crc_, (unsigned long long)client_cid_);
        if (!drop_first.empty()) {
            printf("       [测试] 首发故意丢弃 chunk [");
            bool first = true;
            for (uint32_t s : drop_first) { printf("%s%u", first ? "" : ", ", s); first = false; }
            printf("]\n");
        }
        if (drop_starts > 0)
            printf("       [测试] 故意丢弃前 %d 个 START\n", drop_starts);
    }

    void run(const std::set<uint32_t>& drop_first, int drop_starts) {
        double t0 = now_sec();

        if (!handshake(drop_starts)) {
            printf("[结果] ✗ 握手失败,放弃\n");
            return;
        }

        uint32_t sent = 0;
        for (uint32_t idx = 0; idx < total_chunks_; idx++) {
            if (drop_first.count(idx)) continue;
            send_data(idx, conn_id_);
            sent++;
        }
        send_end();
        flush();
        printf("[完成] DATA %u/%u + END 已发出\n", sent, total_chunks_);

        bool done = false;
        for (int rnd = 0; rnd < MAX_ROUNDS && !done; rnd++) {
            Reply r;
            if (!wait_reply(RESP_TIMEOUT, r)) {
                printf("[超时] 第%d轮无响应,重发 END\n", rnd + 1);
                send_end();
                flush();
                continue;
            }
            if (r.type == CPROTO_TYPE_END_ACK) {
                if (r.status == CPROTO_ST_PASS)
                    printf("[结果] ✓ 接收端确认 PASS(实收 %u/%u 块)\n",
                           r.recv_chunks, total_chunks_);
                else
                    printf("[结果] ✗ 接收端报告 FAIL(实收 %u/%u 块,不可恢复)\n",
                           r.recv_chunks, total_chunks_);
                done = true;
            } else if (r.type == CPROTO_TYPE_NAK) {
                nak_rounds_++;
                retx_total_ += r.chunks.size();
                printf("[NAK] 接收端缺 %zu 块,重传\n", r.chunks.size());
                for (uint32_t s : r.chunks) send_data(s, conn_id_);
                send_end();
                flush();
            }
        }
        if (!done)
            printf("[结果] 超过 %d 轮仍未完成,放弃\n", MAX_ROUNDS);

        double dur = now_sec() - t0;
        double gp  = dur > 0 ? (total_size_ / 1e6) / dur : 0.0;
        printf("[统计] 用时 %.3fs | goodput %.2f MB/s | 发包 %llu 个 / %.2f MB | "
               "重传 %llu 块(%d 轮 NAK) | 握手 %d 次\n",
               dur, gp, (unsigned long long)pkts_, bytes_ / 1e6,
               (unsigned long long)retx_total_, nak_rounds_, hs_attempts_);
    }
};

// ---------------- main ----------------
int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "用法: sudo %s <文件> [丢弃的data-chunk] [丢弃START次数]\n", argv[0]);
        return 1;
    }
    const char* path = argv[1];

    std::set<uint32_t> drop_first;
    if (argc >= 3 && strcmp(argv[2], "-") != 0 &&
        strcmp(argv[2], "none") != 0 && argv[2][0] != '\0') {
        char* s = strdup(argv[2]);
        for (char* t = strtok(s, ","); t; t = strtok(nullptr, ","))
            drop_first.insert(static_cast<uint32_t>(strtoul(t, nullptr, 10)));
        free(s);
    }
    int drop_starts = (argc >= 4) ? atoi(argv[3]) : 0;

    crc32_init();
    try {
        FileMap fm(path);
        if (fm.size() == 0) { fprintf(stderr, "[错误] 空文件\n"); return 1; }
        std::string fn(path);
        auto pos = fn.find_last_of('/');
        if (pos != std::string::npos) fn = fn.substr(pos + 1);
        Sender s(IFACE, fm, fn);
        printf("[发送] %s\n", path);
        s.banner(drop_first, drop_starts);
        s.run(drop_first, drop_starts);
    } catch (const std::exception& e) {
        fprintf(stderr, "[错误] %s\n", e.what());
        return 1;
    }
    return 0;
}