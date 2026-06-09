#!/usr/bin/env python3
# =======================================================================
#  自定义协议栈实验 —— 发送端 (v2 / M3: 握手 + transfer_id + NAK 重传)
#  在 Ubuntu (ens37, 内核态) 上运行,用 Scapy 造包发往接收端
#
#  用法:  sudo python3 sender.py <文件路径> [丢弃的data-seq] [丢弃的START次数]
#  例:    sudo python3 sender.py test.bin              # 正常
#         sudo python3 sender.py test.bin 5,100,357    # 首发丢这几块,测 NAK 重传
#         sudo python3 sender.py test.bin - 1          # 丢第 1 个 START,测握手重发
#
#  流程:握手(START↔START_ACK,拿 transfer_id) → 发 DATA/END(带 id)
#        → END_ACK(PASS) 完成 / NAK 选择性重传 / 超时重发
# =======================================================================
import sys
import os
import time
import struct
import zlib
import queue
import random
from scapy.all import Ether, IP, Raw, AsyncSniffer, conf

# ---- 与 cproto.h 一致的常量 ----
IFACE     = "ens37"
RECV_MAC  = "00:0c:29:74:a1:0d"
SRC_MAC   = "00:0c:29:f5:ca:65"
SRC_IP    = "192.168.40.128"
DST_IP    = "192.168.40.137"
ETYPE     = 0x0800
IP_PROTO  = 0xFD

MAGIC     = 0xD557
T_START, T_DATA, T_END        = 0, 1, 2
T_START_ACK, T_NAK, T_END_ACK = 3, 4, 5
ST_PASS, ST_FAIL              = 0, 1
CHUNK     = 1400

GAP          = 0.000   # pacing
HS_TIMEOUT   = 2.0      # 等 START_ACK 超时
MAX_HS       = 6        # 握手最大尝试次数
RESP_TIMEOUT = 3.0      # 数据阶段等响应超时
MAX_ROUNDS   = 12       # 重传最大轮数

HDR_FMT = ">HBBIHH"
HDR_LEN = struct.calcsize(HDR_FMT)

NONCE       = random.getrandbits(64)   # 本次传输的握手随机数
TRANSFER_ID = None                     # 握手后由接收端分配
resp_q      = queue.Queue()
STAT        = {"pkts": 0, "bytes": 0}  # 发包/字节计数(含重传/重发)
L2SOCK      = None                     # 复用的二层发送 socket(避免每包重开)


def make_hdr(type_, seq, payload_len, fid):
    return struct.pack(HDR_FMT, MAGIC, type_, 0, seq, payload_len, fid)


def send_one(payload, type_, seq, fid):
    frame = (Ether(dst=RECV_MAC, src=SRC_MAC, type=ETYPE) /
             IP(src=SRC_IP, dst=DST_IP, proto=IP_PROTO) /
             Raw(load=make_hdr(type_, seq, len(payload), fid) + payload))
    L2SOCK.send(frame)                 # 复用 socket,比每包 sendp() 快一两个数量级
    STAT["pkts"] += 1
    STAT["bytes"] += 14 + 20 + HDR_LEN + len(payload)


def send_data(data, seq, fid):
    send_one(data[seq * CHUNK:(seq + 1) * CHUNK], T_DATA, seq, fid)


def on_reply(pkt):
    if Raw not in pkt:
        return
    raw = bytes(pkt[Raw].load)
    if len(raw) < HDR_LEN:
        return
    magic, type_, _r, _s, _p, fid = struct.unpack(HDR_FMT, raw[:HDR_LEN])
    if magic != MAGIC:
        return
    body = raw[HDR_LEN:]
    if type_ == T_START_ACK and len(body) >= 12:
        nonce, tid, _rsv = struct.unpack(">QHH", body[:12])
        if nonce == NONCE:
            resp_q.put(("sack", tid))
    elif type_ == T_END_ACK and len(body) >= 6:
        if TRANSFER_ID is not None and fid == TRANSFER_ID:
            status, _rsv, recv = struct.unpack(">BBI", body[:6])
            resp_q.put(("ack", status, recv))
    elif type_ == T_NAK and len(body) >= 2:
        if TRANSFER_ID is not None and fid == TRANSFER_ID:
            (cnt,) = struct.unpack(">H", body[:2])
            if cnt and len(body) >= 2 + cnt * 4:
                seqs = struct.unpack(f">{cnt}I", body[2:2 + cnt * 4])
                resp_q.put(("nak", list(seqs)))


def main():
    global TRANSFER_ID, L2SOCK
    if len(sys.argv) < 2:
        print("用法: sudo python3 sender.py <文件路径> [丢弃的data-seq] [丢弃的START次数]")
        sys.exit(1)

    path = sys.argv[1]
    drop_first = set()
    if len(sys.argv) >= 3 and sys.argv[2] not in ("-", "none", ""):
        drop_first = set(int(x) for x in sys.argv[2].split(","))
    drop_starts = int(sys.argv[3]) if len(sys.argv) >= 4 else 0

    with open(path, "rb") as f:
        data = f.read()
    total_size   = len(data)
    total_chunks = (total_size + CHUNK - 1) // CHUNK
    fname        = os.path.basename(path).encode()
    crc          = zlib.crc32(data) & 0xffffffff
    crc_bytes    = struct.pack(">I", crc)

    print(f"[发送] {path}")
    print(f"       大小 {total_size} 字节 | {total_chunks} 块 | crc32=0x{crc:08x} | nonce=0x{NONCE:016x}")
    if drop_first:
        print(f"       [测试] 首发故意丢弃 data {sorted(drop_first)}")
    if drop_starts:
        print(f"       [测试] 故意丢弃前 {drop_starts} 个 START")

    sniffer = AsyncSniffer(iface=IFACE,
                           filter=f"ether dst {SRC_MAC} and ip proto 253",
                           prn=on_reply, store=False)
    sniffer.start()
    time.sleep(0.3)
    L2SOCK = conf.L2socket(iface=IFACE)   # 开一次,全程复用

    # ---- 握手:START ↔ START_ACK ----
    start_meta = struct.pack(">QQI", NONCE, total_size, total_chunks) + fname
    t0 = time.time()
    suppressed = 0
    hs_attempts = 0
    for attempt in range(1, MAX_HS + 1):
        if suppressed < drop_starts:
            suppressed += 1
            print(f"[握手] 第{attempt}次 START 被故意丢弃(测试)")
        else:
            send_one(start_meta, T_START, 0, 0)   # 握手阶段 file_id 填 0
            print(f"[握手] 发送 START(第{attempt}次)...")
        try:
            msg = resp_q.get(timeout=HS_TIMEOUT)
        except queue.Empty:
            print("[握手] 超时未收到 START_ACK,重试")
            continue
        if msg[0] == "sack":
            TRANSFER_ID = msg[1]
            hs_attempts = attempt
            print(f"[握手] ✓ 收到 START_ACK,接收端分配 transfer_id={TRANSFER_ID}")
            break

    if TRANSFER_ID is None:
        print("[结果] ✗ 握手失败,放弃")
        sniffer.stop()
        L2SOCK.close()
        return

    # ---- 数据阶段:DATA + END(带 transfer_id) ----
    sent = 0
    for seq in range(total_chunks):
        if seq in drop_first:
            continue
        send_data(data, seq, TRANSFER_ID)
        sent += 1
        if GAP:
            time.sleep(GAP)
    send_one(crc_bytes, T_END, 0, TRANSFER_ID)
    print(f"[完成] DATA {sent}/{total_chunks} + END 已发出")

    # ---- 响应循环 ----
    done = False
    retx_total = 0
    nak_rounds = 0
    for rnd in range(MAX_ROUNDS):
        try:
            msg = resp_q.get(timeout=RESP_TIMEOUT)
        except queue.Empty:
            print(f"[超时] 第{rnd+1}轮无响应,重发 END")
            send_one(crc_bytes, T_END, 0, TRANSFER_ID)
            continue
        if msg[0] == "ack":
            status, recv = msg[1], msg[2]
            if status == ST_PASS:
                print(f"[结果] ✓ 接收端确认 PASS(实收 {recv}/{total_chunks} 块)")
            else:
                print(f"[结果] ✗ 接收端报告 FAIL(实收 {recv}/{total_chunks} 块,不可恢复)")
            dur = time.time() - t0
            gp  = (total_size / 1e6) / dur if dur > 0 else 0.0
            print(f"[统计] 用时 {dur:.3f}s | goodput {gp:.2f} MB/s | "
                  f"发包 {STAT['pkts']} 个 / {STAT['bytes']/1e6:.2f} MB | "
                  f"重传 {retx_total} 块({nak_rounds} 轮 NAK) | 握手 {hs_attempts} 次")
            done = True
            break
        elif msg[0] == "nak":
            missing = msg[1]
            retx_total += len(missing)
            nak_rounds += 1
            print(f"[NAK] 接收端缺 {len(missing)} 块,重传 {sorted(missing)[:10]}"
                  f"{' ...' if len(missing) > 10 else ''}")
            for seq in missing:
                send_data(data, seq, TRANSFER_ID)
                if GAP:
                    time.sleep(GAP)
            send_one(crc_bytes, T_END, 0, TRANSFER_ID)
        # 其它(如握手期残留的 sack)忽略

    if not done:
        print(f"[结果] 超过 {MAX_ROUNDS} 轮仍未完成,放弃")

    sniffer.stop()
    L2SOCK.close()


if __name__ == "__main__":
    main()
