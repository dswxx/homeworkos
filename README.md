# homeworeOs

自定义协议栈实验代码。接收端运行在 openEuler + DPDK，发送端从 Python/Scapy 逐步演进到 C++ raw socket/sendmmsg。

## 版本说明

- `v1/`: 单向文件传输，发送端发完即结束，接收端按块写盘并做 CRC 校验。
- `v2/`: 增加反向通道，支持 `START_ACK`、`NAK` 选择性重传和 `END_ACK`。
- `v3/`: 引入 `client_conn_id + connection_id`，尝试多连接/多文件复用。

## 接收端运行

在 DPDK 接收端机器上：

```bash
cd v3
make
make run
```

## 发送端运行

在发送端 Ubuntu 机器上：

```bash
cd v3
make sender
sudo ./sender <file>
```

测试丢块和握手重试：

```bash
sudo ./sender <file> 5,100,357
sudo ./sender <file> - 1
```

## 注意

仓库只保存源码和配置文件，不保存实验生成的 `*.bin`、`recv_*` 文件和编译产物。
