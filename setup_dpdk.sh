#!/bin/bash
# DPDK 自定义协议栈实验 - 接收端环境初始化
# 环境: openEuler 24.03 / VMware e1000 / DPDK 23.11
# 每次重启后执行一次:  sudo ./setup_dpdk.sh
set -euo pipefail

NIC="ens37"          # 连 vmnet1 的实验网卡
HUGEPAGES=512        # 512 * 2MB = 1GB,够本实验用

echo "=== [1/5] 解析 ${NIC} 的 PCI 地址 ==="
if [ ! -e "/sys/class/net/${NIC}/device" ]; then
    echo "  ✗ 找不到 ${NIC}(可能已绑到 DPDK)。当前状态:" >&2
    dpdk-devbind.py --status | grep -iA15 network
    exit 1
fi
PCI=$(basename "$(readlink -f /sys/class/net/${NIC}/device)")
echo "  ${NIC} -> ${PCI}"

echo "=== [2/5] 配置并挂载大页 (${HUGEPAGES} * 2MB) ==="
echo ${HUGEPAGES} > /proc/sys/vm/nr_hugepages
mkdir -p /mnt/huge
mountpoint -q /mnt/huge || mount -t hugetlbfs nodev /mnt/huge
grep HugePages_Total /proc/meminfo

echo "=== [3/5] 加载 vfio-pci (no-IOMMU 模式) ==="
modprobe vfio
echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode
modprobe vfio-pci

echo "=== [4/5] 关闭网卡内核态并绑定到 vfio-pci ==="
ip link set "${NIC}" down 2>/dev/null || true
dpdk-devbind.py --bind=vfio-pci "${PCI}"

echo "=== [5/5] 关闭 firewalld ==="
systemctl stop firewalld 2>/dev/null || true

echo ""
echo "✓ 环境就绪"
dpdk-devbind.py --status | grep "${PCI}"