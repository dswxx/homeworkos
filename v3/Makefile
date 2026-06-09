# Makefile —— v3 接收端/发送端
# 用法:
#   make          编译 DPDK 接收端
#   make run      运行 DPDK 接收端
#   make sender   在发送端机器上编译 C++ sender
#   make clean    清理产物

APP    = recv_stack
SRCS   = recv_stack.c
SENDER = sender

CC      ?= cc
CXX     ?= g++
PKGCONF ?= pkg-config

DPDK_CFLAGS = $(shell $(PKGCONF) --cflags libdpdk 2>/dev/null)
DPDK_LIBS   = $(shell $(PKGCONF) --libs libdpdk 2>/dev/null)

CFLAGS   += -O3 -Wall $(DPDK_CFLAGS)
LDLIBS   += $(DPDK_LIBS)
CXXFLAGS += -O2 -std=c++17 -Wall -Wextra

$(APP): $(SRCS) cproto.h
	@$(PKGCONF) --exists libdpdk || \
		(echo "找不到 libdpdk。请设置: export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:\$$PKG_CONFIG_PATH"; exit 1)
	$(CC) $(CFLAGS) $(SRCS) -o $(APP) $(LDLIBS)

sender: sender.cpp cproto.h
	$(CXX) $(CXXFLAGS) sender.cpp -o $(SENDER)

run: $(APP)
	./$(APP) -l 0,1 -n 4 --iova-mode=pa \
		-d /usr/lib64/librte_mempool_ring.so \
		-d /usr/lib64/librte_net_e1000.so

clean:
	rm -f $(APP) $(SENDER)

.PHONY: run sender clean
