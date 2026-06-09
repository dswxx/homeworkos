# Makefile —— 接收端 (DPDK 23.11, 动态链接)
# 运行时用 -d 加载 mempool ring 和 e1000 插件
# 用法:  make        编译
#        make run    运行
#        make clean  清理

APP  = recv_stack
SRCS = recv_stack.c

PKGCONF ?= pkg-config

ifneq ($(shell $(PKGCONF) --exists libdpdk && echo yes),yes)
$(error 找不到 libdpdk。请设置:export PKG_CONFIG_PATH=/usr/lib64/pkgconfig:$$PKG_CONFIG_PATH)
endif

CFLAGS += -O3 -Wall $(shell $(PKGCONF) --cflags libdpdk)
LDLIBS += $(shell $(PKGCONF) --libs libdpdk)

$(APP): $(SRCS) cproto.h
	$(CC) $(CFLAGS) $(SRCS) -o $(APP) $(LDLIBS)

run: $(APP)
	./$(APP) -l 0,1 -n 4 --iova-mode=pa \
		-d /usr/lib64/librte_mempool_ring.so \
		-d /usr/lib64/librte_net_e1000.so

clean:
	rm -f $(APP)

.PHONY: run clean
