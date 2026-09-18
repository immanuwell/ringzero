CLANG      ?= clang
BPFTOOL    ?= bpftool
ARCH       := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

BPF_SRC    := bpf/xdp_lb.c
BPF_OBJ    := bpf/xdp_lb.o
PASS_SRC   := bpf/xdp_pass.c
PASS_OBJ   := bpf/xdp_pass.o
VMLINUX_H  := bpf/vmlinux.h

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -I bpf -I /usr/include/$(shell uname -m)-linux-gnu \
              -Wall -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types

.PHONY: all bpf zig bench clean vmlinux

# A failed bpftool still leaves the shell-created, empty vmlinux.h behind.
.DELETE_ON_ERROR:

all: bpf zig bench

$(VMLINUX_H):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

vmlinux: $(VMLINUX_H)

bpf: $(VMLINUX_H) $(BPF_OBJ) $(PASS_OBJ)

$(BPF_OBJ): $(BPF_SRC) bpf/common.h $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "built $(BPF_OBJ)"

$(PASS_OBJ): $(PASS_SRC) $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $(PASS_SRC) -o $(PASS_OBJ)
	@echo "built $(PASS_OBJ)"

zig:
	zig build -Doptimize=ReleaseFast

bench:
	$(CC) -O2 -Wall -pthread bench/floodgen.c -o bench/floodgen

clean:
	rm -f $(BPF_OBJ) $(PASS_OBJ) $(VMLINUX_H) bench/floodgen
	rm -rf zig-out .zig-cache
