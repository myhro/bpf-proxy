ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BINARY := proxy
BPF_OBJ := proxy.bpf.o
SKEL := proxy.skel.h

.PHONY: $(BINARY) $(BPF_OBJ) $(SKEL)

clean:
	rm -f $(BINARY) $(BPF_OBJ) $(SKEL) vmlinux.h

proxy: $(SKEL)
	gcc -Wall proxy.c -o $(BINARY) -lbpf

proxy.bpf.o: vmlinux.h
	clang -target bpf \
		-D __TARGET_ARCH_$(ARCH) \
		-I /usr/include/$(shell uname -m)-linux-gnu/ \
		-g -O2 -c proxy.bpf.c -o $(BPF_OBJ)
	llvm-strip-14 -g $(BPF_OBJ)

proxy.skel.h: $(BPF_OBJ)
	bpftool gen skeleton $(BPF_OBJ) > $(SKEL)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
