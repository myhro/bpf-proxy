#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u16);
    __type(value, u8);
} ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} socket SEC(".maps");

SEC("sk_lookup")
int proxy(struct bpf_sk_lookup *ctx) {
    struct bpf_sock *sk;
    int err;

    u16 port = ctx->local_port;
    void *p = bpf_map_lookup_elem(&ports, &port);
    if (p == NULL) {
        return SK_PASS;
    }

    u32 zero = 0;
    sk = bpf_map_lookup_elem(&socket, &zero);
    if (sk == NULL) {
        return SK_DROP;
    }

    err = bpf_sk_assign(ctx, sk, 0);
    bpf_sk_release(sk);
    if (err) {
        return SK_DROP;
    }

    return SK_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
