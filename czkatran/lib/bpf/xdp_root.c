#include <bpf/bpf.h>
#include <bpf/bpf_helpers.h>

#define ROOT_PROG_SIZE 3

//管理员程序
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, ROOT_PROG_SIZE);
    __type(key, __u32);
    __type(value, __u32);
} root_array SEC(".maps");


SEC("xdp")
int xdp_root(struct xdp_md *ctx) {
    __u32* fd;
#pragma clang loop unroll(full)
    for(__u32 i = 0; i < ROOT_PROG_SIZE; i++) {
        bpf_tail_call(ctx, &root_array, i);
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";