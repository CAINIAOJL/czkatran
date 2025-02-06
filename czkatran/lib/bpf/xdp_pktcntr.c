#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/if_tunnel.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf.h>
#include <bpf/bpf_helpers.h>

//ctrl cntrs
#define CTRL_ARRAY_SIZE 2
#define CNTRS_ARRAY_SIZe 512

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CTRL_ARRAY_SIZE);
    __type(key, __u32);
    __type(value, __u32);
} ctl_array SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, CNTRS_ARRAY_SIZe);
    __type(key, __u32);
    __type(value, __u64);
} cntrs_array SEC(".maps");

SEC("xdp")
int pktcntr(struct xdp_md* ctx) {
    void* data = (void*)(long)(ctx->data);
    void* data_end = (void*)(long)(ctx->data_end);

    __u32 ctl_flag_pos = 0;
    __u32 cntrs_flag_pos = 0;
    __u32* flag = bpf_map_lookup_elem(&ctl_array, &ctl_flag_pos);

    if(!flag || *flag == 0) {
        return XDP_PASS;
    }

    __u64* cntr_val = bpf_map_lookup_elem(&cntrs_array, &cntrs_flag_pos);
    if(cntr_val) {
        *cntr_val += 1; //percpu_array 不用原子操作
    }
    return XDP_PASS;

}

char _license[] SEC("license") = "GPL";