#include <bpf/balancer_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#define TC_ACT_SHOT 2
#define TC_ACT_OK 0
 
#define ETH_P_IP 0x0800
 
// 定义key
struct ipv4_lpm_key {
    __u32 prefixlen;
    __u32 data;
};
 
// 定义lpm map
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct ipv4_lpm_key);
    __type(value, __u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(max_entries, 255);
    // 本地持久化map
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ipv4_lpm_map SEC(".maps");
 
struct ipv4_lpm_key *unused_ipv4_lpm_key __attribute__((unused));
 
char __license[] SEC("license") = "Dual MIT/GPL";
 
SEC("tc")
int tc_deny_icmp(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
 
    struct ethhdr *eth_hdr = data;
    if ((void *)eth_hdr + sizeof(*eth_hdr) > data_end || eth_hdr->h_proto != bpf_htons(ETH_P_IP)) {
        return TC_ACT_OK;
    }
 
    struct iphdr *ip_hdr = (void *)eth_hdr + sizeof(*eth_hdr);
    if ((void *)ip_hdr + sizeof(*ip_hdr) > data_end) {
        return TC_ACT_OK;
    }
 
    if (ip_hdr->protocol == IPPROTO_ICMP) {
        struct ipv4_lpm_key key = {
            .prefixlen = 32,
            .data = ip_hdr->daddr
        };
 
        if (!bpf_map_lookup_elem(&ipv4_lpm_map, &key)) {
            return TC_ACT_SHOT;
        }
    }
 
    return TC_ACT_OK;
}