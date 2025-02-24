#pragma once

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>

#include <bpf/bpf_helpers.h>
#include "/home/cainiao/czkatran/czkatran/lib/linux_includes/bpf.h"

#include "encap_helpers.h"

#include "healthchecking.maps.h"
#include "healthchecking_structs.h"

//~
__always_inline static bool set_hc_key(
    const struct __sk_buff* skb,
    struct hc_key* hckey,
    bool is_ipv6
)
{
    void* iphdr = (void*)(long)skb->data + sizeof(struct ethhdr);
    void* transport_hdr;
    
    if(is_ipv6) {
        struct ipv6hdr* ip6hdr = (struct ipv6hdr*)(iphdr);
        if(ip6hdr + 1 > (void*)(long)skb->data_end) {
            return false;
        }
        transport_hdr = iphdr + sizeof(struct ipv6hdr);
        memcpy(hckey->addrv6, ip6hdr->daddr.s6_addr32, 16);
        hckey->proto = ip6hdr->nexthdr;
    } else {
        struct iphdr* iph = (struct iphdr*)(iphdr);
        if(iph + 1 > (void*)(long)skb->data_end) {
            return false;
        }
        transport_hdr = iphdr + sizeof(struct iphdr);
        hckey->addr = iph->daddr;
        hckey->proto = iph->protocol;

    }

    if(hckey->proto == IPPROTO_TCP) {
        struct tcphdr* tcph = (struct tcphdr*)(transport_hdr);
        if(tcph + 1 > (void*)(long)skb->data_end) {
            return false;
        }
        hckey->port = tcph->dest;
    } else if (hckey->proto == IPPROTO_UDP) {
        struct udphdr* udph = (struct udphdr*)(transport_hdr);
        if(udph + 1 > (void*)(long)skb->data_end) {
            return false;
        }
        hckey->port = udph->dest;
    } else {
        return false;
    }
    return true;
}

//~
__always_inline static bool hc_encap_ipip(
    struct __sk_buff* skb,
    struct hc_real_definition* real,
    struct ethhdr* eth,
    bool is_ipv6
)
{
    struct hc_real_definition* src;
    __u64 flags = 0;
    __u16 pkt_len;
    int adjust_len = 0;
    __u32 key;

    pkt_len = skb->len - sizeof(struct ethhdr);

    if(real->flags == V6DADDR) {
        __u8 proto = IPPROTO_IPV6;
        key = V6_SRC_INDEX;
        src = bpf_map_lookup_elem(&hc_pckt_srcs_map, &key);
        if(!src) {
            return false;
        }
        //fixed_gso encap_l3_ipv6
        //标志：不要gso分片，encap在ip前
        flags |= BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV6;
        adjust_len = sizeof(struct ipv6hdr);
        //将新的header插入在mac帧于IP帧之间
        if(bpf_skb_adjust_room(skb, adjust_len, BPF_ADJ_ROOM_MAC, flags)) {
            return false;
        }

        if((skb->data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) > skb->data_end) {
            return false;
        }

        eth = (void*)(long)skb->data;
        eth->h_proto = BE_ETH_P_IPV6;

        struct ipv6hdr* ip6h = (void*)(long)skb->data + sizeof(struct ethhdr);
        if(!is_ipv6) {
            proto = IPPROTO_IPIP;
        }
        __u32 saddr[4];
// //mangle hc src
#ifdef MANGLE_HC_SRC
        create_encap_ipv6_src(MANGLED_HC_SRC_PORT, src->addrv6[3], saddr);
#else
        memcpy(saddr, src->addrv6, 16);
#endif
        create_v6_hdr(ip6h, DEFAULT_TOS, saddr, real->addrv6, pkt_len, proto);
    } else {
        key = V4_SRC_INDEX;
        src = bpf_map_lookup_elem(&hc_pckt_srcs_map, &key);
        if(!src) {
            return false;
        }
        flags |= BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4;
        adjust_len = sizeof(struct iphdr);
        if(bpf_skb_adjust_room(skb, adjust_len, BPF_ADJ_ROOM_MAC, flags)) {
            return false;
        }
        if((skb->data + sizeof(struct ethhdr) + sizeof(struct iphdr)) > skb->data_end) {
            return false;
        }
        struct iphdr* iph = (void*)(long)skb->data + sizeof(struct ethhdr);
#ifdef MANGLE_HC_SEC
        __u32 ip_src = create_encap_ipv4_src(MANGLED_HC_SRC_PORT, src->addr);
#else
        __u32 ip_src = src->addr;
#endif

        create_v4_hdr(iph, DEFAULT_TOS, ip_src, real->addr, pkt_len, IPPROTO_IPIP);
    }
    return true;
}