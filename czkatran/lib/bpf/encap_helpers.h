#pragma once
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <string.h>


#include "balancer_consts.h"
#include "balancer_structs.h"
#include "csum_helpers.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

//~
__always_inline static void create_encap_ipv6_src(
    __u16 port, __be32 src, __u32* saddr
)
{
    saddr[0] = IPIP_V6_PREFIX1;
    saddr[1] = IPIP_V6_PREFIX2;
    saddr[2] = IPIP_V6_PREFIX3;
    saddr[3] = src ^ port;
}

//~
__always_inline static __u32 create_encap_ipv4_src(
    __u16 port,
    __be32 src
)
{
    __u32 ip_suffix = bpf_htons(port);
    ip_suffix <<= 10;
    ip_suffix ^= src;
    return ((0xFFFF0000 & ip_suffix) | IPIP_V4_PREFIX);
}

//~
__always_inline static void create_v4_hdr(
    struct iphdr* ip_hdr,
    __u8 tos,
    __u32 saddr,
    __u32 daddr,
    __u16 palyload_len,
    __u8 proto
)
{
    __u64 csum = 0;
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->frag_off = 0;//意味着不是分片的数据包
    ip_hdr->protocol = proto;
    ip_hdr->check = 0;//校验和

#ifdef COPY_INNER_PACKET_TOS
    ip_hdr->tos = tos;
#else   
    ip_hdr->tos = DEFAULT_TOS;
#endif
    ip_hdr->tot_len = bpf_htons(palyload_len + sizeof(struct iphdr)); //tot_len是头部长度加上负载量
    ip_hdr->id = 0;
    ip_hdr->saddr = saddr;
    ip_hdr->daddr = daddr;
    ip_hdr->ttl = DEFAULT_TTL;
    ipv4_csum_inline(ip_hdr, &csum);
    ip_hdr->check = csum;
}

//~
__always_inline static void create_v6_hdr(
    struct ipv6hdr* ip6_hdr,
    __u8 tos,
    __u32* saddr,
    __u32* daddr,
    __u16 palyload_len,
    __u8 proto
)
{
    ip6_hdr->version = 6;
    memset(ip6_hdr->flow_lbl, 0, sizeof(ip6_hdr->flow_lbl));

#ifdef COPY_INNER_PACKET_TOS
    ip6_hdr->priority = (tos & 0xF0) >> 4;
    ip6_hdr->flow_lbl[0] = (tos & 0x0F) << 4;
#else
    ip6_hdr->priority = DEFAULT_TOS;
#endif
    ip6_hdr->nexthdr = proto;
    ip6_hdr->payload_len = bpf_htons(palyload_len);
    memcpy(ip6_hdr->saddr.s6_addr32, saddr, 16);
    memcpy(ip6_hdr->daddr.s6_addr32, daddr, 16);
}