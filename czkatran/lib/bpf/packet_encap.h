#pragma once

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <string.h>


#include "balancer_consts.h"
#include "balancer_structs.h"
#include "encap_helpers.h"


#include <bpf/bpf_helpers.h>
//~
//默认使用 [ip(6?)ip6] = ipip隧道技术
__always_inline static bool encap_v6(
    struct xdp_md* ctx,
    struct ctl_value* cval,
    bool is_ipv6,
    struct packet_description* pkt,
    struct real_definition* dst,
    __u32 pkt_bytes
)
{
    void* data;
    void* data_end;
    struct ipv6hdr* ip6_hdr;
    struct ethhdr* new_eth;
    struct ethhdr* old_eth;
    __u16 payload_len;
    __u32 saddr[4];
    __u8 proto;

    //向前扩张sizeof(struct ipv6hdr)大小
    if(XDP_ADJUST_HEAD_FUNC(ctx, 0 - (int)sizeof(struct  ipv6hdr))) {
        return false;
    }
    data = (void*)(long)ctx->data;
    data_end = (void*)(long)ctx->data_end;
    new_eth = data; //(struct ethhdr*)data
    old_eth = data + sizeof(struct ipv6hdr);//(struct ethhdr*)(data + sizeof(struct ipv6hdr))
    ip6_hdr = data + sizeof(struct ethhdr);//(struct ipv6hdr*)(data + sizeof(struct ethhdr))

    if(new_eth + 1 > data_end || old_eth + 1 > data_end || ip6_hdr + 1 > data_end) {
        return false; //调整失败
    }
    
    //构建mac帧
    memcpy(new_eth->h_dest, cval->mac, 6);
    memcpy(new_eth->h_source, old_eth->h_dest, 6);

    new_eth->h_proto = BE_ETH_P_IPV6;

    //构建outer_ipv6的原IP地址
    if(is_ipv6) {
        proto = IPPROTO_IPV6; 
        create_encap_ipv6_src(pkt->flow.port16[0], pkt->flow.srcv6[3], saddr);
        payload_len = pkt_bytes + sizeof(struct ipv6hdr);
    } else {
        proto = IPPROTO_IPIP;
        create_encap_ipv6_src(pkt->flow.port16[0], pkt->flow.src, saddr);
        payload_len = pkt_bytes;
    }

    create_v6_hdr(ip6_hdr, pkt->tos, saddr, dst->dstv6, payload_len, proto);
    return true;
}

//~
//ipip encap
__always_inline static bool encap_v4(
    struct xdp_md* ctx,
    struct ctl_value* cval,
    bool is_ipv6,
    struct packet_description* pkt,
    struct real_definition* dst,
    __u32 pkt_bytes
)
{
    void* data;
    void* data_end;
    struct iphdr* ip_hdr;
    struct ethhdr* new_eth, *old_eth;

    if(XDP_ADJUST_HEAD_FUNC(ctx, 0 - (int)sizeof(struct iphdr))) {
        return false;
    }

    data = (void*)(long)ctx->data;
    data_end = (void*)(long)ctx->data_end;
    new_eth = (struct ethhdr*)data;
    old_eth = (struct ethhdr*)(data + sizeof(struct iphdr));
    ip_hdr = (struct iphdr*)(data + sizeof(struct ethhdr));
    
    if(new_eth + 1 > data_end || old_eth + 1 > data_end || ip_hdr + 1 > data_end) {
        return false;
    }

    memcpy(new_eth->h_dest, cval->mac, 6);
    memcpy(new_eth->h_source, old_eth->h_dest, 6);
    new_eth->h_proto = BE_ETH_P_IP;

    //私网ip
    __u32 ip_src = create_encap_ipv4_src(pkt->flow.port16[0], pkt->flow.src);
    create_v4_hdr(ip_hdr, pkt->tos, ip_src, dst->dst, pkt_bytes, IPPROTO_IPIP);

    return true;
}




/**
 * @brief 修改了data，与data_end指针指向的位置 ~
 * @param xdp xdp_md结构体
 * @param data 指向数据包的指针
 * @param data_end 指向数据包尾部的指针 
 * @param isnner_ipv4 是否为内层IPv4协议
 * @return true 修改成功，false 修改失败
 */
__always_inline static bool decap_v6(struct xdp_md *xdp,
                                    void **data,
                                    void **data_end,
                                    bool isnner_ipv4) {
    struct ethhdr *eth_new;
    struct ethhdr *eth_old;
    eth_old = *data;
    eth_new = *data + sizeof(struct ipv6hdr);
    memcpy(eth_new->h_source, eth_old->h_source, 6);
    memcpy(eth_new->h_dest, eth_old->h_dest, 6);
    if(isnner_ipv4) {
        eth_new->h_proto = BE_ETH_P_IP;
    } else {
        eth_new->h_proto = BE_ETH_P_IPV6;
    }

    if(XDP_ADJUST_HEAD_FUNC(xdp, (int)(sizeof(struct ipv6hdr)))) {
        return false; 
    }
    *data = (void *)(long)xdp->data;
    *data_end = (void *)(long)xdp->data_end;
    return true;
}


/**
 * @brief 修改了data，与data_end指针指向的位置 ~
 * @param xdp xdp_md结构体
 * @param data 指向数据包的指针
 * @param data_end 指向数据包尾部的指针 
 * @return true 修改成功，false 修改失败
 */
__always_inline static bool decap_v4(struct xdp_md *xdp,
                                     void **data,
                                     void **data_end) {
    struct ethhdr *eth_new;
    struct ethhdr *eth_old;
    eth_old = *data;
    eth_new = *data + sizeof(struct iphdr);
    memcpy(eth_new->h_source, eth_old->h_source, 6);
    memcpy(eth_new->h_dest, eth_old->h_dest, 6);
    eth_new->h_proto = BE_ETH_P_IP;

    if(XDP_ADJUST_HEAD_FUNC(xdp, sizeof(struct iphdr))) {
        return false;
    }

    *data = (void *)(long)xdp->data;
    *data_end = (void *)(long)xdp->data_end;
    return true;
}


#ifdef INLINE_DECAP_GUE //inline_decap_gue
//~
__always_inline static bool gue_decap_v4(struct xdp_md *xdp, void **data, void **data_end) {
    struct ethhdr *eth_new;
    struct ethhdr *eth_old;
    eth_old = (struct ethhdr *)(*data);
    eth_new = (struct ethhdr *)(*data + sizeof(struct iphdr) + sizeof(struct udphdr));
    //RECORD_GUE_ROUTE(eth_old, eth_new, *data_end, true, true);//?
    memcpy(eth_new->h_source, eth_old->h_source, sizeof(eth_new->h_source));
    memcpy(eth_new->h_dest, eth_old->h_dest, sizeof(eth_new->h_dest));
    eth_new->h_proto = BE_ETH_P_IP;
    if(XDP_ADJUST_HEAD_FUNC(xdp, sizeof(struct iphdr) + sizeof(struct udphdr))) {
        return false;
    }

    *data = (void *)(long)xdp->data;
    *data_end = (void *)(long)xdp->data_end;
    return true;
}

//~
__always_inline static bool gue_decap_v6(struct xdp_md *xdp, void **data, void **data_end bool inner_v4) {
    struct ethhdr *eth_new;
    struct ethhdr *eth_old;
    eth_old = (struct ethhdr *)(*data);
    eth_new = (struct ethhdr *)(*data + sizeof(struct ipv6hdr) + sizeof(udphdr));
    //RECORD_GUE_ROUTE(eth_old, eth_new, *data_end, true, false);//?
    memcpy(eth_new->h_source, eth_old->h_source, sizeof(eth_new->h_source));
    memcpy(eth_new->h_dest, eth_old->h_dest, sizeof(eth_new->h_dest));
    eth_new->proto = inner_v4 ? BE_ETH_P_IP : BE_ETH_P_IPV6;
    if(XDP_ADJUST_HEAD_FUNC(xdp, sizeof(struct ipv6hdr) + sizeof(udphdr))) {
        return false;
    }
    *data = (void *)(long)xdp->data;
    *data_end = (void *)(long)xdp->data_end;
    return true;
}
#endif //INLINE_DECAP_GUE



