#ifndef __PACKET_ENCAP_H__
#define __PACKET_ENCAP_H__

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <string.h>

#include <bpf/bpf.h>
#include <bpf/bpf_helpers.h>
#include "czkatran/lib/bpf/balancer_consts.h"
#include "czkatran/lib/bpf/balancer_structs.h"







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
                                    bool *isnner_ipv4) {
    struct ethhdr *eth_new;
    struct ethhdr *eth_old;
    eth_old = (struct ethhdr *) *data;
    eth_new = (struct ethhdr *)*data + sizeof(struct ipv6hdr);
    memcpy(eth_new->h_source, eth_old->h_source, sizeof(eth_new->h_source));
    memcpy(eth_new->h_dest, eth_old->h_dest, sizeof(eth_new->h_dest));
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
    eth_old = (struct ethhdr *)(*data);
    eth_new = (struct ethhdr *)(*data + sizeof(struct iphdr));
    memcpy(eth_new->h_source, eth_old->h_source, sizeof(eth_new->h_source));
    memcpy(eth_new->h_dest, eth_old->h_dest, sizeof(eth_new->h_dest));
    eth_new->h_proto = BE_ETH_P_IP;

    if(XDP_ADJUST_HEAD_FUNC(xdp, int(sizeof(struct iphdr)))) {
        return false;
    }

    *data = (void *)(long)xdp->data;
    *data_end = (void *)(long)xdp->data_end;
    return true;
}





#endif

