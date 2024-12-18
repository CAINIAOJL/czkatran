#ifndef __PACKET_PARSE_H__
#define __PACKET_PARSE_H__

#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/ip.h>
#include <bpf/bpf.h>
#include "czkatran/lib/bpf/balancer_consts.h"
#include "czkatran/lib/bpf/balancer_structs.h"

/**
 * @brief 计算报文的偏移量
 * @param is_ipv6 是否是ipv6报文
 * @param is_icmp 是否是icmp报文
 * @return 偏移量~
 */
__always_inline static __u64 calc_offset(bool is_ipv6,
                                        bool is_icmp) {
    __u64 off = sizeof(struct ethhdr);
    if(is_ipv6) {
        off += sizeof(struct ipv6hdr);
        if(is_icmp) {
            off += (sizeof(struct icmp6hdr) + sizeof(struct ipv6hdr));
        }
    } else {
        off += sizeof(struct iphdr);
        if(is_icmp) {
            off += (sizeof(struct icmphdr) + sizeof(struct iphdr));
        }
    }
    return off;
}

/**
 * @brief 解析udp报文
 * @param data 报文数据
 * @param data_end 报文数据结束位置
 * @param is_ipv6 是否是ipv6报文
 * @param packet 解析结果
 * @return 是否解析成功~
 */
__always_inline static bool parse_udp(void *data,
                                      void *data_end,
                                      bool is_ipv6,
                                      struct packet_description *packet) {
    bool is_icmp = !((packet->flags & F_ICMP) == 0); //是否是icmp报文
    __u64 off = calc_offset(is_ipv6, is_icmp); 
    struct udphdr* udp;
    udp = (struct udphdr*)data + off;
    if(udp + 1 > data_end) {
        return false;
    }
    //source dest port 转换                                 
    if(!is_icmp) {
        packet->flow.port16[0] = udp->source;
        packet->flow.port16[1] = udp->dest;
    } else {
        packet->flow.port16[0] = udp->dest;
        packet->flow.port16[1] = udp->source;
    }
    return true;
}

//~
__always_inline static bool parse_tcp(void *data,
                                      void *data_end,
                                      bool is_ipv6,
                                      struct packet_description *packet) {

    bool is_icmp = !((packet->flags & F_ICMP) == 0); //是否是icmp报文
    __u64 off = calc_offset(is_ipv6, is_icmp);
    struct tcphdr *tcp;
    tcp = (struct tcphdr *)(data + off);
    if(tcp + 1 > data_end) {
        return false;
    }

    if(tcp->syn) {
        packet->flags |= F_SYN_SET;
    }
    if(!is_icmp) {
        packet->flow.port16[0] = tcp->source;
        packet->flow.port16[1] = tcp->dest;
    } else {
        packet->flow.port16[0] = tcp->dest;
        packet->flow.port16[1] = tcp->source;
    }

    return true;
}




#endif