#pragma once

#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stddef.h>


#include "balancer_maps.h"
#include "csum_helpers.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


/*
ICMP消息头中的校验和字段是
通过计算消息头（包括类型和代码字段）和数据部分的每个16位字的和，
然后将这个和的反码（即，所有位取反后加1）
作为校验和值来设置的。
这个计算过程确保了如果消息中的任何位被改变，
校验和将不再匹配，
从而可以检测到错误。
*/
/*
在调整ICMP消息的校验和时，选择减去而不是加上一个值，
是因为我们想要反映消息中某个字段（在这种情况下是类型字段）的减少。
由于ICMP Echo请求的类型值是128，而ICMP Echo回复的类型值是129，
从Echo请求转换为Echo回复实际上是将类型值增加了1。
但是，当我们调整校验和时，我们并不是直接对类型值进行操作，
而是对已经计算好的校验和进行调整，以反映类型值变化对整体校验和的影响。
校验和是通过将消息的所有字节加在一起（通常是以16位为单位），
然后对结果取反得到的。
因此，如果消息中的某个字节发生了变化（在这个例子中是类型字节从128变为129），
那么校验和也会相应地发生变化。由于我们是从一个较小的值（128）变为一个较大的值（129），
这意味着在二进制表示中，至少有一个位从0变为了1（在这个特定的例子中，是最低有效位从0变为1）。
这个变化会导致整个消息的加和结果增加，
因此，为了保持校验和的有效性，我们需要从现有的校验和中减去一个值来抵消这个增加。
*/

//~
__attribute__((__always_inline__)) static inline int swap_mac_and_send(//---------------√
    void* data,
    void* data_end
)
{
    struct ethhdr* ethhdr = data;
    unsigned char temp_mac[ETH_ALEN];
    memcpy(temp_mac, ethhdr->h_dest, ETH_ALEN);
    memcpy(ethhdr->h_dest, ethhdr->h_source, ETH_ALEN);
    memcpy(ethhdr->h_source, temp_mac, ETH_ALEN);
    return XDP_TX;//转发出去
}

//~
__attribute__((__always_inline__)) static inline void swap_mac(//---------------√
    void* data,
    struct ethhdr* orig_eth
) {
    struct ethhdr* eth_hdr;
    eth_hdr = data;
    memcpy(eth_hdr->h_source, orig_eth->h_dest, ETH_ALEN);
    memcpy(eth_hdr->h_dest, orig_eth->h_source, ETH_ALEN);

    eth_hdr->h_proto = orig_eth->h_proto;
}

//发送icmp报文~
__attribute__((__always_inline__)) static inline int send_icmp_reply(//---------------√
    void* data,
    void* data_end
) {
    struct iphdr* ip_hdr;
    struct icmphdr* icmp_hdr;
    __u64 off = 0; //位移
    __u64 csum = 0;//校验和
    __u32 tmp_addr = 0;    

    if((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr)) > data_end) {
        return XDP_DROP;
    }

    off += sizeof(struct ethhdr);
    ip_hdr = data + off;
    off += sizeof(struct iphdr);
    icmp_hdr = data + off;
    icmp_hdr->type = ICMP_ECHOREPLY;//回应
    /*
    ICMP Echo 和 Reply HDR 之间的唯一区别是类型;
    在第一种情况下，它是 8;其次是 0;
    因此，我们不会从头开始重新计算校验和，而是调整它。
    */
   icmp_hdr->checksum += 0x0008;
   ip_hdr->ttl = DEFAULT_TTL;
   //交换ip源地址目的地址
   tmp_addr = ip_hdr->daddr;
   ip_hdr->daddr = ip_hdr->saddr;
   ip_hdr->saddr = tmp_addr;
   ip_hdr->check = 0;
   ipv4_csum_inline(ip_hdr, &csum);
   ip_hdr->check = csum;//填充校验和

    return swap_mac_and_send(data, data_end);
}


//~
__attribute__((__always_inline__)) static inline int//---------------√
    parse_icmp(
    void* data,
    void* data_end,
    __u64 nh_off,
    struct packet_description* pckt
){
    struct icmphdr* icmp_hdr;
    struct iphdr* ip_hdr;
    icmp_hdr = data + nh_off;

    if(icmp_hdr + 1 > data_end) {
        return XDP_DROP;
    }
    if(icmp_hdr->type == ICMP_ECHO) {
        return send_icmp_reply(data, data_end); //发送icmp回应
    }
    if(icmp_hdr->type != ICMP_DEST_UNREACH) {
        return XDP_PASS;
    }
    if(icmp_hdr->code == ICMP_FRAG_NEEDED) {
        //需要分片
        __u32 stats_key = MAX_VIPS + ICMP_PTB_V4_STATS;
        struct lb_stats* stats_ = bpf_map_lookup_elem(&stats, &stats_key);
        if(!stats_) {
            return XDP_DROP;
        }
        stats_->v1 += 1;
        __u16 pmtu = bpf_ntohs(icmp_hdr->un.frag.mtu);
        if(pmtu < MAX_MTU_IN_PTB_TO_DROP) {
            stats_->v2 += 1;
        }
    }

    //不清楚为什么要这么做
    nh_off += sizeof(struct icmphdr);
    ip_hdr = data + nh_off;

    if(ip_hdr + 1 > data_end) {
        return XDP_DROP;
    }

    if(ip_hdr->ihl != 5) {
        return XDP_DROP;
    }

    pckt->flow.proto = ip_hdr->protocol;
    pckt->flags |= F_ICMP;
    pckt->flow.src = ip_hdr->daddr;
    pckt->flow.dst = ip_hdr->saddr;
    return FURTHER_PROCESSING;
}

//~
__attribute__((__always_inline__)) static inline int 
    send_icmp6_reply(//---------------√
    void* data,
    void* data_end 
)
{
    struct ipv6hdr* ip6_hdr;
    struct icmp6hdr* icmp6_hdr;
    __be32 tmp_addr[4];//128位
    __u64 off = 0;
    if((data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr)) > data_end) {
        return XDP_DROP;
    }

    off += sizeof(struct ethhdr);
    ip6_hdr = data + off;
    off += sizeof(struct ipv6hdr);
    icmp6_hdr = data + off;
    icmp6_hdr->icmp6_type = ICMPV6_ECHO_REPLY;
    /*
    ICMP Echo 和 Reply HDR 之间的唯一区别是类型;
    在第一种情况下，它是 128;第二名是 129 分;
    因此，我们不会从头开始重新计算校验和，而是调整它。
    */
    icmp6_hdr->icmp6_cksum -= 0x0001;
    ip6_hdr->hop_limit = DEFAULT_TTL;
    memcpy(tmp_addr, ip6_hdr->saddr.s6_addr32, 16);
    memcpy(ip6_hdr->saddr.s6_addr32, ip6_hdr->daddr.s6_addr32, 16);
    memcpy(ip6_hdr->daddr.s6_addr32, tmp_addr, 16);
    return swap_mac_and_send(data, data_end);
}

//~
__attribute__((__always_inline__)) static inline int send_icm6_too_big(//---------------√
    struct xdp_md* ctx
)
{
    int headroom = (int)sizeof(struct ipv6hdr) + (int)sizeof(struct icmp6hdr);
    if(XDP_ADJUST_HEAD_FUNC(ctx, 0 - headroom)) {
        return XDP_DROP;
    }

    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    if(data + (ICMP6_TOOBIG_SIZE + headroom) > data_end) {
        return XDP_DROP;
    }

    struct ipv6hdr* ipv6_hdr, *orig_ipv6_hdr;
    struct ethhdr* orig_eth_hdr;
    struct icmp6hdr* icmp6_hdr;

    __u64 csum = 0;//校验和
    __u64 off = 0;

    //需要一张图片帮助理解：理解关键在于指针的移动，并非数据包真正的改变    
    //l2层
    orig_eth_hdr = data + headroom;
    swap_mac(data, orig_eth_hdr);

    off += sizeof(struct ethhdr);
    ipv6_hdr = data + off;
    off += sizeof(struct ipv6hdr);
    icmp6_hdr = data + off;
    off += sizeof(struct icmp6hdr);
    orig_ipv6_hdr = data + off;
    
    //l3层
    ipv6_hdr->version = 6;
    ipv6_hdr->priority = 0;
    ipv6_hdr->nexthdr = IPPROTO_ICMPV6;//后面跟着icmp6 header
    ipv6_hdr->hop_limit = DEFAULT_TTL; //默认跳数
    ipv6_hdr->payload_len = bpf_htons(ICMP6_TOOBIG_PAYLOAD_SIZE);
    memset(ipv6_hdr->flow_lbl, 0, sizeof(ipv6_hdr->flow_lbl));
    memcpy(ipv6_hdr->daddr.s6_addr32, orig_ipv6_hdr->saddr.s6_addr32, 16);
    memcpy(ipv6_hdr->saddr.s6_addr32, orig_ipv6_hdr->daddr.s6_addr32, 16);

    icmp6_hdr->icmp6_type = ICMPV6_PKT_TOOBIG;
    icmp6_hdr->icmp6_code = 0;
    icmp6_hdr->icmp6_mtu = bpf_htonl(MAX_PCKT_SIZE - sizeof(struct ethhdr)); //说白了1500字节
    icmp6_hdr->icmp6_cksum = 0;

    ipv6_csum(icmp6_hdr, ICMP6_TOOBIG_PAYLOAD_SIZE, &csum, ipv6_hdr);
    icmp6_hdr->icmp6_cksum = csum;
    return XDP_TX; //发送icmp数据包
}

//~
__attribute__((__always_inline__)) static inline int //---------------√
 send_icm_too_big(
    struct xdp_md* ctx
) {
    int headroom = (int)sizeof(struct iphdr) + (int)sizeof(struct icmphdr);
    //增长头部
    if(XDP_ADJUST_HEAD_FUNC(ctx, 0 - headroom)) {
        return XDP_DROP;
    }
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    if(data + (headroom + ICMP_TOOBIG_SIZE) > data_end) {
        return XDP_DROP;
    }

    struct iphdr* orig_ip_hdr, *ip_hdr;
    struct icmphdr* icmp_hdr;
    struct ethhdr* orig_eth_hdr;

    __u64 csum = 0;
    __u64 off = 0;

    //l2层
    orig_eth_hdr = data + headroom;
    swap_mac(data, orig_eth_hdr);

    off += sizeof(struct ethhdr);
    ip_hdr = data + off;
    off += sizeof(struct iphdr);
    icmp_hdr = data + off;
    off += sizeof(struct icmphdr);
    orig_ip_hdr = data + off;

    //l3层
    icmp_hdr->type = ICMP_DEST_UNREACH; //无法到达dst
    icmp_hdr->code = ICMP_FRAG_NEEDED; //icmp返回信息需要分片数据包，
    //icmp_hdr->icmp6_mtu = bpf_htons(ICMP_TOOBIG_SIZE - sizeof(struct ethhdr)); //1500字节
    icmp_hdr->un.frag.mtu = bpf_htons(ICMP_TOOBIG_SIZE - sizeof(struct ethhdr)); //1500字节
    icmp_hdr->un.frag.__unused = 0;
    icmp_hdr->checksum = 0;
    ipv4_csum(icmp_hdr, ICMP_TOOBIG_PAYLOAD_SIZE, &csum);
    icmp_hdr->checksum = csum;//校验和

    csum = 0;//重置

    ip_hdr->daddr = orig_ip_hdr->saddr;
    ip_hdr->saddr = orig_ip_hdr->daddr;
    ip_hdr->ttl = DEFAULT_TTL;
    ip_hdr->frag_off = 0;
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = bpf_htons(ICMP_TOOBIG_SIZE + headroom - sizeof(struct ethhdr));
    ip_hdr->id = 0;
    ip_hdr->check = 0;
    ipv4_csum(ip_hdr, sizeof(struct iphdr), &csum);
    ip_hdr->check = csum;
    return XDP_TX;
}

//~
__attribute__((__always_inline__)) static inline int//---------------√
 send_icmp_too_big(
    struct xdo_md* ctx,
    bool is_ipv6,
    int pckt_size
) {
    int offset = pckt_size;
    if(is_ipv6) {
        offset -= ICMP6_TOOBIG_SIZE;
    } else {
        offset -= ICMP_TOOBIG_SIZE;
    }

    //调整数据包
    //尾部调整 负数delta为收缩
    if(bpf_xdp_adjust_tail(ctx, 0 - offset)) {
        return XDP_DROP;
    }
    if(is_ipv6) {
        return send_icm6_too_big(ctx);
    } else {
        return send_icm_too_big(ctx);
    }
}


//~
__always_inline static int parse_icmpv6(//---------------√
    void* data,
    void* data_end,
    __u64 nh_off,
    struct packet_description* pckt
)
{
    struct icmp6hdr* icmp6_hdr;
    struct ipv6hdr* ip6_hdr;
    icmp6_hdr = data + nh_off;
    if(icmp6_hdr + 1 > data_end) {
        return XDP_DROP;
    }
    if(icmp6_hdr->icmp6_type == ICMPV6_ECHO_REQUEST) {
        return send_icmp6_reply(data, data_end);//发送回应
    }

    if((icmp6_hdr->icmp6_type != ICMPV6_PKT_TOOBIG )&&
        (icmp6_hdr->icmp6_type != ICMPV6_DEST_UNREACH)) {
            return XDP_PASS;//内核栈处理
        }

    if(icmp6_hdr->icmp6_type == ICMPV6_PKT_TOOBIG) {
        __u32 stats_key = MAX_VIPS + ICMP_PTB_V6_STATS;
        struct lb_stats* stats_ = bpf_map_lookup_elem(&stats, &stats_key);
        if(!stats_) {
            return XDP_DROP;
        }
        stats_->v1 += 1;//记录状态
        __u32 pmtu = bpf_ntohs(icmp6_hdr->icmp6_mtu);
        if(pmtu < MAX_MTU_IN_PTB_TO_DROP) {
            stats_->v2 += 1;//记录状态
        }
    }

    nh_off += sizeof(struct icmp6hdr);
    ip6_hdr = data + nh_off;
    if(ip6_hdr + 1 > data_end) {
        return XDP_DROP;
    }

    pckt->flow.proto = ip6_hdr->nexthdr;
    pckt->flags |= F_ICMP;
    memcpy(pckt->flow.srcv6, ip6_hdr->daddr.s6_addr32, 16);
    memcpy(pckt->flow.dstv6, ip6_hdr->saddr.s6_addr32, 16);
    return FURTHER_PROCESSING;
}


//~
//补充quic的实现机理
__attribute__((__always_inline__)) static inline bool ignorable_quic_icmp_code(
    void* data,
    void* data_end,
    bool is_ipv6
)
{
    __u64 off = sizeof(struct ethhdr);
    if(is_ipv6) {
        struct icmp6hdr* icmp6_hdr = data + off + sizeof(struct ipv6hdr);
    
        return (icmp6_hdr->icmp6_code == ICMPV6_ADDR_UNREACH) ||
                (icmp6_hdr->icmp6_code == ICMPV6_PORT_UNREACH);
    } else {
        struct icmphdr* icmp_hdr = data + off + sizeof(struct iphdr);
    
        return (icmp_hdr->code == ICMP_PORT_UNREACH) ||
                (icmp_hdr->code == ICMP_HOST_UNREACH);
    }
    //return true;
}