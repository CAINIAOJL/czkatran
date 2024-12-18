#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <stdbool.h>
#include <stddef.h>

#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "czkatran/decap/bpf/decap.bpf.h"
#include "czkatran/lib/bpf/balancer_consts.h"
#include "czkatran/lib/bpf/balancer_structs.h"
#include "czkatran/lib/bpf/packet_encap.h"
#include "czkatran/lib/bpf/packet_parse.h"

//decap 解封装
//encp 封装

#ifndef DECAP_PROG_SEC
#define DECAP_PROG_SEC "xdp"
#endif

/**
 * @brief 解析L3层头部
 * @param packet 包描述符
 * @param protocol 协议类型
 * @param packet_size 包大小
 * @param data 数据起始地址
 * @param off 偏移量
 * @param data_end 数据结束地址
 * @param is_ipv6 是否是ipv6
 * @return 处理结果~
 */
__always_inline static int process_l3_header(struct packet_description *packet,
                                            __u8 *protocol,
                                            __u16 *packet_size,
                                            void *data,
                                            __u64 off,
                                            void *data_end,
                                            bool is_ipv6
                                            ) {

    struct iphdr *iph;
    struct ipv6hdr *ipv6h;
    __u64 iph_len;
    if (is_ipv6) {
        //ipv6
        ipv6h = data + off;
        if (ipv6h + 1 > data_end) {
            return XDP_DROP;
        }

        iph_len = sizeof(struct ipv6hdr);
        *protocol = ipv6h->nexthdr;
        packet->flow.proto = *protocol;
        *packet_size = bpf_ntohs(ipv6h->payload_len);
        off += iph_len;
        //暂且不太懂这个字段的作用
        if(*protocol == IPPROTO_FRAGMENT) {
            return XDP_DROP;
        }
#ifdef DECAP_STRICT_DESTINATION
        memcpy(packet->flow.dstv6, ipv6h->daddr.s6_addr32, 16);
#endif //decap_strict_destination
    } else {
        iph = data + off;
        if (iph + 1 > data_end) {
            return XDP_DROP;
        }

        if (iph->ihl != 5) {
            return XDP_DROP;
        }

        *protocol = iph->protocol;
        packet->flow.proto = *protocol;
        *packet_size = bpf_ntohs(iph->tot_len);
        off += IPV4_HDR_LEN_NO_OPT;

        if (iph->frag_off & PACKET_FRAGMENTED) {
            return XDP_DROP;
        }
#ifdef DECAP_STRICT_DESTINATION
        packet->flow.dst = iph->daddr;
#endif
    }
    return FURTHER_PROCESSING;
}

//~
#ifdef INLINE_DECAP_GUE
__always_inline static int process_encaped_gue_packet(void ** data,
                                                      void ** data_end,
                                                      struct xdp_md *xdp,
                                                      bool is_ipv6,
                                                      bool *inner_ipv6) {
    int offset = 0;
    if(is_ipv6) {
        __u8 v6 = 0;
        offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
        if(*data + offset + 1 > *data_end) {
            return XDP_DROP;
        }
        //指向GUE header
        v6 = ((__u8*)(*data))[offset];
        v6 &= GUEV1_IPV6MASK;
        *inner_ipv6 = v6 ? true : false;
        if(v6) {
            //inner packet是ipv6类型的数据包
            if(!gue_decap_v6(xdp, data, data_end, false)) {
                return XDP_DROP;
            }
        } else {
            //inner packet是ipv4类型的数据包
            if(!gue_decap_v6(xdp, data, data_end, true)) {
                return XDP_DROP;
            }
        }
    } else {
        offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
        if(*data + offset > *data_end) {
            return XDP_DROP;
        }
        if(!gue_decap_v4(xdp, data, data_end)) {
            return XDP_DROP;
        }
    }
    return FURTHER_PROCESSING;
}
#endif //INLINE_DECAP_GUE

__always_inline static void validate_tpr_server_id(void *data,
                                                   __u64 off, 
                                                   void *data_end, 
                                                   bool is_ipv6, 
                                                   struct xdp_md *xdp, 
                                                   struct decap_stats *data_stats) {
    __u16 inner_packet_size= 0;
    struct packet_description inner_packet = {}; //内嵌的数据包描述符
    __u8 inner_protocol = 0;
    if(process_l3_header(&inner_packet, &inner_protocol, &inner_packet_size, data, off, data_end, is_ipv6) >= 0) {
        return;
    }

    if(inner_protocol != IPPROTO_TCP) {
        return;
    }
    if(!parse_tcp(data, data_end, is_ipv6, &inner_packet)) {
        return;
    }

    if(!(inner_packet.flags & F_SYN_SET)) {
        __u32 s_key = 0;
        __u32 *server_id_host = bpf_map_lookup_elem(&tpr_server_id, &s_key);
        if(server_id_host && *server_id_host > 0) {
            __u32 server_id = 0;
            tcp_hdr_opt_lookup_server_id(xdp, is_ipv6, &server_id);
            if(server_id > 0) {
                data_stats->tpr_total += 1;
                if(server_id != *server_id_host) {
                    data_stats->tpr_misrouted += 1;
                }
            }
        }
    }
}




//~
#ifdef DECAP_STRICT_DESTINATION
__always_inline static int check_decap_dst(struct packet_description *packet, 
                                          bool is_ipv6) {
    struct real_definition * host_primary_addrs;
    __u32 addr_index;

    if (is_ipv6) {
        addr_index = V6_SRC_INDEX;
        host_primary_addrs = bpf_map_lookup_elem(&packet_srcs, &addr_index);
        if (host_primary_addrs) {
            if (host_primary_addrs->dstv6[0] != packet->flow.dstv6[0] ||
               host_primary_addrs->dstv6[1] != packet->flow.dstv6[1] ||
               host_primary_addrs->dstv6[2] != packet->flow.dstv6[2] ||
               host_primary_addrs->dstv6[3] != packet->flow.dstv6[3]) {
                    return XDP_PASS;
               }
        }
    } else {
        addr_index = V4_SRC_INDEX;
        host_primary_addrs = bpf_map_lookup_elem(&packet_srcs, &addr_index);
        if (host_primary_addrs) {
            if (host_primary_addrs->dst != packet->flow.dst) {
                return XDP_PASS;
            }
        }
    }
    return FURTHER_PROCESSING;
}
#endif //decap_strict_destination

/**
 * @brief 解封装ipip数据包
 * @param data 数据起始地址
 * @param data_end 数据结束地址
 * @param is_ipv6 是否是ipv6
 * @param packet 包描述符
 * @param protocol 协议类型
 * @param packet_size 包大小
 * @param off 偏移量
 * @return 处理结果~
 */
__always_inline static int process_encap_ipip_packet(void **data, 
                                                     void **data_end, 
                                                     struct xdp_md *xdp,
                                                     bool *is_ipv6,
                                                     struct packet_description *packet,
                                                     __u8 *protocol,
                                                     __u64 *packet_size,
                                                     __u64 off) {
    if (*protocol == IPPROTO_IPIP) {
        //ipip隧道设备
        if (*is_ipv6) {
            //ipv6
            if ((*data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) > *data_end) {
                return XDP_DROP;
            }
            if (!decap_ipv6(xdp, data, data_end, true)) {
                return XDP_DROP;
            }
        } else {
            if ((*data + sizeof(struct ethhdr) + sizeof(struct iphdr)) > *data_end) {
                return XDP_DROP;
            }
            if (!decap_v4(xdp, data, data_end)) {
                return XDP_DROP;
            }
        }
    } else if (*protocol == IPPROTO_IPV6) {
        //ipv6
        if ((*data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr)) > *data_end) {
            return XDP_DROP;
        }
        //不是隧道相关，直接解封装
        if (!decap_v6(xdp, data, data_end, false)) {
            return XDP_DROP;
        }
    }
    return FURTHER_PROCESSING;
}


/**
 * @brief 解析数据包的开始
 * @param data 数据起始地址
 * @param data_end 数据结束地址
 * @param is_ipv6 是否是ipv6
 * @param packet 包描述符
 * @param protocol 协议类型
 * @param packet_size 包大小
 * @param off 偏移量
 * @return 处理结果~
 */
//__attribute__((_always_inline_))
__always_inline static int process_packet(void *data,
                                         __u64 off, 
                                         void *data_end, 
                                         bool is_ipv6, 
                                         struct xdp_md *ctx) {
    struct packet_description packet = {};
    struct decap_stats *data_stats;
    __u32 key = 0;
    __u8 protocol;

    int ret;
    __u16 packet_size = 0;
    ret = process_l3_header(&packet, 
                            &protocol, 
                            &packet_size, 
                            data, 
                            off, 
                            data_end, 
                            is_ipv6); //l3层处理函数（IP层）
    if (ret >= 0) {
        return ret;
    }
    protocol = packet.flow.proto;

    data_stats = bpf_map_lookup_elem(&decap_cunters, &key);
    if (!data_stats) {
        return XDP_PASS;
    }
    //如果是隧道数据包，或者是ipv协议的以太帧
    if (protocol == IPPROTO_IPIP || protocol == IPPROTO_IPV6) {
#ifdef DECAP_STRICT_DESTINATION //decap_strict_destination
        ret = check_decap_dst(&packet, is_ipv6);
        if(ret >= 0) {
            return ret;
        }
#endif
        if (is_ipv6) {
            data_stats->decap_v6 += 1;
        } else {
            data_stats->decap_v4 += 1;
        }
        data_stats->total += 1;

        ret = process_encap_ipip_packet(&data, &data_end, ctx, &is_ipv6, &packet, &protocol, &packet_size, off);
        if (ret >= 0) {
            return ret;
        }
    }
#ifdef INLINE_DECAP_GUE
    else if (protocol == IPPROTO_UDP) {
        if (!parse_udp(data, data_end, is_ipv6, &packet)) {
            return XDP_PASS;
        }
        if(packet.flow.port16[1] == bpf_htons(GUE_DPORT)) {
#ifdef DECAP_STRICT_DESTINATION
            ret = check_decap_dst(&packet, is_ipv6);
            if(ret >= 0) {
                return ret;
            }
#endif

            if(is_ipv6) {
                data_stats->decap_v6 += 1;
            } else {
                data_stats->decap_v4 += 1;
            }
            data_stats->total += 1;
            bool inner_ipv6 = false;
            ret = process_encaped_gue_packet(&data, &data_end, ctx, is_ipv6, &inner_ipv6);
            if (ret >= 0) {
                return ret;
            }
            validate_tpr_server_id(data, off, data_end, inner_ipv6, ctx, data_stats);

        }
    }
#endif
}




//~
SEC(DECAP_PROG_SEC)
int xdp_decap(struct xdp_md *ctx) {
    //具体可以查看Linux源码分析tcp/ip实现中的对于sk__buffer的描述，非常详细
    void *data = (void *)(long)(ctx->data);
    void *data_end = (void *)(long)(ctx->data_end);

    struct ethhdr *eth = data;
    __u32 eth_proto; //协议类型
    __u32 nh_off; //网络层头部偏移

    nh_off = sizeof(struct ethhdr); //网络层头部偏移
    if (data + nh_off > data_end) {
        return XDP_DROP; //数据不够长，丢弃
    }

    eth_proto = eth->h_proto; //获取协议类型

    if (eth_proto == BE_ETH_P_IP) {
        //处理IP数据包
        return process_packet(data, nh_off, data_end, false, ctx);
    } else if (eth_proto == BE_ETH_P_IPV6) {
        //处理ipv6数据包
        return process_packet(data, nh_off, data_end, true, ctx);
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";