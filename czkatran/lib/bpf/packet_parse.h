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
#include <linux/version.h>

#include <bpf/bpf_helpers.h>
#include "balancer_consts.h"
#include "balancer_structs.h"

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


#if defined(TCP_SERVER_ID_ROUTING) || defined(DECAP_TPR_STATS)

__always_inline int parse_hdr_opt_raw(const void *data,
                                      const void *data_end, 
                                      struct hdr_opt_state *tcp_state) {

    __u8 *tcp_opt, kind, hdr_len;

    if(!tcp_state) {
        return -1;
    }

    tcp_opt = (__u8 *)(data + tcp_state->bytes_offset);
    if(tcp_opt + 1 > data_end) {
        return -1;
    }

    kind = tcp_opt[0];
    if(kind == TCP_OPT_EOF) {
        return -1;
    }

    if(kind == TCP_OPT_NOP) {
        tcp_state->bytes_offset++;
        tcp_state->hdr_bytes_remaining--;
        return 0;
    }

    if(tcp_state->hdr_bytes_remaining < 2 || 
     tcp_opt + sizeof(__u8) + sizeof(__u8) > data_end) {
        // 选项长度至少为2字节 或者指针右移两位指向的value（server_id）超过了报文的末尾
        return -1;
    }

    hdr_len = tcp_opt[1];
    if(hdr_len > tcp_state->hdr_bytes_remaining) {
        return -1;
    }

    if(kind == TCP_HDR_OPT_MAX_OPT_CHECKS) {
        //再次检查
        if(hdr_len != TCP_HDR_OPT_LEN_TPR) {
            return -1;
        }
        if(tcp_opt + TCP_HDR_OPT_LEN_TPR > data_end) {
            return -1;
        }

        tcp_state->server_id = *(__u32 *)&tcp_opt[2];
        return 1;
    }
    
    tcp_state->bytes_offset += hdr_len;
    tcp_state->hdr_bytes_remaining -= hdr_len;
    return 0;
}

//~
#ifndef TCP_HDR_OPT_SKIP_UNROLL_LOOP
__always_inline
#endif
int parse_hdr_opt(struct xdp_md *xdp,
                  struct hdr_opt_state *tcp_state) {
    __u8 *tcp_opt, kind, hdr_len;

    const void *data = (void *)(long)xdp->data;
    const void *data_end = (void *)(long)xdp->data_end;
    return parse_hdr_opt_raw(data, data_end, tcp_state);
}

__always_inline static int tcp_hdr_opt_lookup_server_id(const struct xdp_md *xdp,
                                                        bool is_ipv6,
                                                        __u32 *server_id) {

    const void *data = (void *)(long)(xdp->data);
    const void *data_end = (void *)(long)(xdp->data_end);
    struct tcphdr *tcphdr;
    __u64 hdr_offset = 0;
    __u8 tcp_hdr_opt_len = 0;
    struct hdr_opt_state tcp_opt = {};
    int err = 0;

    hdr_offset = calc_offset(is_ipv6, false);
    tcphdr = (struct tcphdr *)(data + hdr_offset);
    //判断
    if(tcphdr + 1 > data_end) {
        return FURTHER_PROCESSING;
    }

    //doff 四位 单位为 4字节（32位）
    //doff * 4 再减去头部长度，如果为零，表示没有tcp选项
    tcp_hdr_opt_len = (tcphdr->doff * 4) - sizeof(struct tcphdr);
    if (tcp_hdr_opt_len < TCP_HDR_OPT_LEN_TPR) {
        return FURTHER_PROCESSING;
    }
    tcp_opt.hdr_bytes_remaining = tcp_hdr_opt_len;
    tcp_opt.bytes_offset = hdr_offset + sizeof(struct tcphdr); //指向选项的第一个字节

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0) || \
    !defined TCP_HDR_OPT_SKIP_UNROLL_LOOP
    //在提供的代码中，这段指令出现在两个函数中：tcp_hdr_opt_lookup和tcp_hdr_opt_lookup_skb。这两个函数的主要功能是从TCP数据包的选项字段中解析出服务器ID。由于BPF（Berkeley Packet Filter）程序的限制，特别是在Linux内核版本低于5.3的系统中，BPF验证器（verifier）无法验证循环的边界条件。因此，为了通过验证器的检查，编译器需要对循环进行完全展开，确保循环体中的每一部分都被正确地验证。
#pragma clang loop unroll(full)
#endif
    //循环解析TCP选项
    for (int i = 0; i < TCP_HDR_OPT_MAX_OPT_CHECKS; i++) {
        err = parse_hdr_opt(xdp, &tcp_opt);
        if (err || !tcp_opt.hdr_bytes_remaining) {
            break;
        }
    }
    if(!tcp_opt.server_id) {
        return FURTHER_PROCESSING;
    }
    *server_id = tcp_opt.server_id;
    return 0;
}
#endif //TCP_SERVER_ID_ROUTING || DECAP_TPR_STATS




#endif