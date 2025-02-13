#pragma once

#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/ip.h>
#include <linux/version.h>

#include "balancer_consts.h"
#include "balancer_structs.h"

#include "balancer_maps.h"

//#include <bpf/bpf.h>
//#include <bpf/bpf_helpers.h>


/*                      QUIC LONG HEADER
0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+
   |1|X X X X X X X|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Version (32)                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | DCID Len (8)  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               Destination Connection ID (0..2040)           ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | SCID Len (8)  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Source Connection ID (0..2040)              ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |X X X X X X X X X X X X X X X X X X X X X X X X X X X X X X  ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
/*
Long Header Packet {
     Header Form (1) = 1,
     Version-Specific Bits (7),
     Version (32),
     Destination Connection ID Length (8),
     Destination Connection ID (0..2040),
     Source Connection ID Length (8),
     Source Connection ID (0..2040),
     Version-Specific Data (..),
   }
*/

struct quic_long_header {
    __u8 flags;
    __u32 version;
    
    // [4bits] Dest Conn Id + [4 bits] Source Conn Id = [8 bits]conn_id_lens 
    __u8 conn_id_lens;

    __u8 dst_connection_id[QUIC_MIN_CONNID_LEN];
} __attribute__((__packed__));

/*                   QUIC SHORT HEADER
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+
   |0|X X X X X X X|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Destination Connection ID (*)               ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |X X X X X X X X X X X X X X X X X X X X X X X X X X X X X X  ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/*
   Short Header Packet {
     Header Form (1) = 0,
     Version-Specific Bits (7),
     Destination Connection ID (..),
     Version-Specific Data (..),
   }
*/

struct quic_short_header {
    __u8 flags;
    __u8 dst_connection_id[QUIC_MIN_CONNID_LEN];
} __attribute__((__packed__));

struct quic_parse_result {
    int server_id;
    __u8 cid_version;
    bool is_initial;
};

struct stable_routing_header {
    __u8 connection_id[STABLE_RT_LEN]; //一个字节
}__attribute__((__packed__));

struct udp_stable_rt_result {
    __be32 server_id;
    bool is_stable_rt_pkt;
};


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
    udp = data + off;
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
    tcp = data + off;
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
    if(kind == TCP_OPT_EOL) {
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

    if(kind == TCP_HDR_OPT_KIND_TPR) {
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

//~
__always_inline static struct quic_parse_result parse_quic(
    void* data,
    void* data_end,
    bool is_ipv6,
    struct packet_description* pckt
) {
    struct quic_parse_result result = {
        .server_id = FURTHER_PROCESSING,
        .cid_version = 0xFF,
        .is_initial = false
    };

    bool is_icmp = (pckt->flags & F_ICMP);

    __u64 off = calc_offset(is_ipv6, is_icmp);

    if((data + off + sizeof(struct udphdr) + sizeof(__u8)) > data_end) {
        return result;
    }

    __u8* quic_data = data + off + sizeof(struct udphdr);
    __u8* pckt_type = quic_data;
    __u8* connId = NULL;

    /*
    CONN ID 的位置根据数据包是长报头还是短报头而变化。
    一旦我们计算了 conn id 的偏移量，只需读取固定长度，
    即使 connid len 可以是 0 或 4-18 字节，
    因为 czkatran 只关心 Dest Conn Id 中的前 16 位
    */
   //长头
   if((*pckt_type & QUIC_LONG_HEADER) == QUIC_LONG_HEADER) {
        if((quic_data + sizeof(struct quic_long_header)) > data_end) {
            return result;
        }
        if((*pckt_type & QUIC_PACKET_TYPE_MASK) < QUIC_HEADERMASK) {
            /*
            对于客户端初始数据包和 0RTT 数据包 - 回退以使用 C. 哈希，
            因为connection-id 不是服务器选择的 ID。
            */
            result.is_initial = true;
            return result;
        }

        struct quic_long_header* long_header = (struct quic_long_header*)quic_data;
        if(long_header->conn_id_lens < QUIC_MIN_CONNID_LEN) {
            return result;
        }
        connId = long_header->dst_connection_id;
   } else {
    //短头
    //直接读取connID
    if(quic_data + sizeof(struct quic_short_header) > data_end) {
        return result;
    }
    connId = ((struct quic_short_header*)quic_data)->dst_connection_id;
   }
   if(!connId) {
    return result;
   }

    //取前两位
   __u8 connIdVersion = (connId[0] >> 6);
   result.cid_version = connIdVersion;
   if(connIdVersion == QUIC_CONNID_VERSION_V1) {
        result.server_id = ((connId[0] & 0x3F) << 10) | (connId[1] << 2) | (connId[2] >> 6);
        return result;
   } else if(connIdVersion == QUIC_CONNID_VERSION_V2) {
        result.server_id = (connId[1] << 16) | (connId[2] << 8) | (connId[3]);
        return result;
   } else if (connIdVersion == QUIC_CONNID_VERSION_V3) {
        result.server_id = (connId[1] << 24) | (connId[2] << 16) | (connId[3] << 8) | (connId[4]);
   }
   return result;
}


//~
__always_inline static struct udp_stable_rt_result parse_udp_stable_rt_hdr(
    void* data,
    void* data_end,
    bool is_ipv6,
    struct packet_description* pckt
)
{
    struct udp_stable_rt_result result = {
        .server_id = STABLE_RT_NO_SERVER_ID,
        .is_stable_rt_pkt = false
    };
    bool is_icmp = (pckt->flags & F_ICMP);
    __u64 off = calc_offset(is_ipv6, is_icmp);

    if((data + off + sizeof(struct udphdr) + sizeof(__u8)) > data_end) {
        return result;
    }

    __u8* udp_data = data + off + sizeof(struct udphdr);
    __u8* pkt_type = udp_data;
    __u8* connId = NULL;

    if((*pkt_type) == STABLE_ROUTING_HEADER) {
        //带有stable routing header的数据包
        if(udp_data + sizeof(struct stable_routing_header) > data_end) {
            return result;
        }
        connId = ((struct stable_routing_header*)udp_data)->connection_id;
        result.is_stable_rt_pkt = true;
    }
    if(!connId) {
        return result;
    }

    result.server_id = (connId[1] << 16) | (connId[2] << 8) | (connId[3]);
    return result;
}



#ifdef TCP_SERVER_ID_ROUTING
__always_inline static int tcp_hdr_opt_lookup(
    struct xdp_md* ctx,
    bool is_ipv6,
    struct real_definition** dst,
    struct packet_description* pckt
)
{
    __u32 server_id = 0;
    int err = 0;
    if(tcp_hdr_opt_lookup_server_id(ctx, is_ipv6, &server_id) == FURTHER_PROCESSING) {
        return FURTHER_PROCESSING;
    }

    __u32 key = server_id;
    __u32* real_pos = bpf_map_lookup_elem(&server_id_map, &key);
    if(!real_pos) {
        return FURTHER_PROCESSING;
    }
    key = *real_pos;
    if(key == 0) {
        /*
        由于 server_id_map 是一个bpf_map_array因此其所有成员都是 0 初始化的，
        这可能导致不存在的键与索引 0 处的 real 错误匹配。
        因此，只需跳过值为 0 的 key 即可避免数据包路由错误。
        */
        return FURTHER_PROCESSING;
    }
    pckt->real_index = key;
    *dst = bpf_map_lookup_elem(&reals, &key);
    if(!(*dst)) {
        return FURTHER_PROCESSING;
    }
    return 0;
}
#endif // TCP_SERVER_ID_ROUTING'
