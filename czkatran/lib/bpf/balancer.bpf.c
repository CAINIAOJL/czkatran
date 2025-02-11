#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <stdbool.h>
#include <stddef.h>

#include "/home/cainiao/czkatran/czkatran/lib/linux_includes/jhash.h"
//#include "balancer_maps.h"
#include "control_data_maps.h"
#include "balancer_helpers.h"
#include "packet_encap.h"
#include "packet_parse.h"
#include "handle_icmp.h"

__always_inline static bool is_under_flood(
    __u32* cur_time
) {
    __u32 conn_rate_key = MAX_VIPS + NEW_CONN_RATE_CNTR;
    struct lb_stats* conn_rate_stats = 
        bpf_map_lookup_elem(&stats, &conn_rate_key);
    if(!conn_rate_stats) {
        return true; //直截了当地判断syn攻击，待进一步优化
    }
    *cur_time = bpf_ktime_get_ns();
    /*
    我们将检查新连接速率是否低于预定义的速率
    价值;conn_rate_stats.v1 包含最后一个
    second， v2 - 上次 Quanta 开始的时间。
    */
    if((*cur_time - conn_rate_stats->v2) > ONE_SEC  /* 1 sec in nanosec*/) {
        conn_rate_stats->v1 = 1;
        conn_rate_stats->v2 = *cur_time; //存放的是时间
    } else {
        conn_rate_stats->v1++;
        /*
        我们正在超过最大连接速率。跳过 LRU 更新和源路由查找
        */
        if(conn_rate_stats->v1 > MAX_CONN_RATE) {
            return true;
        }
    }
    return false;
}



//~
__always_inline static int 
process_l3_headers(
    struct packet_description* pckt,
    __u8* protocol,
    __u64 nh_off,
    __u16* pkt_bytes,
    void* data,
    void* data_end,
    bool is_ipv6
) 
{
    int action;
    struct iphdr* iphdr;
    struct ipv6hdr* ipv6hdr;
    __u64 iph_len;
    if(!is_ipv6) {
        //ipv4
        iphdr = data + nh_off;
        if(iphdr + 1 > data_end) {
            return XDP_DROP;
        }
        if(iphdr->ihl != 5) {
            return XDP_DROP;
        }
        pckt->tos = iphdr->tos;
        *protocol = iphdr->protocol;
        pckt->flow.proto = *protocol;
        *pkt_bytes = bpf_ntohs(iphdr->tot_len);
        nh_off += IPV4_HDR_LEN_NO_OPT; //20

        //检测是否是ip分片数据包
        if(iphdr->frag_off & PACKET_FRAGMENTED) {
            return XDP_DROP;//丢弃ip分片数据包
        }
        if(*protocol == IPPROTO_ICMP) {
            //icmp报文
            action = parse_icmp(data, data_end, nh_off, pckt);
            if(action >= 0) {
                return action;
            }
        } else {
            pckt->flow.src = iphdr->saddr;
            pckt->flow.dst = iphdr->daddr;
        }
    } else {
        //ipv6
        iphdr = data + nh_off;
        if(ipv6hdr + 1 > data_end) {
            return XDP_DROP;
        }

        iph_len = sizeof(struct ipv6hdr);
        *protocol = ipv6hdr->nexthdr;
        pckt->flow.proto = *protocol;

        //取出优先级
        pckt->tos = (ipv6hdr->priority << 4) & 0xF0;
        //合并流标签
        pckt->tos = pckt->tos | ((ipv6hdr->flow_lbl[0] >> 4) & 0x0F);

        *pkt_bytes = bpf_ntohs(ipv6hdr->payload_len);
        nh_off += iph_len;

        if(*protocol == IPPROTO_FRAGMENT) {
            //ip分片数据包
            return XDP_DROP;
        } else if (*protocol == IPPROTO_ICMPV6) {
            action = parse_icmpv6(data, data_end, nh_off, pckt);
            if(action >= 0) {
                return action;
            }
        } else {
            memcpy(pckt->flow.srcv6, ipv6hdr->saddr.s6_addr32, 16);
            memcpy(pckt->flow.dstv6, ipv6hdr->daddr.s6_addr32, 16);
        }
    }
    return FURTHER_PROCESSING;
}

//~
#ifdef INLINE_DECAP_GENERIC
__always_inline static int check_decap_dst(
    struct packet_description* pckt,
    bool is_ipv6,
    bool* pass
) {
    struct address dst_address = {};
    struct lb_stats* data_stats;

#ifdef DECAP_STRICT_DESTINATION //decap_strict_destination
    struct real_definition* host_primary_addrss;
    __u32 addr_index;

    if(is_ipv6) {
        addr_index = V6_SRC_INDEX;
        //问题
        host_primary_addrss = bpf_map_lookup_elem(&packet_srcs, &addr_index);
        /*
        由于外部数据包目标与主机 IPv6 不匹配，
        因此请勿解封。
        它允许将数据包传送到正确的网络命名空间。
        */
       if(host_primary_addrss) {
        if(host_primary_addrss->dstv6[0] != pckt->flow.dstv6[0] ||
           host_primary_addrss->dstv6[1] != pckt->flow.dstv6[1] || 
           host_primary_addrss->dstv6[2] != pckt->flow.dstv6[2] || 
           host_primary_addrss->dstv6[3] != pckt->flow.dstv6[3]) {
            return XDP_PASS;
           }
       }
    } else {
        addr_index = V4_SRC_INDEX;
        host_primary_addrss = bpf_map_lookup_elem(&packet_srcs, &addr_index);
        if(host_primary_addrss) {
            if(host_primary_addrss->dst != pckt->flow.dst) {
                return XDP_PASS;
            }
        }
    }
#endif //INLINE_DECAP_GENERIC

    if(is_ipv6) {
        memcpy(dst_address.addrv6, pckt->flow.dstv6, 16);
    } else {
        dst_address.addr = pckt->flow.dst;
    }

    __u32* decap_dst_flags = bpf_map_lookup_elem(&decap_dst, &dst_address);

    if(decap_dst_flags) {
        *pass = false;
        __u32 stats_key = MAX_VIPS + REMOTE_ENCAP_CNTRS;
        data_stats = bpf_map_lookup_elem(&stats, &stats_key);
        if(!data_stats) {
            return XDP_DROP;
        }
        data_stats->v1++;
    }
    return FURTHER_PROCESSING;
}
#endif //INLINE_DECAP_GENERIC

//~
#ifdef INLINE_DECAP_IPIP
__always_inline static int 
process_encaped_ipip_pckt(
    void** data,
    void** data_end,
    struct xdp_md *ctx, 
    bool* is_ipv6,
    __u8* protocol,
    bool pass
) {
    int action;
    if(*protocol == IPPROTO_IPIP) {
        //ipip包
        if(*is_ipv6) {
            int offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
            if((*data + offset) > *data_end) {
                return XDP_DROP;
            }
            action = decrement_ttl(*data, *data_end, offset, false);
            if(!decap_v6(ctx, data, data_end, true)) {
                return XDP_DROP;
            }
            *is_ipv6 = false;
        } else {
            int offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
            if((*data + offset) > *data_end) {
                return XDP_DROP;
            }
            action = decrement_ttl(*data, *data_end, offset, false);
            if(!decap_v4(ctx, data, data_end)) {
                return XDP_DROP;
            }
        }
    } else if (*protocol == IPPROTO_IPV6) {
        int offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        if((*data + offset) > *data_end) {
            return XDP_DROP;
        }
        action = decrement_ttl(*data, *data_end, offset, true);
        if(!decap_v6(ctx, data, data_end, false)) {
            return XDP_DROP;
        }
    }

    __u32 stats_key = MAX_VIPS + DECAP_CNTR;
    struct lb_stats* data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if(!data_stats) {
        return XDP_DROP;
    }

    if(is_ipv6) {
        data_stats->v2++;
    } else {
        data_stats->v1++;
    }

    if(action >= 0) {
        return action;
    }

    if(pass) {
        return XDP_PASS; //交给内核栈
    }
    return recirculate(ctx);//循环处理
}
#endif //INLINE_DECAP_IPIP

/*#ifdef INLINE_DECAP_GENERIC
__always_inline static int check_decap_dst(
    struct packet_description* pckt,
    bool is_ipv6,
    bool* pass)
{
    struct address* dst_addr = {};
    struct lb_stats* data_stats;

#ifdef DECAP_STRICT_DESTINATION
    struct real_definition* host_primary_addrs;
    __u32 addr_index;

    if(is_ipv6) {
        addr_index = V6_SRC_INDEX;
        host_primary_addrs = bpf_map_lookup_elem(&packet_srcs, &addr_index);
        if(host_primary_addrs) {
            if(host_primary_addrs->dstv6[0] != pckt->flow.dstv6[0] ||
               host_primary_addrs->dstv6[1] != pckt->flow.dstv6[1] || 
               host_primary_addrs->dstv6[2] != pckt->flow.dstv6[2] || 
               host_primary_addrs->dstv6[3] != pckt->flow.dstv6[3]) {
                return XDP_PASS;
            }
        }
    } else {
        addr_index = V4_SRC_INDEX;
        host_primary_addrs = bpf_map_lookup_elem(&packet_srcs, &addr_index);
        if(host_primary_addrs) {
            if(host_primary_addrs->dst != pckt->flow.dst) {
                return XDP_PASS;
            }
        }
    }
#endif

    if(is_ipv6) {
        memcpy(dst_addr->addrv6, pckt->flow.dstv6, 16);
    } else {
        dst_addr->addr = pckt->flow.dst;
    }

    __u32* decap_dst_flags = bpf_map_lookup_elem(&decap_dst, &dst_addr);
    if(decap_dst_flags) {
        *pass = false;
        __u32 stats_key = MAX_VIPS + REMOTE_ENCAP_CNTRS;
        data_stats = bpf_map_lookup_elem(&stats, &stats_key);
        if(!data_stats) {
            return XDP_DROP;
        }
        data_stats->v1++;
    }
    return FURTHER_PROCESSING;
}
#endif */ // INLINE_DECAP_GENERIC

//~
#ifdef INLINE_DECAP_GUE

__always_inline static void incr_decap_vip_stats(
    void* data,
    __u64 nh_off,
    void* data_end,
    bool is_ipv6
)
{
    struct packet_description inner_pckt = {};
    struct vip_definition vip = {};
    struct vip_meta* vip_info;
    __u8 inner_protocol;
    __u16 inner_pckt_bytes;
    //分析l3层
    if(process_l3_headers(
        &inner_pckt, 
        &inner_protocol, 
        nh_off, 
        &inner_pckt_bytes,
        data, 
        data_end,
        is_ipv6) >= 0) {
        return;
    }
    if(is_ipv6) {
        memcpy(vip.vipv6, inner_pckt.flow.dstv6, 16);//收集目的ipv6地址
    } else {
        vip.vip = inner_pckt.flow.dst;
    }
    vip.proto = inner_pckt.flow.proto;

    //分析l4层
    if(inner_protocol == IPPROTO_TCP) {
        if(!parse_tcp(data, data_end, is_ipv6, &inner_pckt)) {
            return;
        }
    }
    if(inner_protocol == IPPROTO_UDP) {
        if(!parse_udp(data, data_end, is_ipv6, &inner_pckt)) {
            return;
        }
    }
    vip.port = inner_pckt.flow.port16[1]; //目的端口
    vip_info = bpf_map_lookup_elem(&vip_map, &vip);
    //存在记录
    if(vip_info) {
        __u32 vip_num = vip_info->vip_num;
        //通过hash序号查找并且更新状态
        struct lb_stats* decap_stats = bpf_map_lookup_elem(&decap_vip_stats, &vip_num);
        if(decap_stats) {
            decap_stats->v1++; //记录状态
        }
    }
}

__always_inline static int process_encaped_gue_pckt(
    void** data,
    void** data_end,
    struct xdp_md* ctx,
    __u64 nh_off,
    bool is_ipv6,
    bool* pass
)
{
    int offset = 0;
    int action;
    bool inner_ipv6 = false;
    //外层是否是ipv6
    if(is_ipv6) {
        __u8 v6 = 0;
        offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
        if((*data + offset + 1) > *data_end) {
            //1 个字节用于 gue v1 标记，用于确定什么是内部协议
            return XDP_DROP;
        }
        v6 = ((__u8*)(*data))[offset];
        v6 &= GUEV1_IPV6MASK;
        inner_ipv6 = v6 ? true : false;
        //内层是否是ipv6
        if(v6) {
           action = decrement_ttl(*data, *data_end, offset, true); //是ipv6
           if(!gue_decap_v6(ctx, data, data_end, false)) {
                return XDP_DROP;
           } 
        } else {
            action = decrement_ttl(*data, *data_end, offset, false); //是ipv4
            if(!gue_decap_v6(ctx, data, data_end, true)) {
                return XDP_DROP;
            }
        }
    } else {
        offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
        if((*data + offset) > *data_end) {
            return XDP_DROP;
        }
        action = decrement_ttl(*data, *data_end, offset, false);
        if(!gue_decap_v4(ctx, data, data_end)) {
            return XDP_DROP;
        }
    }

    __u32 stats_key = MAX_VIPS + DECAP_CNTR;
    struct lb_stats* data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if(!data_stats) {
        return XDP_DROP;
    }
    if(is_ipv6) {
        data_stats->v2++;
    } else {
        data_stats->v1++;
    }

    if(action >= 0) {
        return action;
    }

    if(pass) {
        incr_decap_vip_stats(*data, nh_off, *data_end, inner_ipv6);
        return XDP_PASS;
    }
    return recirculate(ctx);
}
#endif //INLINE_DECAP_GUE

__always_inline static void increment_quic_cid_version_stats(
    struct lb_quic_packets_stats* quic_packets_stats,
    __u8 cid_version
)
{
    if(cid_version == QUIC_CONNID_VERSION_V1) {
        quic_packets_stats->cid_v1++;
    } else if (cid_version == QUIC_CONNID_VERSION_V2) {
        quic_packets_stats->cid_v2++;
    } else if(cid_version == QUIC_CONNID_VERSION_V3) {
        quic_packets_stats->cid_v3++;
    } else {
        quic_packets_stats->cid_v0++;
    }
}

__always_inline static int check_and_update_real_index_in_lru(
    struct packet_description* pckt,
    void* lru_map
) {
    struct real_pos_lru* dst_lru = bpf_map_lookup_elem(lru_map, &pckt->flow);
    if(dst_lru) {
        if(dst_lru->pos == pckt->real_index) {
            return DST_MATCH_IN_LRU;
        } else {
            dst_lru->pos = pckt->real_index;
            return DST_MISMATCH_IN_LRU;
        }
    }
    __u64 cur_time;
    if(is_under_flood(&cur_time)) {
        return DST_NOT_FOUND_IN_LRU;
    }
    struct real_pos_lru new_dst_lru = {};
    new_dst_lru.pos = pckt->real_index;
    bpf_map_update_elem(&lru_map, &pckt->flow, &new_dst_lru, BPF_ANY);
    return DST_NOT_FOUND_IN_LRU;
}

//~
__always_inline static void incr_server_id_routing_stats(
    __u32 vip_num, 
    bool newConn, 
    bool misMatchInLRU)
{
    struct lb_stats* per_vip_stats = bpf_map_lookup_elem(&server_id_stats, &vip_num);
    if(!per_vip_stats) {
        return;
    }
    if(newConn) {
        per_vip_stats->v1++; //新的连接
    }
    if(misMatchInLRU) {
        per_vip_stats->v2++; //无法匹配
    }
}

#ifdef UDP_STABLE_ROUTING
//~
__always_inline static bool process_udp_stable_routing(
    void* data,
    void* data_end,
    struct real_definition** dst,
    struct packet_description* pckt,
    bool is_ipv6
)
{
    __u32 stable_rt_stats_key = 0;
    struct lb_stable_rt_packets_stats* udp_lb_rt_stats = 
        bpf_map_lookup_elem(&stable_rt_stats, &stable_rt_stats_key);
    if(!udp_lb_rt_stats) {
        return XDP_DROP;
    }

    struct udp_stable_rt_result usr = 
        parse_udp_stable_rt_hdr(data, data_end, is_ipv6, pckt);
    
    if(usr.server_id > 0) {
        __u32 key = usr.server_id;
        __u32* real_pos = bpf_map_lookup_elem(&server_id_map, &key);
        if(real_pos) {
            //得到该server_id对应的real_pos
            key = *real_pos;
            if(key != 0) {
                pckt->real_index = key;
                //得到real_pos对应的real_definition
                *dst = bpf_map_lookup_elem(&reals, &key);
                if(!*dst) {
                    udp_lb_rt_stats->cid_unknown_real_dropped++;
                    return XDP_DROP;
                }
                udp_lb_rt_stats->cid_routed++;
            }
        } else {
            udp_lb_rt_stats->cid_invalid_server_id++;
            udp_lb_rt_stats->ch_routed++;
        }
    } else {
        if(!usr.is_stable_rt_pkt) {
            udp_lb_rt_stats->invalid_packet_type++;
        }
        udp_lb_rt_stats->ch_routed++;
    }
}
#endif

//~
//cache操作，
__always_inline static void connecttion_table_lookup(
    struct real_definition** dst,
    struct packet_description* pckt, 
    void* lru_map,
    bool is_Globallru
)
{   
    struct real_pos_lru* dst_lru;
    __u64 time;
    __u32 key;
    dst_lru = bpf_map_lookup_elem(lru_map, &pckt->flow);
    if(!dst_lru) {
        return;
    }
    if(!is_Globallru && pckt->flow.proto == IPPROTO_UDP) {
        time = bpf_ktime_get_ns();
        if(time - dst_lru->atime > LRU_UDP_TIMEOUT) {
            return;
        }
        dst_lru->atime = time;
    }

    key = dst_lru->pos;
    pckt->real_index = key;
    *dst = bpf_map_lookup_elem(&reals, &key);
    return;
}

//~
#ifdef GLOBAL_LRU_LOOKUP
__always_inline static int perform_global_lru_lookup(
    struct real_definition** dst,
    struct packet_description* pckt,
    __u32 cpu_num,
    struct vip_meta* vip_info,
    bool is_ipv6 
)
{
    void* g_lru_map = bpf_map_lookup_elem(&global_lru_map, &cpu_num);
    __u32 global_lru_stats_key = MAX_VIPS + REMOTE_ENCAP_CNTRS;

    struct lb_stats* global_lru_stats_ = 
        bpf_map_lookup_elem(&stats, global_lru_stats_key);
    if(!global_lru_stats_) {
        return XDP_DROP;
    }
    if(!g_lru_map) {
        global_lru_stats_->v1++; //记录
        /*
        我们无法检索此 cpu 的全局 lru。
        这个计数器在 prod (生产环境)中不应该是 0 以外的任何值。
        我们将使用它 monitoring.global_lru_stats->v1 += 1; 
        此 CPU 不存在全局 LRU 映射
        */
        g_lru_map = &fallback_glru;
    }

    connecttion_table_lookup(dst, pckt, g_lru_map, true);
    if(*dst) {
        global_lru_stats_->v2++;
    }

    return FURTHER_PROCESSING;
}
#endif


__always_inline static void increment_ch_drop_real_0() {
    __u32 ch_drop_key = MAX_VIPS + CH_DROP_STATS;
    struct lb_stats* ch_drop_stats = 
        bpf_map_lookup_elem(&stats, &ch_drop_key);
    if(!ch_drop_stats) {
        return;
    }
    ch_drop_stats->v2++;
}

__always_inline static void increment_ch_drop_no_real() {
    __u32 ch_drop_stats_key = MAX_VIPS + CH_DROP_STATS;
    struct lb_stats* ch_drop_stats = 
        bpf_map_lookup_elem(&stats, &ch_drop_stats_key);
    if(!ch_drop_stats) {
        return;
    }
    ch_drop_stats->v1++;
}

__always_inline static __u32 get_packet_hash(
    struct packet_description* pckt,
    bool hash_16bytes
) {
    if(hash_16bytes) {
        return jhash_2words(jhash(pckt->flow.srcv6, 16, INIT_JHASH_SEED_V6),
        pckt->flow.ports, INIT_JHSAH_SEED);
    } else {
        return jhash_2words(pckt->flow.src, pckt->flow.ports, INIT_JHSAH_SEED);
    }
}

//~
__always_inline static bool get_packet_dst(
    struct real_defination** dst,
    struct packet_description* pckt,
    struct vip_meta* vip_info,
    bool is_ipv6,
    void *lru_map
)
{
    struct real_pos_lru new_dst = {};
    bool under_flood;
    bool src_found;
    __u64 cur_time;
    __u32 key;
    __u32 hash;
    __u32* real_pos;
    under_flood = is_under_flood(&cur_time);

#ifdef LPM_SRC_LOOKUP
    if(vip_info->flags & F_SRC_ROUTING) {
        __u32* lpm_val;
        if(is_ipv6) {
            struct v6_lpm_key lpm_key_v6 = {};
            lpm_key_v6.prefixlen = 128;
            memcpy(lpm_key_v6.addrv6, pckt->flow.srcv6, 16);
            lpm_val = bpf_map_lookup_elem(&lpm_src_v6, &lpm_key_v6);
        } else {
            struct v4_lpm_key lpm_key_v4 = {};
            lpm_key_v4.prefixle = 32;
            lpm_key_v4.addr = pckt->flow.src;
            lpm_val = bpf_map_lookup_elem(&lpm_src_v4, &lpm_key_v4);
        }
        
        if(lpm_val) {
            src_found = true;
            key = *lpm_val;
        }

        __u32 stats_key = MAX_VIPS + LPM_SRC_CNTRS;
        struct lb_stats* lpm_stats = 
            bpf_map_lookup_elem(&stats, &stats_key);
        if(lpm_stats) {
            if(src_found) {
                lpm_stats->v2++;
            } else {
                lpm_stats->v1++;
            }
        }
    }
#endif

    if(!src_found) {
        bool hahs_16bytes = is_ipv6;

        if(vip_info->flags & F_HASH_DPORT_ONLY) {
            /*
            仅使用 DST 端口进行哈希计算的服务
            例如，如果数据包具有相同的 DST 端口 ->则它们将发送到相同的 real。
            通常是 VoIP 相关服务。
            */
           pckt->flow.port16[0] = pckt->flow.port16[1];
           memset(pckt->flow.srcv6, 0, 16);
        }
        hash = get_packet_hash(pckt, hahs_16bytes) % RING_SIZE;
        key = RING_SIZE * (vip_info->vip_num) + hash;

        real_pos = bpf_map_lookup_elem(&ch_rings, &key);
        if(!real_pos) {
            return false;
        }
        key = *real_pos;
        if(key == 0) {
            //这里，0代表初始化，我们的real ids 从1开始
            /*
            真实 ID 从 1 开始，因此我们不会将 id 0 映射到任何真实 ID。这
            如果 VIP 的 CH 环未初始化，则可能会发生这种情况。
            */
           increment_ch_drop_real_0(); //计数
           return false;
        }
    }
    //key != 0
    pckt->real_index = key;
    *dst = bpf_map_lookup_elem(&reals, &key);
    if(!(*dst)) {
        increment_ch_drop_no_real(); //计数
        return false;
    }

    if(lru_map && !(vip_info->flags & F_LRU_BYPASS) && !under_flood) {
        if(pckt->flow.proto == IPPROTO_UDP) {
            new_dst.atime = cur_time;
        }
        new_dst.pos = key;
        //更新LRU
        bpf_map_update_elem(lru_map, &pckt->flow, &new_dst, BPF_ANY);
    }
    return true;
}

//~
__always_inline static int update_vip_lru_miss_stats(
    struct vip_definition* vip,
    struct packet_description* pckt,
    struct vip_meta* vip_info,
    bool is_ipv6
){
    __u32 vip_miss_stats_key = 0;
    struct vip_definition* lru_miss_stat_vip = 
        bpf_map_lookup_elem(&vip_miss_stats, &vip_miss_stats_key);
    if(!lru_miss_stat_vip) {
        return XDP_DROP;
    }

    bool address_match = (is_ipv6 && 
                            lru_miss_stat_vip->vipv6[0] == vip->vipv6[0] &&
                            lru_miss_stat_vip->vipv6[1] == vip->vipv6[1] && 
                            lru_miss_stat_vip->vipv6[2] == vip->vipv6[2] && 
                            lru_miss_stat_vip->vipv6[3] == vip->vipv6[3]
                     || !is_ipv6 && lru_miss_stat_vip->vip == vip->vip);
    bool port_match = lru_miss_stat_vip->port == vip->port;
    bool proto_match = lru_miss_stat_vip->proto == vip->proto;
    bool vip_match = address_match && port_match && proto_match;
    if(vip_match) {
        __u32 lru_stats_key = pckt->real_index;
        __u32* lru_miss_stats_ = bpf_map_lookup_elem(&lru_miss_stats, &lru_stats_key);
        if(!lru_miss_stats_) {
            return XDP_DROP;
        }

        *lru_miss_stats_++;
    }
    return FURTHER_PROCESSING;
}

__always_inline static int 
process_packet(
    struct xdp_md *ctx, 
    __u64 nh_off, 
    bool is_ipv6) 
{
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;
    struct real_definition* dst = NULL;
    struct packet_description pckt = {};
    struct vip_definition vip = {};
    struct vip_meta* vip_info;
    struct lb_stats* data_stats;
    struct ctl_value* cval;//存放mac地址和一些信息的结构体
    __u64 iph_len;
    __u8 protocol;
    __u16 original_sport;//原本的原端口

    int action;
    __u32 vip_num;
    __u32 mac_addr_pos = 0;
    __u16 pkt_bytes = 0;
    action = process_l3_headers(
        &pckt, &protocol, nh_off, &pkt_bytes, data, data_end, is_ipv6
    );

    if(action >= 0) {
        return action;
    }
    protocol = pckt.flow.proto;

//如果是ipip数据包，我们要解封检验
#ifdef INLINE_DECAP_IPIP
   /* This is to workaround a verifier issue for 5.2.
   * The reason is that 5.2 verifier does not handle register
   * copy states properly while 5.6 handles properly.
   *
   * For the following source code:
   *   if (protocol == IPPROTO_IPIP || protocol == IPPROTO_IPV6) {
   *     ...
   *   }
   * llvm12 may generate the following simplified code sequence
   *   100  r5 = *(u8 *)(r9 +51)  // r5 is the protocol
   *   120  r4 = r5
   *   121  if r4 s> 0x10 goto target1
   *   122  *(u64 *)(r10 -184) = r5
   *   123  if r4 == 0x4 goto target2
   *   ...
   *   target2:
   *   150  r1 = *(u64 *)(r10 -184)
   *   151  if (r1 != 4) { __unreachable__}
   *
   * For the path 123->150->151, 5.6 correctly noticed
   * at insn 150: r4, r5, *(u64 *)(r10 -184) all have value 4.
   * while 5.2 has *(u64 *)(r10 -184) holding "r5" which could be
   * any value 0-255. In 5.2, "__unreachable" code is verified
   * and it caused verifier failure.
   */
  if(protocol == IPPROTO_IPIP) {
    bool pass = true;
    action = check_decap_dst(&pckt, is_ipv6, &pass);
    if(action >= 0) {
        return action;
    }
    return process_encaped_ipip_pckt(&data, &data_end, ctx, &is_ipv6, &protocol, pass);
  } else if (protocol == IPPROTO_IPV6) {
    bool pass = true;
    action = check_decap_dst(&pckt, is_ipv6, &pass);
    if(action >= 0) {
        return action;
    }
    return process_encaped_ipip_pckt(&data, &data_end, ctx, &is_ipv6, &protocol, pass);
  }
#endif //INLINE_DECAP_IPIP

    if(protocol == IPPROTO_TCP) {
        if(!parse_tcp(data, data_end, is_ipv6, &pckt)) {
            return XDP_DROP;
        }
    } else if (protocol == IPPROTO_UDP) {
        if(!parse_udp(data, data_end, is_ipv6, &pckt)) {
            return XDP_DROP;
        }
#ifdef INLINE_DECAP_GUE
        if(pckt.flow.port16[1] == bpf_htons(GUE_DPORT)) { //目的端口是gue数据包传输的端口
            bool pass = true;
            action = check_decap_dst(&pckt, is_ipv6, &pass);
            if(action >= 0) {
                return action;
            }
            return process_encaped_gue_pckt(&data, &data_end, ctx, nh_off, is_ipv6, pass);
        }
#endif //INLINE_DECAP_GUE
    } else {
        return XDP_PASS; //交给内核栈
    }

    if(is_ipv6) {
        memcpy(vip.vipv6, pckt.flow.dstv6, 16);
    } else {
        vip.vip = pckt.flow.dst;
    }

    vip.port = pckt.flow.port16[1];
    vip.proto = pckt.flow.proto;
    vip_info = bpf_map_lookup_elem(&vip_map, &vip);
    if(!vip_info) {
        vip.port = 0;
        //在找一遍看有没有
        vip_info = bpf_map_lookup_elem(&vip_map, &vip);
        if(!vip_info) {
            return XDP_PASS; //交给内核栈
        }
        /*
        VIP，
        它不关心 dst 端口
        （所有发送到此 VIP 的数据包，
        带有不同的 dst 端口，
        但来自同一个 src 端口/ip 
        必须发送到同一个 real
        */
        if(!(vip_info->flags & F_HASH_DPORT_ONLY) &&
            !(vip_info->flags & F_HASH_SRC_DST_ONLY)) {
                pckt.flow.port16[1] = 0;
            }
    }

    if(data_end - data > MAX_PCKT_SIZE) {
        //发出警告，暂且没有
#ifdef ICMP_TOOBIG_GENERATION
        __u32 stats_key = MAX_VIPS + ICMP_TOOBIG_CNTRS;
        data_stats = bpf_map_lookup_elem(&stats, &stats_key);
        if(!data_stats) {
            return XDP_DROP;//数据包超出限制大小，丢弃
        }
        if(is_ipv6) {
            data_stats->v2++; //计数
        } else {
            data_stats->v1++;
        }

        return send_icmp_too_big(ctx, is_ipv6, data_end - data);
#else
        return XDP_DROP;
#endif
    }

    __u32 stats_key = MAX_VIPS + LRU_CNTRS;
    data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if(!data_stats) {
        return XDP_DROP;
    }

    data_stats->v1++;

    if(vip_info->flags & F_HAHS_NO_SRC_PORT) {
        //service，其中 diff src 端口，但同一个 IP 必须去同一个 real，
        pckt.flow.port16[0] = 0;
    }

    vip_num = vip_info->vip_num; //hansh环的位置
    /*
    获取 SMP（对称多处理）处理器 ID。
    请注意，所有程序在禁用迁移的情况下运行，
    这意味着 SMP 处理器 ID 在程序执行期间是稳定的。
    返回
    运行该程序的处理器的 SMP ID。
    */
    __u32 cpu_num = bpf_get_smp_processor_id();
    void* lru_map_ = bpf_map_lookup_elem(&lru_mapping, &cpu_num);
    if(!lru_map_) {
        //没有找到
        lru_map_ = &fallback_cache;
        __u32 lru_stats_key = MAX_VIPS + FALLBACK_LRU_CNTRS;
        struct lb_stats* lru_stats = bpf_map_lookup_elem(&stats, &lru_stats_key);
        if(!lru_stats) {
            return XDP_DROP;
        }
        //我们无法检索每个 CPU/内核的 lru 并回退到
        //默认 1 个。这个计数器在 prod(生产环境) 中不应该是 0 以外的任何值。
        //我们将使用它来进行监控。
        lru_stats->v1++;
    }

    //支持quic协议
    if(vip_info->flags & F_QUIC_VIP) {
        bool is_icmp = (pckt.flags & F_ICMP);
        if(is_icmp) {
            /*
            根据 rfc792，“Destination Unreachable Message”具有 Internet 报头加上原始数据报数据的前 64 位。
            因此，不能保证在 icmp 消息中具有完整的 quic 标头。
            此外，如果原始数据报中的 QUIC Headers 是短 Headers，
            则它没有服务器生成的可用于路由的连接 ID。
            回退到 CH 以路由 QUIC ICMP 消息。
            */
           __u32 stats_key = MAX_VIPS + QUIC_ICMP_STATS;
           struct lb_stats* data_stats = bpf_map_lookup_elem(&stats, &stats_key);
            if(!data_stats) {
                return XDP_DROP;
            }
            data_stats->v1++;
            if(ignorable_quic_icmp_code(data, data_end, is_ipv6)) {
                data_stats->v2++;
            }
        } else {
            __u32 quic_packets_stats_key = 0;
            struct lb_quic_packets_stats* quic_packets_stats = 
                bpf_map_lookup_elem(&quic_stats_map, &quic_packets_stats_key);
            if(!quic_packets_stats) {
                return XDP_DROP;
            }

            struct quic_parse_result quic_res = parse_quic(data, data_end, is_ipv6, &pckt);
            if(quic_res.server_id > 0) {
                //增加计数
                increment_quic_cid_version_stats(quic_packets_stats, quic_res.cid_version);
                __u32 key = quic_res.server_id;//以server_id为key，查找真实节点
                __u32* real_pos = bpf_map_lookup_elem(&server_id_map, &key);
                if(real_pos) {
                    key = *real_pos;
                    if(key == 0) {
                        //错误计数
                        quic_packets_stats->cid_invalid_server_id++;
                        quic_packets_stats->cid_invalid_server_id_sample = quic_res.server_id; //错误的server_id
                        quic_packets_stats->ch_routed++; //路由
                    } else {
                        pckt.real_index = key;//存储服务器的真实节点
                        dst = bpf_map_lookup_elem(&reals, &key);
                        if(!dst) {
                            quic_packets_stats->cid_unknown_real_dropped++;
                            //发出警告
                            return XDP_DROP; //丢弃数据包
                        }
                        int res = check_and_update_real_index_in_lru(&pckt, lru_map_);
                        if(res == DST_MATCH_IN_LRU) {
                            quic_packets_stats->dst_match_in_lru++;
                        } else if(res == DST_MISMATCH_IN_LRU) {
                            quic_packets_stats->dst_mismatch_in_lru++;
                            incr_server_id_routing_stats(vip_num, false, true);
                        } else {
                            quic_packets_stats->dst_not_found_in_lru++;
                        }
                        quic_packets_stats->cid_routed++;
                    }
                } else {
                    //无法得到服务器id的真实位置--real_pos
                    quic_packets_stats->cid_invalid_server_id++;
                    quic_packets_stats->cid_invalid_server_id_sample = quic_res.server_id;
                    quic_packets_stats->ch_routed++; //hash环错误计数
                }
            } else if (!quic_res.is_initial) {
                    //不需要初始化，意味着不是新的连接
                    quic_packets_stats->ch_routed++;
            } else {
                //需要初始化，是新的连接
                quic_packets_stats->cid_initial++;
                incr_server_id_routing_stats(vip_num, true, false);
            }
        }
    }
#ifdef UDP_STABLE_ROUTING
    if(pckt.flow.proto == IPPROTO_UDP && 
        vip_info->flags & F_UDP_STABLE_ROUTING_VIP) {
            process_udp_stable_routing(data, data_end, &dst, &pckt, is_ipv6);
    }
#endif //UDP_STABLE_ROUTING

    /*
    在进行 Real Selection 之前保存原始 Sport，可能会更改其值。
    */
    original_sport = pckt.flow.port16[0];//sport


    if(!dst){ //为空，新的连接
#ifdef TCP_SERVER_ID_ROUTING  
        if(pckt.flow.proto == IPPROTO_TCP) {
            __u32 tpr_packets_stats_key = 0;
            struct lb_tpr_packets_stats* tpr_packets_stats_ = 
            bpf_map_lookup_elem(&tpr_stats_map, &tpr_packets_stats_key);
            if(!tpr_packets_stats_) {
                return XDP_DROP;
            }

            if(pckt.flags & F_SYN_SET) {
                tpr_packets_stats_->tcp_syn++;
                incr_server_id_routing_stats(
                    vip_num, true, false
                );
            } else {
                if(tcp_hdr_opt_lookup(ctx, is_ipv6, &dst, &pckt) == FURTHER_PROCESSING) {
                    tpr_packets_stats_->ch_routed++;
                } else {
                    if(lru_map && (vip_info->flags & F_LRU_BYPASS)) {
                        int res = check_and_update_real_index_in_lru(&pckt, lru_map);
                        if(res == DST_MISMATCH_IN_LRU) {
                            tpr_packets_stats_->dst_mismatch_in_lru++;
                            incr_server_id_routing_stats(vip_num, false, true);
                        }
                    }
                    tpr_packets_stats_->sid_routed++;
                } 
            }
        }
#endif //
        //在缓存中寻找lru
        //排除三种情况
        //1：没有找到dst
        //2：数据包的标志没有F_SYN_SET，意味着不是第一次连接
        //3：虚拟ip的标志为中没有F_LRU_BYPASS，
        if(!dst && 
        !(pckt.flags & F_SYN_SET) && 
        !(vip_info->flags & F_LRU_BYPASS)) {
            connecttion_table_lookup(&dst, &pckt, lru_map_, /*isGloballru*/false);
        }

#ifdef GLOBAL_LRU_LOOKUP
        if(!dst && 
        !(pckt.flags & F_SYN_SET) && 
        (vip_info->flags & F_GLOBAL_LRU)) {
            int global_lru_lookup_result = 
                perform_global_lru_lookup(&dst, &pckt, cpu_num, vip_info, is_ipv6);
            if(global_lru_lookup_result >= 0) {
                return global_lru_lookup_result;
            }
        }
#endif //GLOBAL_LRU_LOOKUP

        if(!dst) {
            if(pckt.flow.proto == IPPROTO_TCP) {
                __u32 lru_stats_key = MAX_VIPS + LRU_MISS_CNTRS;
                struct lb_stats* lru_stats = 
                    bpf_map_lookup_elem(&stats, &lru_stats_key);
                if(!lru_stats) {
                    return XDP_DROP;
                }

                if(pckt.flags & F_SYN_SET) {
                    //由于新的 TCP 会话而错过
                    lru_stats->v1++;
                } else {
                    /*
                    非 SYN TCP 数据包未命中。可能是因为 LRU
                    垃圾桶或因为另一个 katran 正在重新启动，并且所有
                    会话已重新洗牌
                    */
                   //报告丢失 no_syn_lru_miss
                   lru_stats->v2++;
                }
            }
            
            // 2025-2-6-21:56
            if(!get_packet_dst(&dst, &pckt, vip_info, is_ipv6, lru_map_)) {
                return XDP_DROP;
            }

            if(update_vip_lru_miss_stats(&vip, &pckt, vip_info, is_ipv6)) {
                return XDP_DROP;
            }
            data_stats->v2++;
        }
    }

    cval = bpf_map_lookup_elem(&ctl_array, &mac_addr_pos);

    if(!cval) {
        return XDP_DROP;
    }

    data_stats = bpf_map_lookup_elem(&stats, &vip_num); 
    {
        if(!data_stats) {
            return XDP_DROP;
        }
        data_stats->v1++;
        data_stats->v2+= pkt_bytes; //数据包的大小
    }

    data_stats = bpf_map_lookup_elem(&reals_stats, &pckt.real_index);
    if(!data_stats) {
        return XDP_DROP;
    }

    data_stats->v1++;
    data_stats->v2+= pkt_bytes;

    //local_delivery_optimization 本地配送优化
#ifdef LOCAL_DELIVERY_OPTIMIZATION
    if((vip_info->flags & F_LOCAL_VIP) && (dst->flags & F_LOCAL_REAL)) {
        return XDP_PASS;
    }
#endif

    //封装操作
    //恢复原始 sport 值，将其用作 GUE 运动的种子
    pckt.flow.port16[0] = original_sport;
    if(dst->flags & F_IPV6) {
        if(!PCKT_ENCAP_V6(ctx, cval, is_ipv6, &pckt, dst, pkt_bytes)) {
            return XDP_DROP;
        }
    } else {
        if(!PCKT_ENCAP_V4(ctx, cval, is_ipv6, &pckt, dst, pkt_bytes)) {
            return XDP_DROP;
        }
    }
    return XDP_TX;
}



SEC(PROG_SEC_NAME)
int balancer_ingress(struct xdp_md *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct ethhdr* eth = data;
    __u32 eth_proto;
    __u32 nh_off;

    nh_off = sizeof(struct ethhdr);

    if(data + nh_off > data_end) {
        return XDP_DROP; //错误数据包
    }

    eth_proto = eth->h_proto;

    if(eth_proto == BE_ETH_P_IP) {
        return process_packet(ctx, nh_off, false);
    } else if(eth_proto == BE_ETH_P_IPV6) {
        return process_packet(ctx, nh_off, true);
    } else {
        return XDP_PASS; //交给内核栈处理
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";







