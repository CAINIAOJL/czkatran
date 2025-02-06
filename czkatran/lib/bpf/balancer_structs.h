#ifndef BALANCER_STRUCTS_H
#define BALANCER_STRUCTS_H

//所有用到的结构体定义

// flow metadata
struct flow_key {
    union {
        __be32 src;
        __be32 srcv6[4];
    };
    union {
        __be32 dst;
        __be32 dstv6[4];
    };
    union {
        __u32 ports;
        __u16 port16[2]; //0 source port, 1 dest port
    };
    __u8 proto;
};

//client's packet metadata
struct packet_description {
    struct flow_key flow;
    __u32 real_index;
    __u8 flags;
    __u8 tos; // type of service 看关于tos的定义与用法
};

//the place client's packet should be sent to 
struct real_definition {
    union {
        __be32 dst;
        __be32 dstv6[4];
    };//目的ip地址
    __u8 flags;
};

// where to send client's packet from LRU_MAP
struct real_pos_lru {
    __u32 pos;
    __u64 atime;
};

struct hdr_opt_state {
    __u32 server_id;
    __u8 bytes_offset;
    __u8 hdr_bytes_remaining;
};

struct ctl_value {
    union {
        /* data */
        __u64 value;
        __u32 ifindex; //网口的索引
        __u8 mac[6];//mac地址
    };
};

struct vip_definition {
    union {
        __be32 vip;
        __be32 vipv6[4];
    };//虚拟IP地址
    __u16 port;
    __u8 proto;
};

//虚拟元数据
struct vip_meta {
    __u32 flags;
    __u32 vip_num;//在hash环中的位置
};

struct address {
    union 
    {
        __be32 addr;
        __be32 addrv6[4];
    };
};

struct lb_stats {
    __u64 v2;
    __u64 v1;
};

struct lb_quic_packets_stats {
    __u64 ch_routed;
    __u64 cid_initial;
    __u64 cid_invalid_server_id;
    __u64 cid_invalid_server_id_sample;
    __u64 cid_routed;
    __u64 cid_unknown_real_dropped;
    __u64 cid_v0;
    __u64 cid_v1;
    __u64 cid_v2;
    __u64 cid_v3;
    __u64 dst_match_in_lru;
    __u64 dst_mismatch_in_lru;
    __u64 dst_not_found_in_lru;
};

struct lb_stable_rt_packets_stats {
    __u64 ch_routed;
    __u64 cid_routed;
    __u64 cid_invalid_server_id;
    __u64 cid_unknown_real_dropped;
    __u64 invalid_packet_type;
};

struct lb_tpr_packets_stats {
    __u64 ch_routed;
    __u64 dst_mismatch_in_lru;
    __u64 sid_routed;
    __u64 tcp_syn;
};


#endif /* BALANCER_STRUCTS_H */