#pragma once

#include <cstdint>

namespace czkatran {

struct ctl_value {
    union {
        uint64_t value; //value of the control variable
        uint32_t ifindex; //interface index
        uint8_t mac[6]; //mac地址
    };
};


struct lb_stats {
    uint64_t v1;
    uint64_t v2;
};


struct event_metadata {
    uint32_t events;
    uint32_t pkt_len;
    uint32_t data_len;
}__attribute__((__packed__));

//------------------------------------2025-2-14-------------------------------
//--------------------------√
struct vip_meta {
    uint32_t flags;
    uint32_t vip_num;
};

struct vip_definition {
    union {
        uint32_t vip;
        uint32_t vipv6[4];
    };
    uint16_t port;
    uint16_t proto;
};
//------------------------------------2025-2-14-------------------------------
//--------------------------√

//------------------------------------2025-2-15-------------------------------
struct v4_lpm_key {
    uint32_t prefixlen;
    uint32_t addr;
};

struct v6_lpm_key {
    uint32_t prefixlen;
    uint32_t addr[4];
};

//------------------------------------2025-2-15-------------------------------

//------------------------------------2025-2-16-------------------------------
struct flow_key {
    union {
        uint32_t src;
        uint32_t srcv6[4];
    };
    union {
        uint32_t dst;
        uint32_t dstv6[4];
    };
    union {
        uint32_t ports;
        uint16_t port16[2];
      };
    uint8_t proto;
};

struct real_pos_lru {
    uint32_t pos;
    uint64_t atime;
};

struct flow_debug_info {
    union {
        uint32_t l4_hop;
        uint32_t l4_hopv6[4];
    };
    union {
        uint32_t this_hop;
        uint32_t this_hopv6[4];
    };
};

struct hc_mac {
    uint8_t mac[6];
};

//------------------------------------2025-2-16-------------------------------

//------------------------------------2025-2-17/9-------------------------------
struct lb_tpr_packets_stats {
    uint64_t ch_routed;
    uint64_t dst_mismatch_in_lru;
    uint64_t sid_routed;
    uint64_t tcp_syn;
};

struct lb_stable_rt_packet_stats {
    uint64_t ch_routed;
    uint64_t cid_routed;
    uint64_t cid_invalid_server_id;
    uint64_t cid_unknown_real_dropped;
    uint64_t invalid_packet_type;
};

struct lb_quic_packets_stats {
    uint64_t ch_routed;
    uint64_t cid_initial;
    uint64_t cid_invalid_server_id;
    uint64_t cid_invalid_server_id_sample;
    uint64_t cid_routed;
    uint64_t cid_unknown_real_dropped;
    uint64_t cid_v0;
    uint64_t cid_v1;
    uint64_t cid_v2;
    uint64_t cid_v3;
    uint64_t dst_match_in_lru;
    uint64_t dst_mismatch_in_lru;
    uint64_t dst_not_found_in_lru;
};

//------------------------------------2025-2-17/9-------------------------------
}