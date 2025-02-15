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








}