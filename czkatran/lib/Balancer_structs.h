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












}