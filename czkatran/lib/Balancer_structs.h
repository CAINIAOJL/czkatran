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













}