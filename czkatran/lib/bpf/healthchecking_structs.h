#pragma once

struct hc_real_definition {
    union {
        __be32 addr;
        __be32 addrv6[4];
    };
    __u8 flags;
};

struct hc_stats {
    __u64 pckts_processed;
    __u64 pckts_dropped;
    __u64 pckts_skipped;
    __u64 pckts_too_big;
};


struct hc_key {
    union {
        __be32 addr;
        __be32 addrv6[4];
    };
    __u16 port;
    __u8 proto;
};

struct hc_mac {
    __u8 mac[6];
};


