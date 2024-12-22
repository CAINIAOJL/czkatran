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
    };
    __u8 flags;
};


struct hdr_opt_state {
    __u32 server_id;
    __u8 bytes_offset;
    __u8 hdr_bytes_remaining;
};





#endif /* BALANCER_STRUCTS_H */