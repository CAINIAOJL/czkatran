#pragma once

#include <bpf/bpf.h>
#include <bpf/bpf_helpers.h>
#include "balancer_consts.h"
#include "balancer_structs.h"

#ifdef INLINE_DECAP_GENERIC
struct {
    __uint(type, BPF_MAP_TYPE_HASH);//hash表
    __uint(max_entries, MAX_VIPS);
    __type(key, struct address);
    __type(value, __u32);
} decap_dst SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, SUBPROGRAMS_ARRAY_SIZE);
    __type(key, __u32);
    __type(value, __u32);
} subprograms SEC(".maps");

#endif //INLINE_DECAP_GENERIC




#if defined(GUE_ENCAP) || defined(DECAP_STRICT_DESTINATION) 

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct real_definition);
} packet_srcs SEC(".maps");
#endif
