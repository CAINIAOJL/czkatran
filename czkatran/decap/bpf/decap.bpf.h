#pragma once

//#include <czkatran/lib/linux_includes/bpf.h>
//#include <czkatran/lib/linux_includes/bpf_helpers.h>
#include "/home/cainiao/czkatran/czkatran/lib/bpf/balancer_consts.h"

#include "/home/cainiao/czkatran/czkatran/lib/linux_includes/bpf.h"
#include <bpf/bpf_helpers.h>
// maps used by LB decap

#ifndef DECAP_STATS_MAP_SIZE
#define DECAP_STATS_MAP_SIZE 1
#endif

struct decap_stats {
    __u64 decap_v4;
    __u64 decap_v6;
    __u64 total;
    __u64 tpr_misrouted;
    __u64 tpr_total;
};


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DECAP_STATS_MAP_SIZE);
    __type(key, __u32); //vip 虚拟IP地址
    __type(value, struct decap_stats);  //stats 统计信息
} decap_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, DECAP_STATS_MAP_SIZE);
    __type(key, __u32);
    __type(value, __u32);
} tpr_server_id SEC(".maps");



