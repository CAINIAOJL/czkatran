#pragma once

#include <bpf/bpf.h>
#include <bpf/bpf_helpers.h>

#include "balancer_consts.h"
#include "balancer_structs.h"

//存放vip信息：vip地址和端口对应hash环的num序号
struct {
    __uint(type, BPF_MAP_TYPE_HASH);//hash表
    __uint(max_entries, MAX_VIPS);
    __type(key, struct vip_definition);
    __type(value, struct vip_meta);
} vip_map SEC(".maps");

//vip对应的lb_stats状态记录
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);//每个cpu上保存一份
    __uint(max_entries, MAX_VIPS);
    __type(key, __u32);
    __type(value, struct lb_stats);
} decap_vip_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_MAP_SIZE);
    __type(key, __u32);
    __type(value, struct lb_stats);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, QUIC_STATS_MAP_SIZE);
    __type(key, __u32);
    __type(value, struct lb_quic_packets_stats);
} quic_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_QUIC_REALS);//真实服务器数量
    __type(key, __u32);
    __type(value, __u32);
} server_id_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, MAX_SUPPORTED_CPUS);
    __type(key, __u32);
    __type(value, __u32);
    __array(
        values,
        struct {
            __uint(type, BPF_MAP_TYPE_LRU_HASH); //lru hash表
            __uint(max_entries, DEFAULT_LRU_SIZE);
            __type(key, struct flow_key);
            __type(value, struct real_pos_lru);
        }
    );
} lru_mapping SEC(".maps");

//当上述map在寻找时落空时，补充的cache
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DEFAULT_LRU_SIZE);
    __type(key, struct flow_key);
    __type(value, struct real_pos_lru);
} fallback_cache SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_REALS);
    __type(key, __u32);
    __type(value, struct real_definition);
} reals SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_VIPS);
    __type(key, __u32);
    __type(value, struct lb_stats);
} server_id_stats SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STABLE_RT_STATS_MAP_SIZE);
    __type(key, __u32);
    __type(value, struct lb_stable_rt_packets_stats);
} stable_rt_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, TPR_STATS_MAP_SIZE);
    __type(key, __u32);
    __type(value, struct lb_tpr_packets_stats);
} tpr_stats_map SEC(".maps");

#ifdef GLOBAL_LRU_LOOKUP

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, MAX_SUPPORTED_CPUS);
    __type(key, __u32);
    __type(value, __u32);
    __array(value,
        struct {
            __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
            __uint(max_entries, DEFAULT_LRU_SIZE);
            __type(key, struct flow_key);
            __type(value, __u32);
        }
    );
} global_lru_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, DEFAULT_LRU_SIZE);
    __type(key, struct flow_key);
    __type(value, __u32);
} fallback_glru SEC(".maps");

#endif