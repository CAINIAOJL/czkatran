#pragma once

#include <bpf/bpf_helpers.h>
#include "/home/cainiao/czkatran/czkatran/lib/linux_includes/bpf.h"

#include "balancer_consts.h"
#include "healthchecking.consts.h"
#include "healthchecking_structs.h"


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, STATS_SIZE);
    __type(key, __u32);
    __type(value, struct hc_stats);
} hc_stats_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_REALS); 
    __type(key, __u32);
    __type(value, struct hc_real_definition);
} hc_real_map SEC(".maps");
 

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, CTRL_MAP_SIZE);
} hc_ctrl_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct hc_mac);
} hc_pckt_macs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, struct hc_real_definition);
} hc_pckt_srcs_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_VIPS);
    __type(key, struct hc_key);
    __type(value, __u32);
} hc_key_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_VIPS);
    __type(key, __u32);
    __type(value, __u64);
}per_hckey_stats SEC(".maps");