#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/string.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "/home/cainiao/czkatran/czkatran/lib/linux_includes/bpf.h"

#include "encap_helpers.h"

#include "healthchecking.consts.h"
#include "healthchecking_structs.h"
#include "healthchecking.maps.h"
#include "healthchecking_helpers.h"

SEC("tc")
int healthcheck_encap(struct __sk_buff *skb) {
    __u32 stats_key = GENERIC_STATS_INDEX;
    __u32 key = HC_MAIN_INTF_POSITION;
    __u32 somark = skb->mark;
    __u32 ifindex = 0;
    __u64 flags = 0;
    bool is_ipv6;
    struct hc_stats* prog_stas;
    struct hc_real_definition* src;
    struct hc_mac* esrc, *dsrc;
    struct ethhdr* eth;
    prog_stas = bpf_map_lookup_elem(&hc_stats_map, &stats_key);
    if(!prog_stas) {
        return TC_ACT_UNSPEC;
    }

    if(somark == 0) {
        prog_stas->pckts_skipped++;
        return TC_ACT_UNSPEC;
    }

    struct hc_real_definition* real = bpf_map_lookup_elem(&hc_real_map, &somark);
    if(!real) {
        prog_stas->pckts_skipped++;
        return TC_ACT_UNSPEC;
    }
#if HC_MAX_PACKET_SIZE > 0
    prog_stas->pckts_dropped++;
    prog_stas->pckts_too_big++;
    return TC_ACT_SHOT;
#endif

    __u32* intf_ifindex = bpf_map_lookup_elem(&hc_ctrl_map, &key);
    if(!intf_ifindex) {
        prog_stas->pckts_dropped++;
        return TC_ACT_UNSPEC;
    }


    key = HC_SRC_MAC_POS;
    esrc = bpf_map_lookup_elem(&hc_pckt_macs, &key);
    if(!esrc) {
        prog_stas->pckts_dropped++;
        return TC_ACT_UNSPEC;
    }

    key = HC_DST_MAC_POS;
    dsrc = bpf_map_lookup_elem(&hc_pckt_macs, &key);
    if(!dsrc) {
        prog_stas->pckts_dropped++;
        return TC_ACT_UNSPEC;
    }

    if((skb->data + sizeof(struct ethhdr)) > skb->data_end) {
        prog_stas->pckts_dropped++;
        return TC_ACT_SHOT;
    }

    //获取h_proto
    eth = (void*)(long)skb->data;
    if(eth->h_proto == BE_ETH_P_IPV6) {
        is_ipv6 = true;
    }

    struct hc_key hckey = {};

    bool hc_key_parseable = set_hc_key(skb, &hckey, is_ipv6);

    skb->mark = 0;

    if(!HC_ENCAP(skb, real, eth, is_ipv6)) {
        prog_stas->pckts_dropped++;
        return TC_ACT_SHOT;
    }

    if(skb->data + sizeof(struct ethhdr) > skb->data_end) {
        prog_stas->pckts_dropped++;
        return TC_ACT_SHOT;
    }

    //构造
    eth = (void*)(long)skb->data;
    memcpy(eth->h_source, esrc->mac, 6);
    memcpy(eth->h_dest, dsrc->mac, 6);

    prog_stas->pckts_processed++;

    if(hc_key_parseable) {
        __u32* hc_key_cntr_index = bpf_map_lookup_elem(&hc_key_map, &hckey);
        if(hc_key_cntr_index) {
            __u32* packet_processd_for_hc_key = 
                bpf_map_lookup_elem(&per_hckey_stats, hc_key_cntr_index);
            if(packet_processd_for_hc_key) {
                *packet_processd_for_hc_key++; //计数加一
            }
        }
    }
    return bpf_redirect(*intf_ifindex, REDIRECT_EGRESS);//转发

}
char _license[] SEC("license") = "GPL";