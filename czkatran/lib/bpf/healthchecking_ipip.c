#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/string.h>


#include <bpf/bpf.h>
#include <bpf/bpf_helpers.h>

#include "balancer_consts.h"
#include "healthchecking.consts.h"
#include "balancer_structs.h"
#include "healthchecking.maps.h"

SEC("tc")
int healthcheck_encap(struct __sk_buff* skb) {
    int action = 0;
    int tun_falgs = 0;
    __u32 intifindex;
    __u32 somark = skb->mark;
    __u32 v4_intf_pos = 1;
    __u32 v6_intf_pos = 2;

    struct bpf_tunnel_key tkey = {};
    struct hc_stats* prog_stas;
    __u32 stats_key = GENERIC_STATS_INDEX;

    prog_stas = bpf_map_lookup_elem(&hc_stats_map, &stats_key);
    if(!prog_stas) {
        return TC_ACT_UNSPEC;
    }
    if(somark == 0) {
        prog_stas->pckts_skipped++;
        return TC_ACT_UNSPEC;
    }

    struct hc_real_definition* real =
        bpf_map_lookup_elem(&hc_real_map, &somark);
    if(!real) {
        prog_stas->pckts_skipped++;
        return TC_ACT_UNSPEC;
    }

    //超出定义数据报的大小
    if(skb->len > MAX_PCKT_SIZE) {
        prog_stas->pckts_dropped++;
        prog_stas->pckts_too_big++;
        return TC_ACT_UNSPEC;
    }

    __u32* v4_intf_ifindex = bpf_map_lookup_elem(&hc_ctrl_map, &v4_intf_ifindex);
    if(!v4_intf_ifindex) {
        prog_stas->pckts_dropped++;
        return TC_ACT_UNSPEC;
    }

    __u32* v6_intf_ifindex = bpf_map_lookup_elem(&hc_ctrl_map, &v6_intf_ifindex);
    if(!v6_intf_ifindex) {
        prog_stas->pckts_dropped++;
        return TC_ACT_UNSPEC;
    }

    tkey.tunnel_ttl = DEFAULT_TTL;

    skb->mark = 0;

    if(real->flags == V6DADDR) {
        tun_falgs = BPF_F_TUNINFO_IPV6;
        memcpy(tkey.remote_ipv6, real->addrv6, 16);
        intifindex = *v6_intf_ifindex;
    } else {
        tkey.remote_ipv4 = real->addr;
        intifindex = *v4_intf_ifindex;
    }
    prog_stas->pckts_processed++;
    bpf_skb_set_tunnel_key(skb, &tkey, sizeof(tkey), tun_falgs);
    return bpf_redirect(intifindex, REDIRECT_EGRESS);
}

char _license[] SEC("license") = "GPL";

