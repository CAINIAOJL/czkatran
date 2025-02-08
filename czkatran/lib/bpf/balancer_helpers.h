#pragma once

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stdbool.h>


#include "balancer_consts.h"
#include "balancer_structs.h"
#include "control_data_maps.h"
#include "csum_helpers.h"


//~
#ifdef INLINE_DECAP_GENERIC
__always_inline static int recirculate(
    struct xdp_md* ctx
) {
    int i = RECIRCULATION_INDEX;
    bpf_tail_call(ctx, &subprograms, i);
    return XDP_PASS;
}
#endif //INLINE_DECAP_GENERIC

//~
__always_inline static int decrement_ttl(
    void* data,
    void* data_end,
    int offset,
    bool is_ipv6
)
{
    struct iphdr* ip_hdr;
    struct ipv6hdr* ipv6_hdr;

    if(is_ipv6) {
        if((data + offset + sizeof(struct ipv6hdr)) > data_end) {
            return XDP_DROP;
        }
        ipv6_hdr = (struct ipv6hdr*)(data + offset);
        if(!--ipv6_hdr->hop_limit) {
            //ttl跳数位0
            return XDP_DROP;
        }
    } else {
        //ipv4需要校验csum
        if((data + offset + sizeof(struct iphdr)) > data_end) {
            return XDP_DROP;
        }
        ip_hdr = (struct iphdr*)(data + offset);
        __u32 csum = 0;
        if(!--ip_hdr->ttl) {
            //ttl = 0
            return XDP_DROP;
        }
        csum = ip_hdr->check + 0x0001;
        //折叠操作：前16位于后16位相加
        ip_hdr->check = (csum & 0xffff) + (csum >> 16); 
    }
    return FURTHER_PROCESSING;
}

//完整的测试bpf_xdp_adjust_head
__always_inline static int test_bpf_xdp_adjust_head(
    struct xdp_md* ctx,
    int delta //偏移量
)
{
    long res = bpf_xdp_adjust_head(ctx, delta);
    if(res) {
        return res;
    }
    //delta大于0，表示扩张操作
    if(delta >= 0) {
        return res;
    }

    //重新验证指针位置，在调整后，指针可能不在有效范围内
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;
    int offset = 0 - delta;
    if(data + offset > data_end) {
        return -1;
    }
    memset(data, 0xFF, offset);

    return res;
}

#ifdef CZKATRAN_TEST_MODE
#define XDP_ADJUST_HEAD_FUNC test_bpf_xdp_adjust_head
#else
#define XDP_ADJUST_HEAD_FUNC bpf_xdp_adjust_head
#endif