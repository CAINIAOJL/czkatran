#pragma once

#define GENERIC_STATS_INDEX 0

#define HC_MAIN_INTF_POSITION 3

#define STATS_SIZE 1

/*
指定最大数据包大小以避免数据包超过 mss（封装后）
当设置为 0 时，healthchecker_kern 不会执行 SKB 长度检查，
依靠 GSO 对传输路径上超过 MSS 的数据包进行分段
*/
/*
TSO(TCP Segmentation Offload): 是一种利用网卡来对大数据包进行自动分段，降低CPU负载的技术。 其主要是延迟分段。

GSO(Generic Segmentation Offload): GSO是协议栈是否推迟分段，在发送到网卡之前判断网卡是否支持TSO，如果网卡支持TSO则让网卡分段，否则协议栈分完段再交给驱动。 如果TSO开启，GSO会自动开启。
*/
#ifndef HC_MAX_PACKET_SIZE
#define HC_MAX_PACKET_SIZE 0
#endif


#define CTRL_MAP_SIZE 4

#define HC_SRC_MAC_POS 0
#define HC_DST_MAC_POS 1

#define V6DADDR (1 << 0)

// for ip-in-ip encap
// source address of the healthcheck would be crafted the same way as data
// packet
// #define MANGLE_HC_SRC 1
#define MANGLED_HC_SRC_PORT 31337

#define REDIRECT_EGRESS 0