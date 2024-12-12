// 所有用到的宏
#ifndef BALANCER_CONSTS_H
#define BALANCER_CONSTS_H

//xdp_md中的proto字段
#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710

//ipv4/ipv6头部长度
#define IPV4_HDR_LEN_NO_OPT 20
#define IPV4_HDR_LEN_PLUS_ICMP 28
#define IPV6_HDR_LEN_PLUS_ICMP 48

//暂且不知
#define PACKET_FRAGMENTED 65343

//继续处理
#define FURTHER_PROCESSING -1

//index for packet_srcs table--->(BPF_MAP_TYPE_ARRAY)
#define V4_SRC_INDEX 0
#define V6_SRC_INDEX 1


#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710

#define XDP_ADJUST_HEAD_FUNC bpf_xdp_adjust_head

//XDP_ABORTED：表示 XDP 程序处理数据包时遇到错误或异常。

//XDP_DROP：在网卡驱动层直接将该数据包丢掉，通常用于过滤无效或不需要的数据包，如实现 DDoS 防护时，丢弃恶意数据包。

//XDP_PASS：数据包继续送往内核的网络协议栈，和传统的处理方式一致。这使得 XDP 可以在有需要的时候，继续使用传统的内核协议栈进行处理。

//XDP_TX：数据包会被重新发送到入站的网络接口（通常是修改后的数据包）。这种操作可以用于实现数据包的快速转发、修改和回环测试（如用于负载均衡场景）。

//XDP_REDIRECT：数据包重定向到其他的网卡或 CPU，结合 AF_XDP[2]可以将数据包直接送往用户空间。


#endif // BALANCER_CONSTS_H