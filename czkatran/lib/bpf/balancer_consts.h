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

//FLAGS
#define F_ICMP (1 << 0)
#define F_SYN_SET (1 << 1)




#ifndef GUE_DPORT
#define GUE_DPORT 6080
#endif

//GUE 变体 1 使用内部数据包的前四位作为伪报头，我们使用这四位中的最后两位来区分 v4 和 v6。有关详细信息，请参阅 RFC
#define GUEV1_IPV6MASK 0x30 // 0011 0000

//XDP_ABORTED：表示 XDP 程序处理数据包时遇到错误或异常。

//XDP_DROP：在网卡驱动层直接将该数据包丢掉，通常用于过滤无效或不需要的数据包，如实现 DDoS 防护时，丢弃恶意数据包。

//XDP_PASS：数据包继续送往内核的网络协议栈，和传统的处理方式一致。这使得 XDP 可以在有需要的时候，继续使用传统的内核协议栈进行处理。

//XDP_TX：数据包会被重新发送到入站的网络接口（通常是修改后的数据包）。这种操作可以用于实现数据包的快速转发、修改和回环测试（如用于负载均衡场景）。

//XDP_REDIRECT：数据包重定向到其他的网卡或 CPU，结合 AF_XDP[2]可以将数据包直接送往用户空间。


#if defined(TCP_SERVER_ID_ROUTING) || defined(DECAP_TPR_STATS)
//原本的tcp中的option端的格式为：
// kind/type (1 byte) | length (1 byte) | value 
//cap： the structure of header-option to save server_id
// kind/type (1 byte) | length (1 byte) | server_id (4 bytes)

#define TCP_HDR_OPT_KIND_TPR 0xB7

#define TCP_HDR_OPT_LEN_TPR 6 // = 1 + 1 + 4

#define TCP_HDR_OPT_MAX_OPT_CHECKS 15

#define TCP_OPT_EOF 0

#define TCP_OPT_NOP 1

#endif // TCP_SERVER_ID_ROUTING || DECAP_TPR_STATS








#endif // BALANCER_CONSTS_H