// 所有用到的宏
#ifndef BALANCER_CONSTS_H
#define BALANCER_CONSTS_H

#define CTL_MAP_SIZE 16

//xdp_md中的proto字段
#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710

//ipv4/ipv6头部长度
#define IPV4_HDR_LEN_NO_OPT 20
#define IPV4_HDR_LEN_PLUS_ICMP 28
#define IPV6_HDR_LEN_PLUS_ICMP 48

//ip分片数据包
#define PACKET_FRAGMENTED 65343

//继续处理
#define FURTHER_PROCESSING -1

#define STABLE_RT_NO_SERVER_ID 0

//index for packet_srcs table--->(BPF_MAP_TYPE_ARRAY)
#define V4_SRC_INDEX 0
#define V6_SRC_INDEX 1


#define BE_ETH_P_IP 8
#define BE_ETH_P_IPV6 56710

#define XDP_ADJUST_HEAD_FUNC bpf_xdp_adjust_head

#define ICMP_TOOBIG_CNTRS 4

// 30 sec in nanosec
#ifndef LRU_UDP_TIMEOUT 
#define LRU_UDP_TIMEOUT 30000000000U 
#endif


//FLAGS
#define F_ICMP (1 << 0)

#define F_IPV6 (1 << 0)

#define F_SYN_SET (1 << 1)

#define F_HAHS_NO_SRC_PORT (1 << 0)

#define F_LRU_BYPASS (1 << 1)

#define F_LOCAL_REAL (1 << 1)

#define F_QUIC_VIP (1 << 2)

#define F_HASH_DPORT_ONLY (1 << 3)

//FMP算法
#define F_SRC_ROUTING (1 << 4)

#define F_LOCAL_VIP (1 << 5)

#define F_GLOBAL_LRU (1 << 6)

#define F_HASH_SRC_DST_ONLY (1 << 7)

#define F_UDP_STABLE_ROUTING_VIP (1 << 8)

#define SUBPROGRAMS_ARRAY_SIZE 1 //subprograms array size

#define RECIRCULATION_INDEX 0 //recirculation index


/*
如果请求的 MTU 小于此数字，
则丢弃 ICMP PTB/需要分段的消息。
如果请求的 MTU 大于该值，
它们将通过 CH 传送到后端服务器。
特别是对于 QUIC ICMP 消息，
在建立连接后，由于 5 元组的变化，
某些消息可能会路由错误。在一段时间超时后自动恢复后，
影响应该是暂时的。
由于已知攻击，最好丢弃请求 MTU 较小的 ICMP 消息，
以请求较小的 MTU 来强制分段并增加开销。
目前，我们只收集 katran stats 中的数据，
而不会删除它们。
 */
#define MAX_MTU_IN_PTB_TO_DROP 1280 // 1500


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

#ifndef MAX_SUPPORTED_CPUS
#define MAX_SUPPORTED_CPUS 128
#endif

/*
default LRU 是后备 LRU，将在转发 CPU/内核时使用
在 LRU Map-in-Map 中找不到每个核心的 LRU。
我们只应在运行 UnitTests 时在此默认 LRU 中遇到 hit。
这就是为什么默认情况下，这个 LRU 的值这么小
*/
#define DEFAULT_LRU_SIZE 1000

#ifndef PROG_SEC_NAME
#define PROG_SEC_NAME "xdp"
#endif

//来自 draft-ietf-quic-transport-22 和
//draft-ietf-quic-invariants-06
#define QUIC_LONG_HEADER 0x80
#define QUIC_SHORT_HEADER 0x00
/*
0x52为 0b01010010。6 个 MSB 位用于对 edgeray udp 数据包进行编码
type 和两个 LSB 位用于对连接 ID 版本 type 进行编码
因此，稳定 udp 类型的第一个字节的范围是 0x50 - 0x53;
*/
#define STABLE_ROUTING_HEADER 0x52
#define QUIC_HEADERMASK 0x20
#define QUIC_PACKET_TYPE_MASK 0x30

#define STABLE_RT_LEN 8


#ifndef QUIC_MIN_CONNID_LEN
#define QUIC_MIN_CONNID_LEN 8
#endif

//0x01	服务端创建的双向流？
#ifndef QUIC_CONNID_VERSION_V1
#define QUIC_CONNID_VERSION_V1 0x1
#endif

//0x02	客户端创建的单向流？
#ifndef QUIC_CONNID_VERSION_V2
#define QUIC_CONNID_VERSION_V2 0x2
#endif

//0x03	服务端创建的单向流？
#ifndef QUIC_CONNID_VERSION_V3
#define QUIC_CONNID_VERSION_V3 0x3
#endif

//SERVER_ID_HASH_MAP
#ifdef SERVER_ID_HASH_MAP
#ifndef MAX_NUM_SERVER_IDS
#define MAX_NUM_SERVER_IDS (1 << 24)
#endif

#else

#ifndef MAX_QUIC_REALS
#define MAX_QUIC_REALS 0x00fffffe // 2^24-2
#endif

#endif //SERVER_ID_HASH_MAP

#define ONE_SEC 1000000000U // 1 sec in nanosec


#ifndef MAX_VIPS
#define MAX_VIPS 512
#endif

#ifndef MAX_REALS
#define MAX_REALS 512
#endif

#ifndef RING_SIZE
#define RING_SIZE 65537
#endif

//默认跳数64
#ifndef DEFAULT_TTL
#define DEFAULT_TTL 64 
#endif

/*
最大以太网数据包大小 目标为 VIP
我们需要强制执行它，因为如果 origin_packet + encap_hdr > MTU
然后，根据 Dirver，它可能会 panic 或 drop 数据包
默认值：1500 个 IP 大小 + 14 个以太 HDR 大小
*/
#ifndef MAX_PCKT_SIZE
#define MAX_PCKT_SIZE 1514
#endif

/*
对于 v4 和 v6：初始数据包将被截断为 eth 标头的大小
加上 IPv4/IPv6 标头和少量字节的有效载荷
*/
#define ICMP_TOOBIG_SIZE 98
#define ICMP6_TOOBIG_SIZE 262

#define ICMP6_TOOBIG_PAYLOAD_SIZE (ICMP6_TOOBIG_SIZE - 6)
#define ICMP_TOOBIG_PAYLOAD_SIZE (ICMP_TOOBIG_SIZE - 6)

//hash环的大小
#define CH_RING_SIZE (MAX_VIPS * RING_SIZE) 
//lb_stats状态数
#define STATS_MAP_SIZE (MAX_VIPS * 2)

#define QUIC_STATS_MAP_SIZE 1

#ifndef INIT_JHSAH_SEED
#define INIT_JHSAH_SEED CH_RING_SIZE
#endif

#ifndef INIT_JHASH_SEED_V6
#define INIT_JHASH_SEED_V6 MAX_VIPS
#endif


#define LRU_CNTRS 0

#define LRU_MISS_CNTRS 1

#define STABLE_RT_STATS_MAP_SIZE 1

#define TPR_STATS_MAP_SIZE 1

//用于syn flood防御
#define NEW_CONN_RATE_CNTR 2

#define FALLBACK_LRU_CNTRS 3

#define LPM_SRC_CNTRS 5

//远程封装数据包计数器的偏移量
#define REMOTE_ENCAP_CNTRS 6

#define GLOBAL_LRU_CNTRS 8

//记录ch未初始化状态
#define CH_DROP_STATS 9 

#define DECAP_CNTR 10

#define QUIC_ICMP_STATS 11

#define ICMP_PTB_V6_STATS 12

#define ICMP_PTB_V4_STATS 13

/*
对于 LRU 更新，每个内核每秒的最大新连接数 a如果我们超过此值 
- 我们将绕过 LRU 更新。
*/
#ifndef MAX_CONN_RATE
#define MAX_CONN_RATE 125000
#endif

#ifndef MAX_LPM_SRC
#define MAX_LPM_SRC 3000000
#endif

#define DST_MATCH_IN_LRU 0
#define DST_MISMATCH_IN_LRU 1
#define DST_NOT_FOUND_IN_LRU 2


#ifdef GUE_ENCAP
#define PCKT_ENCAP_V4 gue_encap_v4
#define PCKT_ENCAP_V6 gue_encap_v6
#define HC_ENCAP hc_encap_gue
#else
#define PCKT_ENCAP_V4 encap_v4
#define PCKT_ENCAP_V6 encap_v6
#define HC_ENCAP hc_encap_ipip
#endif

//The Internet Assigned Numbers Authority (IANA) has reserved the
//   following three blocks of the IP address space for private internets:

//     10.0.0.0        -   10.255.255.255  (10/8 prefix)
//     172.16.0.0      -   172.31.255.255  (172.16/12 prefix)
//     192.168.0.0     -   192.168.255.255 (192.168/16 prefix)
#ifndef IPIP_V4_PREFIX
#define IPIP_V4_PREFIX 4268
#endif

//根据本文件，IANA已将IPv6地址前缀0100:：/64的分配记录为“Internet协议版本6地址空间”中的仅丢弃前缀，
//并将前缀添加到“IANA IPv6专用地址注册表”[IANA-IPV6REG]。
//尚未将任何结束方分配给此前缀。前缀已从以下位置分配

#ifndef IPIP_V6_PREFIX1
#define IPIP_V6_PREFIX1 1
#endif

#ifndef IPIP_V6_PREFIX2
#define IPIP_V6_PREFIX2 0
#endif

#ifndef IPIP_V6_PREFIX3
#define IPIP_V6_PREFIX3 0
#endif

// 指定是否将内部数据包 DSCP 值复制到外部 Encapped 数据包
//1000 – minimize delay ** #最小延迟**
//0100 – maximize throughput #最大吞吐量
//0010 – maximize reliability #最高可靠性
//0001 – minimize monetary cost** #最小费用**0000 – normal service** #一般服务**
#ifndef COPY_INNER_PACKET_TOS
#define COPY_INNER_PACKET_TOS 1
#endif

// 默认TOS
#ifndef DEFAULT_TOS
#define DEFAULT_TOS 0
#endif
#endif // BALANCER_CONSTS_H