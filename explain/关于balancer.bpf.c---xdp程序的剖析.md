# 一：关于网络的分层解析-预先：
## 1.1计算机网络七层网络：
从底向上分别为：物理层，链路层，网络层，传输层，会话层，表示层，应用层。

(卡特兰负载均衡器工作在我们的L4层，也就是传输层)

#### 2.1 L6层，数据链路层数据包解析：（有底层协议向上分析）
数据包：【【ethhdr】【payload】】

```cpp
#if __UAPI_DEF_ETHHDR
struct ethhdr {
unsigned char	h_dest[ETH_ALEN];	/* destination eth addr	*/
unsigned char	h_source[ETH_ALEN];	/* source ether addr	*/
__be16		h_proto;		/* packet type ID field	*/
} __attribute__((packed));
#endif
```

ethhdr以太网头结构体，包含目的mac地址，源mac地址，下一层的协议类型（指明数据包的网络层类型）。

#### 2.2 L5层，网络层数据包解析：
数据包： 【【ethhdr】【iphdr/ipv6hdr】【payload】】

```cpp
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8	ihl:4,
		version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	__u8	version:4,
  		ihl:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__struct_group(/* no tag */, addrs, /* no attrs */,
		__be32	saddr;
		__be32	daddr;
	);
	/*The options start here. */
};
```

```cpp
struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8			priority:4,
				version:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8			version:4,
				priority:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__u8			flow_lbl[3];

	__be16			payload_len;
	__u8			nexthdr;
	__u8			hop_limit;

	__struct_group(/* no tag */, addrs, /* no attrs */,
		struct	in6_addr	saddr;
		struct	in6_addr	daddr;
	);
};
```

![](https://cdn.nlark.com/yuque/0/2025/png/42989229/1740558658011-0e5709ea-ac2d-49fa-8b85-8c3455a9325a.png)

#### 2.23L4层，传输层数据包解析：
数据包： 【【ethhdr】【iphdr】【tcphdr/udphdr】【payload】】

```cpp
struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};
```

```cpp
struct udphdr {
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	check;
};

```

![](https://cdn.nlark.com/yuque/0/2025/png/42989229/1740559779114-f8e99cd0-1c95-4661-817d-c5a8becb4b73.png)

![](https://cdn.nlark.com/yuque/0/2025/png/42989229/1740559789294-19d08565-8323-44ce-9d4a-845ed3ac05e2.png)

## 1.2linux隧道技术解析：
### 1.2.1 ipip隧道数据包解析：
数据包：【【Ethhdr】<font style="color:#DF2A3F;">【【iphdr】【iphdr】】</font>【payload】】

```shell
#设置隧道网口
ip link add name ipip0 type ipip local LOCAL_IPv4_ADDR remote REMOTE_IPv4_ADDR
ip link set ipip0 up
ip addr add INTERVAL_IPv4_ADDR/24 dev ipip0
ip route add REMOTE_INTERVAL_SUBNET/24 dev ipip0
```

```shell
#设置ipip网口
ip link add name ipip1 type ipip local LOCAL_IPv4_ADDR remote REMOTE_IPv4_ADDR
ip link set ipip1 up
ip addr add INTERVAL_IPv4_ADDR/24 dev ipip1
ip route add REMOTE_INTERVAL_SUBNET/24 dev ipip1
```

### 1.2.2 SIT/IP6TNL隧道数据包解析：
数据包： 【Ethhdr】<font style="color:#DF2A3F;">【iphdr】【iphdr/ipv6hdr】</font><font style="color:#000000;">【payload】</font><font style="color:#E4495B;"></font>

```shell
ip link add name sitl type sit local LOCAL_IPv4_ADDR remote REMOTE_IPv4_ADDR mode any
ip link set sitl up
ip addr add INTERVAL_IPv4_ADDR/24 dev sitl
```

数据包： 【Ethhdr】<font style="color:#DF2A3F;">【ipv6hdr】【iphdr/ipv6hdr】</font><font style="color:#000000;">【payload】</font>

```shell
ip link add name ipip6 type ip6tnl local LOCAL_IPv6_ADDR remote REMOTE_IPv6_ADDR mode any
```

### 1.2.3 GRE/GRETAP隧道数据包解析：(Generic Routing Encapsulation)
数据包：【Ethhdr】<font style="color:#E4495B;">【iphdr header（Proto GRE）】【GRE header】【Inner Ip Header】</font>【payload】--GRE

```shell
ip link add name grel type local LOCAL_TPv4_ADDR remote REMOTE_IPv4_ADDR [seq] key KEY 
```

数据包：【Ethhdr】<font style="color:#E4495B;">【ip header（Proto GRE）】【GRE header】【Inner Ethhdr Header】【Inner Ip Header】</font>【payload】--GRETAP

```shell
ip link add name gretap1 type gretap local LOCAL_IPv4_ADDR remote REMOTE_IPv4_ADDR
```

```plain
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |C|       Reserved0       | Ver |         Protocol Type         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Checksum (optional)      |       Reserved1 (Optional)    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 1.2.4 IP6GRE/IP6GRETAP隧道数据包解析：
数据包：【Ethhdr】<font style="color:#E4495B;">【ip6 header（Proto GRE）】【GRE header】【Inner Ip Header</font>】【payload】--GRE

```shell
ip link add name grel type ip6gre local LOCAL_IPv6_ADDR remote REMOTE_IPv6_ADDR
```

数据包：【Ethhdr】<font style="color:#E4495B;">【ip6 header（Proto GRE）】【GRE header】【Inner Ethhdr Header】【Inner Ip Header】</font>【payload】--GRETAP

```shell
ip link add name gretapl type ip6gretap local LOCAL_IPv6_ADDR remote REMOTE_IPv6_ADDR
```

### 1.2.5 FOU隧道数据包解析：(foo over UDP)
数据包：【Ethhdr】<font style="color:#E4495B;">【iphdr】【UDP Header】【Inner IP/GRE Header】</font>【payload】

```shell
ip fou add port 5555 ipproto 47 #FOU 从 5555 端口接收 IPIP 数据包
ip link add name tunl type ipip remote 192.168.1.1 local 192.168.1.2 ttl 225 encap fou encap-sport auto encap-dport 5555
```

### 1.2.6 GUE隧道数据包解析：(Generic UDP Encapsulation)
数据包：【Ethhdr】<font style="color:#E4495B;">【ip Header】【UDP Header】【GUE Header】【Inner IP/GRE Header】</font>【payload】

```shell
ip fou add port 5555 gue
ip link add name tunl type ipip reomte 192.168.1.1 local 192.168.1.2 ttl 225 encap gue encap-sport auto encap-dport 5555
```

<font style="color:rgb(85, 85, 85);">当前，GUE隧道支持内部IPIP，SIT，GRE封装</font>

```plain
0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\
   |        Source port            |      Destination port         | |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ UDP
   |           Length              |          Checksum             | |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+/
   | 0 |C|   Hlen  |  Proto/ctype  |             Flags             |\
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |
   |                                                               | GUE
   ~                  Extensions Fields (optional)                 ~ |
   |                                                               | |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+/
```

```plain
0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\
   |        Source port            |      Destination port         | |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ UDP
   |           Length              |          Checksum             | |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+/
   |0|1|0|0|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |   Protocol    |   Header Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source IPv4 Address                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Destination IPv4 Address                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```plain
0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\
   |        Source port            |      Destination port         | |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ UDP
   |           Length              |          Checksum             | |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+/
   |0|1|1|0| Traffic Class |           Flow Label                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |     NextHdr   |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                        Source IPv6 Address                    +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                      Destination IPv6 Address                 +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```plain
+-------------------------------------+
   |   IP header (next proto = 17,UDP)   |
   |-------------------------------------|
   |                  UDP                |
   |-------------------------------------|
   |  GUE (proto = 4,IPv4 encapsulation) |
   |-------------------------------------|
   |        IPv4 header and packet       |
   +-------------------------------------+
```

### 1.2.7 GENEVE隧道数据包解析：(<font style="color:#000000;">Generic Network Virtualization Encapsulation</font>)
数据包：【Ethhdr】<font style="color:#E4495B;">【IP Header（proto UDP）】【UDP Header】【Geneve Header】【Inner Ethhdr】</font>【payload】

```shell
ip link add name geneve0 type geneve id VNI remote REMOTE_IPv4_ADDR
```

### 1.2.8 ERSPAN/IP6ERSPAN隧道数据包解析：(<font style="color:#000000;">Encapsulated Remote Switched Port Analyzer)</font>
数据包：【ethhdr】<font style="color:#E4495B;">【Outer IP Header (proto GRE)】【GRE Header】【ERSPAN Header】【Inner Ethhdr】【Inner IP Header】</font>【payload】

```shell
ip link add dev erspan1 type erspan local LOCAL_IPv4_ADDR remote REMOTE_IPv4_ADDR seq key KEY erspan_ver 1 erspan IDX
#or
ip link add dev erspan1 type erspan local LOCAL_IPv4_ADDR remote REMOTE_IPv4_ADDR seq key KEY erspan_ver 2 erspan_dir DIRECTION erspan_hwid HWID

#Add tc fliter to monitor traffic
tc qdisc add dev MONITOR_DEV handle ffff: ingress
tc filter add dev MONITOR_DEV parent ffff: matchall skip_hw action mirred egress mirror dev erspan1
```

### 1.2.9 总结：
| **<font style="color:rgb(68, 68, 68);">Tunnel/Link Type</font>** | **<font style="color:rgb(68, 68, 68);">Outer Header</font>** | **<font style="color:rgb(68, 68, 68);">Encapsulate Header</font>** | **<font style="color:rgb(68, 68, 68);">Inner Header</font>** |
| --- | --- | --- | --- |
| <font style="color:rgb(102, 102, 102);">ipip</font> | <font style="color:rgb(102, 102, 102);">IPv4</font> | <font style="color:rgb(102, 102, 102);">None</font> | <font style="color:rgb(102, 102, 102);">IPv4</font> |
| <font style="color:rgb(102, 102, 102);">sit</font> | <font style="color:rgb(102, 102, 102);">IPv4</font> | <font style="color:rgb(102, 102, 102);">None</font> | <font style="color:rgb(102, 102, 102);">IPv4/IPv6</font> |
| <font style="color:rgb(102, 102, 102);">ip6tnl</font> | <font style="color:rgb(102, 102, 102);">IPv6</font> | <font style="color:rgb(102, 102, 102);">None</font> | <font style="color:rgb(102, 102, 102);">IPv4/IPv6</font> |
| <font style="color:rgb(102, 102, 102);">vti</font> | <font style="color:rgb(102, 102, 102);">IPv4</font> | <font style="color:rgb(102, 102, 102);">IPsec</font> | <font style="color:rgb(102, 102, 102);">IPv4</font> |
| <font style="color:rgb(102, 102, 102);">vti6</font> | <font style="color:rgb(102, 102, 102);">IPv6</font> | <font style="color:rgb(102, 102, 102);">IPsec</font> | <font style="color:rgb(102, 102, 102);">IPv6</font> |
| <font style="color:rgb(102, 102, 102);">gre</font> | <font style="color:rgb(102, 102, 102);">IPv4</font> | <font style="color:rgb(102, 102, 102);">GRE</font> | <font style="color:rgb(102, 102, 102);">IPv4/IPv6</font> |
| <font style="color:rgb(102, 102, 102);">gretap</font> | <font style="color:rgb(102, 102, 102);">IPv4</font> | <font style="color:rgb(102, 102, 102);">GRE</font> | <font style="color:rgb(102, 102, 102);">Ether + IPv4/IPv6</font> |
| <font style="color:rgb(102, 102, 102);">ip6gre</font> | <font style="color:rgb(102, 102, 102);">IPv6</font> | <font style="color:rgb(102, 102, 102);">GRE</font> | <font style="color:rgb(102, 102, 102);">IPv4/IPv6</font> |
| <font style="color:rgb(102, 102, 102);">ip6gretap</font> | <font style="color:rgb(102, 102, 102);">IPv6</font> | <font style="color:rgb(102, 102, 102);">GRE</font> | <font style="color:rgb(102, 102, 102);">Ether + IPv4/IPv6</font> |
| <font style="color:rgb(102, 102, 102);">fou</font> | <font style="color:rgb(102, 102, 102);">IPv4/IPv6</font> | <font style="color:rgb(102, 102, 102);">UDP</font> | <font style="color:rgb(102, 102, 102);">IPv4/IPv6/GRE</font> |
| <font style="color:rgb(102, 102, 102);">gue</font> | <font style="color:rgb(102, 102, 102);">IPv4/IPv6</font> | <font style="color:rgb(102, 102, 102);">UDP + GUE</font> | <font style="color:rgb(102, 102, 102);">IPv4/IPv6/GRE</font> |
| <font style="color:rgb(102, 102, 102);">geneve</font> | <font style="color:rgb(102, 102, 102);">IPv4/IPv6</font> | <font style="color:rgb(102, 102, 102);">UDP + Geneve</font> | <font style="color:rgb(102, 102, 102);">Ether + IPv4/IPv6</font> |
| <font style="color:rgb(102, 102, 102);">erspan</font> | <font style="color:rgb(102, 102, 102);">IPv4</font> | <font style="color:rgb(102, 102, 102);">GRE + ERSPAN</font> | <font style="color:rgb(102, 102, 102);">IPv4/IPv6</font> |
| <font style="color:rgb(102, 102, 102);">ip6erspan</font> | <font style="color:rgb(102, 102, 102);">IPv6</font> | <font style="color:rgb(102, 102, 102);">GRE + ERSPAN</font> | <font style="color:rgb(102, 102, 102);">IPv4/IPv6</font> |


# 二：关于balancer.bpf.c---xdp程序的解析：
## 2.1主体函数：
```cpp
SEC(PROG_SEC_NAME)
int balancer_ingress(struct xdp_md *ctx) {
    void *data = (void*)(long)ctx->data;
    void *data_end = (void*)(long)ctx->data_end;

    struct ethhdr* eth = data;
    __u32 eth_proto;
    __u32 nh_off;

    nh_off = sizeof(struct ethhdr);

    if(data + nh_off > data_end) {
        return XDP_DROP; //错误数据包
    }

    eth_proto = eth->h_proto;

    if(eth_proto == BE_ETH_P_IP) {
        return process_packet(ctx, nh_off, false);
    } else if(eth_proto == BE_ETH_P_IPV6) {
        return process_packet(ctx, nh_off, true);
    } else {
        return XDP_PASS; //交给内核栈处理
    }
}
```

首先检查数据包的mac地址，检查数据包是否长度合法，接着进入处理函数process_packet（）中。主体函数过长，我们切段分析：

### 2.1.1 相关结构体介绍：
```cpp
struct real_definition {
    union {
        __be32 dst;
        __be32 dstv6[4];
    };//目的ip地址
    __u8 flags;
};
```

**real_definition结构体：是我们服务器集群中，服务器的真实ip地址，可以分为ipv4、ipv6和标志。**

****

```cpp
struct flow_key {
    union {
        __be32 src;
        __be32 srcv6[4];
    };
    union {
        __be32 dst;
        __be32 dstv6[4];
    };
    union {
        __u32 ports;
        __u16 port16[2]; //0 source port, 1 dest port
    };
    __u8 proto;
};

struct packet_description {
    struct flow_key flow;
    __u32 real_index;
    __u8 flags;
    __u8 tos; // type of service 看关于tos的定义与用法
};
```

**packet_description结构体：是数据包的描述结构体，用于收集数据分析检查。包含源ip，目的ip，端口，协议，服务器流向序号，标志， 服务标志tos**

****

```cpp

struct ctl_value {
    union {
        /* data */
        __u64 value;
        __u32 ifindex; //网口的索引
        __u8 mac[6];//mac地址
    };
};
```

**ctl_value结构体：是用来存储mac地址，网口索引，服务器序号**

****

```cpp
struct lb_stats {
    __u64 v2;
    __u64 v1;
};
```

**lb_stats结构体：是用来存储在负载均衡中的一些状态变量，用于检查test**

****

```cpp
struct vip_definition {
    union {
        __be32 vip;
        __be32 vipv6[4];
    };//虚拟IP地址
    __u16 port;
    __u8 proto;
};
```

vip_definition结构体：是用来存储vip虚拟ip的相关信息，ip地址，端口，协议，被卡特兰负载均衡使用。



```cpp
struct vip_meta {
    __u32 flags;
    __u32 vip_num;//在hash环中的位置
};
```

vip_meta结构体：是用来描述虚拟ip对应的服务器节点的位置，包含标志，后端节点



```cpp
struct address {
union 
{
__be32 addr;
__be32 addrv6[4];
};
};
```

一个描述IP地址的结构体，没有什么特别的。

### 2.1.2 process_l3_headers解析：
```cpp
__attribute__((__always_inline__)) static inline int//---------------√
process_l3_headers(
struct packet_description* pckt,
__u8* protocol,
__u64 nh_off,
__u16* pkt_bytes,
void* data,
void* data_end,
bool is_ipv6
) 
{
    int action;
    struct iphdr* iphdr;
    struct ipv6hdr* ipv6hdr;
    __u64 iph_len;
    if(!is_ipv6) {
        //ipv4
        iphdr = data + nh_off;
        if(iphdr + 1 > data_end) {
            return XDP_DROP;
        }
        if(iphdr->ihl != 5) {
            return XDP_DROP;
        }
        pckt->tos = iphdr->tos;
        *protocol = iphdr->protocol;
        pckt->flow.proto = *protocol;
        *pkt_bytes = bpf_ntohs(iphdr->tot_len);
        nh_off += IPV4_HDR_LEN_NO_OPT; //20

        //检测是否是ip分片数据包
        if(iphdr->frag_off & PACKET_FRAGMENTED) {
            return XDP_DROP;//丢弃ip分片数据包
        }
        if(*protocol == IPPROTO_ICMP) {
            //icmp报文
            action = parse_icmp(data, data_end, nh_off, pckt);
            if(action >= 0) {
                return action;
            }
        } else {
            pckt->flow.src = iphdr->saddr;
            pckt->flow.dst = iphdr->daddr;
        }
    } else {
        //ipv6
        ipv6hdr = data + nh_off;
        if(ipv6hdr + 1 > data_end) {
            return XDP_DROP;
        }

        iph_len = sizeof(struct ipv6hdr);
        *protocol = ipv6hdr->nexthdr;
        pckt->flow.proto = *protocol;

        //取出优先级
        pckt->tos = (ipv6hdr->priority << 4) & 0xF0;
        //合并流标签
        pckt->tos = pckt->tos | ((ipv6hdr->flow_lbl[0] >> 4) & 0x0F);

        *pkt_bytes = bpf_ntohs(ipv6hdr->payload_len);
        nh_off += iph_len;

        if(*protocol == IPPROTO_FRAGMENT) {
            //ip分片数据包
            return XDP_DROP;
        } else if (*protocol == IPPROTO_ICMPV6) {
            action = parse_icmpv6(data, data_end, nh_off, pckt);
            if(action >= 0) {
                return action;
            }
        } else {
            memcpy(pckt->flow.srcv6, ipv6hdr->saddr.s6_addr32, 16);
            memcpy(pckt->flow.dstv6, ipv6hdr->daddr.s6_addr32, 16);
        }
    }
    return FURTHER_PROCESSING;
}
```

我们将解析数据包的l3层。首先，进行相关的数据包检查，包括ipv4和ipv6数据包长度是否合法。收集ip层相关信息，将ip层的IP地址收集到结构体之中，卡特兰不能识别分片数据包！将分片数据包抛弃。解析ip层的协议，处理icmp数据包的两个格式（v4和v6）。进入icmp处理阶段。

```cpp
__attribute__((__always_inline__)) static inline int 
    parse_icmp(
    void* data,
    void* data_end,
    __u64 nh_off,
    struct packet_description* pckt
){
    struct icmphdr* icmp_hdr;
    struct iphdr* ip_hdr;
    icmp_hdr = data + nh_off;

    if(icmp_hdr + 1 > data_end) {
        return XDP_DROP;
    }
    if(icmp_hdr->type == ICMP_ECHO) {
        return send_icmp_reply(data, data_end); //发送icmp回应
    }
    if(icmp_hdr->type != ICMP_DEST_UNREACH) {
        return XDP_PASS;
    }
    if(icmp_hdr->code == ICMP_FRAG_NEEDED) {
        //需要分片
        __u32 stats_key = MAX_VIPS + ICMP_PTB_V4_STATS;
        struct lb_stats* stats_ = bpf_map_lookup_elem(&stats, &stats_key);
        if(!stats_) {
            return XDP_DROP;
        }
        stats_->v1 += 1;
        __u16 pmtu = bpf_ntohs(icmp_hdr->un.frag.mtu);
        if(pmtu < MAX_MTU_IN_PTB_TO_DROP) {
            stats_->v2 += 1;
        }
    }

    //不清楚为什么要这么做
    nh_off += sizeof(struct icmphdr);
    ip_hdr = data + nh_off;

    if(ip_hdr + 1 > data_end) {
        return XDP_DROP;
    }

    if(ip_hdr->ihl != 5) {
        return XDP_DROP;
    }

    pckt->flow.proto = ip_hdr->protocol;
    pckt->flags |= F_ICMP;
    pckt->flow.src = ip_hdr->daddr;
    pckt->flow.dst = ip_hdr->saddr;
    return FURTHER_PROCESSING;
}
```

进入这个函数，首先检查icmp数据包的长度合法性，如果type是ICMP_CODE，则进入send_icmp_reply(data, data_end)，发出icmp回应。检查分片标志，记录数量状态，检查pmtu，检查icmp报文中动态mtu（path-mtu），检查是否大于我们定义的一个预值，收集数量状态。

关于pmtu：

<font style="color:rgb(25, 27, 31);">PMTUD 就是为了解决这类问题，PMTUD 可以动态的检测到链路上最小的 MTU。PMTUD 仅支持 TCP 和 UDP 协议，在开启了 PMTUD 的设备上 TCP 或者 UDP 一般会将 DF bit 设置为 1 即 Don’t Fragment。</font>

[<font style="color:rgb(9, 64, 142);">DF bit</font>](https://zhida.zhihu.com/search?content_id=110755626&content_type=Article&match_order=1&q=DF+bit&zhida_source=entity)<font style="color:rgb(25, 27, 31);"> </font><font style="color:rgb(25, 27, 31);">= 0 代表可以做 fragmentation，DF bit = 1 代表不能做 fragmentation。</font>

[<font style="color:rgb(9, 64, 142);">MF bit</font>](https://zhida.zhihu.com/search?content_id=110755626&content_type=Article&match_order=1&q=MF+bit&zhida_source=entity)<font style="color:rgb(25, 27, 31);"> </font><font style="color:rgb(25, 27, 31);">= 0 代表该数据包是整个数据流里面最后一个包，MF bit = 1 代表还有更多被 fragment 的数据包</font>

<font style="color:rgb(25, 27, 31);">网络中的节点就靠 DF bit 判断能否做 fragmentation，靠 MF bit 判断做了 fragmentation 的数据包是否全部收到。</font>

```c
__attribute__((__always_inline__)) static inline int send_icmp_reply(
    void* data,
    void* data_end
) {
    struct iphdr* ip_hdr;
    struct icmphdr* icmp_hdr;
    __u64 off = 0; //位移
    __u64 csum = 0;//校验和
    __u32 tmp_addr = 0;    

    if((data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr)) > data_end) {
        return XDP_DROP;
    }

    off += sizeof(struct ethhdr);
    ip_hdr = data + off;
    off += sizeof(struct iphdr);
    icmp_hdr = data + off;
    icmp_hdr->type = ICMP_ECHOREPLY;//回应
    /*
    ICMP Echo 和 Reply HDR 之间的唯一区别是类型;
    在第一种情况下，它是 8;其次是 0;
    因此，我们不会从头开始重新计算校验和，而是调整它。
    */
   icmp_hdr->checksum += 0x0008;
   ip_hdr->ttl = DEFAULT_TTL;
   //交换ip源地址目的地址
   tmp_addr = ip_hdr->daddr;
   ip_hdr->daddr = ip_hdr->saddr;
   ip_hdr->saddr = tmp_addr;
   ip_hdr->check = 0;
   ipv4_csum_inline(ip_hdr, &csum);
   ip_hdr->check = csum;//填充校验和

    return swap_mac_and_send(data, data_end);
}

__attribute__((__always_inline__)) static inline int swap_mac_and_send(
    void* data,
    void* data_end
)
{
    struct ethhdr* ethhdr = data;
    unsigned char temp_mac[ETH_ALEN];
    memcpy(temp_mac, ethhdr->h_dest, ETH_ALEN);
    memcpy(ethhdr->h_dest, ethhdr->h_source, ETH_ALEN);
    memcpy(ethhdr->h_source, temp_mac, ETH_ALEN);
    return XDP_TX;//转发出去
}

```

进入到icmp报文构造函数中，利用已有的数据包进行修改，修改ttl，交换ip地址，补充更正校验和，交换mac地址，转发出去。

ipv6形如上述：

```c
__always_inline static int parse_icmpv6(
    void* data,
    void* data_end,
    __u64 nh_off,
    struct packet_description* pckt
)
{
    struct icmp6hdr* icmp6_hdr;
    struct ipv6hdr* ip6_hdr;
    icmp6_hdr = data + nh_off;
    if(icmp6_hdr + 1 > data_end) {
        return XDP_DROP;
    }
    if(icmp6_hdr->icmp6_type == ICMPV6_ECHO_REQUEST) {
        return send_icmp6_reply(data, data_end);//发送回应
    }

    if((icmp6_hdr->icmp6_type != ICMPV6_PKT_TOOBIG )&&
        (icmp6_hdr->icmp6_type != ICMPV6_DEST_UNREACH)) {
            return XDP_PASS;//内核栈处理
        }

    if(icmp6_hdr->icmp6_type == ICMPV6_PKT_TOOBIG) {
        __u32 stats_key = MAX_VIPS + ICMP_PTB_V6_STATS;
        struct lb_stats* stats_ = bpf_map_lookup_elem(&stats, &stats_key);
        if(!stats_) {
            return XDP_DROP;
        }
        stats_->v1 += 1;//记录状态
        __u32 pmtu = bpf_ntohs(icmp6_hdr->icmp6_mtu);
        if(pmtu < MAX_MTU_IN_PTB_TO_DROP) {
            stats_->v2 += 1;//记录状态
        }
    }

    nh_off += sizeof(struct icmp6hdr);
    ip6_hdr = data + nh_off;
    if(ip6_hdr + 1 > data_end) {
        return XDP_DROP;
    }

    pckt->flow.proto = ip6_hdr->nexthdr;
    pckt->flags |= F_ICMP;
    memcpy(pckt->flow.srcv6, ip6_hdr->daddr.s6_addr32, 16);
    memcpy(pckt->flow.dstv6, ip6_hdr->saddr.s6_addr32, 16);
    return FURTHER_PROCESSING;
}


__attribute__((__always_inline__)) static inline int 
    send_icmp6_reply(
    void* data,
    void* data_end 
)
{
    struct ipv6hdr* ip6_hdr;
    struct icmp6hdr* icmp6_hdr;
    __be32 tmp_addr[4];//128位
    __u64 off = 0;
    if((data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr)) > data_end) {
        return XDP_DROP;
    }

    off += sizeof(struct ethhdr);
    ip6_hdr = data + off;
    off += sizeof(struct ipv6hdr);
    icmp6_hdr = data + off;
    icmp6_hdr->icmp6_type = ICMPV6_ECHO_REPLY;
    /*
    ICMP Echo 和 Reply HDR 之间的唯一区别是类型;
    在第一种情况下，它是 128;第二名是 129 分;
    因此，我们不会从头开始重新计算校验和，而是调整它。
    */
    icmp6_hdr->icmp6_cksum -= 0x0001;
    ip6_hdr->hop_limit = DEFAULT_TTL;
    memcpy(tmp_addr, ip6_hdr->saddr.s6_addr32, 16);
    memcpy(ip6_hdr->saddr.s6_addr32, ip6_hdr->daddr.s6_addr32, 16);
    memcpy(ip6_hdr->daddr.s6_addr32, tmp_addr, 16);
    return swap_mac_and_send(data, data_end);
}
```

到此，数据包的l3层解析到此结束。

### 2.1.3 ：-DINLINE_DECAP_IPIP解析：
```cpp
//如果是ipip数据包，我们要解封检验
#ifdef INLINE_DECAP_IPIP
/* This is to workaround a verifier issue for 5.2.
   * The reason is that 5.2 verifier does not handle register
   * copy states properly while 5.6 handles properly.
   *
   * For the following source code:
   *   if (protocol == IPPROTO_IPIP || protocol == IPPROTO_IPV6) {
   *     ...
   *   }
   * llvm12 may generate the following simplified code sequence
   *   100  r5 = *(u8 *)(r9 +51)  // r5 is the protocol
   *   120  r4 = r5
   *   121  if r4 s> 0x10 goto target1
   *   122  *(u64 *)(r10 -184) = r5
   *   123  if r4 == 0x4 goto target2
   *   ...
   *   target2:
   *   150  r1 = *(u64 *)(r10 -184)
   *   151  if (r1 != 4) { __unreachable__}
   *
   * For the path 123->150->151, 5.6 correctly noticed
   * at insn 150: r4, r5, *(u64 *)(r10 -184) all have value 4.
   * while 5.2 has *(u64 *)(r10 -184) holding "r5" which could be
   * any value 0-255. In 5.2, "__unreachable" code is verified
   * and it caused verifier failure.
   */
if(protocol == IPPROTO_IPIP) {
    bool pass = true;
    action = check_decap_dst(&pckt, is_ipv6, &pass);
    if(action >= 0) {
        return action;
    }
    return process_encaped_ipip_pckt(&data, &data_end, ctx, &is_ipv6, &protocol, pass);
} else if (protocol == IPPROTO_IPV6) {
    bool pass = true;
    action = check_decap_dst(&pckt, is_ipv6, &pass);
    if(action >= 0) {
        return action;
    }
    return process_encaped_ipip_pckt(&data, &data_end, ctx, &is_ipv6, &protocol, pass);
}
    #endif //INLINE_DECAP_IPIP
```

假如数据包的类型是IPIP类型的，逻辑上进入此判断域。

根据protocol收集到的协议，是IPIP数据包，我们首先进入check_decap_dst(&pckt, is_ipv6, &pass)检查源IP地址，目的IP地址。

```cpp
#ifdef INLINE_DECAP_GENERIC
__attribute__((__always_inline__)) static inline int 
check_decap_dst(
struct packet_description* pckt,
bool is_ipv6,
bool* pass
) {
    struct address dst_address = {};
    struct lb_stats* data_stats;

    #ifdef DECAP_STRICT_DESTINATION 
    struct real_definition* host_primary_addrss;
    __u32 addr_index;

    if(is_ipv6) {
        addr_index = V6_SRC_INDEX;
        //问题
        host_primary_addrss = bpf_map_lookup_elem(&packet_srcs, &addr_index);
        /*
        由于外部数据包目标与主机 IPv6 不匹配，
        因此请勿解封。
        它允许将数据包传送到正确的网络命名空间。
        */
        if(host_primary_addrss) {
            if(host_primary_addrss->dstv6[0] != pckt->flow.dstv6[0] ||
                host_primary_addrss->dstv6[1] != pckt->flow.dstv6[1] || 
                host_primary_addrss->dstv6[2] != pckt->flow.dstv6[2] || 
                host_primary_addrss->dstv6[3] != pckt->flow.dstv6[3]) {
                return XDP_PASS;
            }
        }
    } else {
        addr_index = V4_SRC_INDEX;
        host_primary_addrss = bpf_map_lookup_elem(&packet_srcs, &addr_index);
        if(host_primary_addrss) {
            if(host_primary_addrss->dst != pckt->flow.dst) {
                /*
                由于外部数据包目的地与主机 IPv4 不匹配，因此
                不要解封。它将允许传递数据包
                添加到正确的网络命名空间。
                */
                return XDP_PASS;
            }
        }
    }
    #endif //INLINE_DECAP_GENERIC

    if(is_ipv6) {
        memcpy(dst_address.addrv6, pckt->flow.dstv6, 16);
    } else {
        dst_address.addr = pckt->flow.dst;
    }

    __u32* decap_dst_flags = bpf_map_lookup_elem(&decap_dst, &dst_address);

    if(decap_dst_flags) {
        *pass = false;
        __u32 stats_key = MAX_VIPS + REMOTE_ENCAP_CNTRS;
        data_stats = bpf_map_lookup_elem(&stats, &stats_key);
        if(!data_stats) {
            return XDP_DROP;
        }
        data_stats->v1 += 1;
    }
    return FURTHER_PROCESSING;
}
#endif //INLINE_DECAP_GENERIC
```

首先，如果定义DECAP_STRICT_DEATINATION，那么我们进行主机ip检查，将IPIP数据包中的OUTER SRC IP和我们packet_srcs映射中存储的源主机ip地址进行比较，如果不一致， 我们交给内核栈处理。

将IPIP数据包中的OUTER DST IP收集起来，在我们decap_dst映射中寻找是否匹配，如果匹配，则pass变量为false，收集数量状态。进一步处理。

接下来进入process_encaped_ipip_pckt（）解析IPIP数据包

```cpp
#ifdef INLINE_DECAP_IPIP
__attribute__((__always_inline__)) static inline int 
process_encaped_ipip_pckt(
void** data,
void** data_end,
struct xdp_md *ctx, 
bool* is_ipv6,
__u8* protocol,
bool pass
) {
    int action;
    if(*protocol == IPPROTO_IPIP) {
        //ipip包
        if(*is_ipv6) {
            int offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
            if((*data + offset) > *data_end) {
                return XDP_DROP;
            }
            action = decrement_ttl(*data, *data_end, offset, false);
            if(!decap_v6(ctx, data, data_end, true)) {
                return XDP_DROP;
            }
            *is_ipv6 = false;
        } else {
            int offset = sizeof(struct ethhdr) + sizeof(struct iphdr);
            if((*data + offset) > *data_end) {
                return XDP_DROP;
            }
            action = decrement_ttl(*data, *data_end, offset, false);
            if(!decap_v4(ctx, data, data_end)) {
                return XDP_DROP;
            }
        }
    } else if (*protocol == IPPROTO_IPV6) {
        int offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr);
        if((*data + offset) > *data_end) {
            return XDP_DROP;
        }
        action = decrement_ttl(*data, *data_end, offset, true);
        if(!decap_v6(ctx, data, data_end, false)) {
            return XDP_DROP;
        }
    }

    __u32 stats_key = MAX_VIPS + DECAP_CNTR;
    struct lb_stats* data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if(!data_stats) {
        return XDP_DROP;
    }

    if(is_ipv6) {
        data_stats->v2 += 1;
    } else {
        data_stats->v1 += 1;
    }

    if(action >= 0) {
        return action;
    }

    if(pass) {
        return XDP_PASS; //交给内核栈
    }
    return recirculate(ctx);//循环处理
}
#endif //INLINE_DECAP_IPIP
```

```cpp
__attribute__((__always_inline__)) static inline int//---------------√
decrement_ttl(
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
```

```cpp
__attribute__((__always_inline__)) static inline bool 
                                    decap_v6(struct xdp_md *xdp,
                                    void **data,
                                    void **data_end,
                                    bool isnner_ipv4) {//---------------√
    struct ethhdr *eth_new;
    struct ethhdr *eth_old;
    eth_old = *data;
    eth_new = *data + sizeof(struct ipv6hdr);
    memcpy(eth_new->h_source, eth_old->h_source, 6);
    memcpy(eth_new->h_dest, eth_old->h_dest, 6);
    if(isnner_ipv4) {
        eth_new->h_proto = BE_ETH_P_IP;
    } else {
        eth_new->h_proto = BE_ETH_P_IPV6;
    }

    if(XDP_ADJUST_HEAD_FUNC(xdp, (int)(sizeof(struct ipv6hdr)))) {
        return false; 
    }
    *data = (void *)(long)xdp->data;
    *data_end = (void *)(long)xdp->data_end;
    return true;
}

__attribute__((__always_inline__)) static inline bool decap_v4(struct xdp_md *xdp,
                                     void **data,
                                     void **data_end) {//---------------√
    struct ethhdr *eth_new;
    struct ethhdr *eth_old;
    eth_old = *data;
    eth_new = *data + sizeof(struct iphdr);
    memcpy(eth_new->h_source, eth_old->h_source, 6);
    memcpy(eth_new->h_dest, eth_old->h_dest, 6);
    eth_new->h_proto = BE_ETH_P_IP;

    if(XDP_ADJUST_HEAD_FUNC(xdp, (int)sizeof(struct iphdr))) {
        return false;
    }

    *data = (void *)(long)xdp->data;
    *data_end = (void *)(long)xdp->data_end;
    return true;
}
```

我们来看看IPIP数据包的格式

【Ethhdr】【OUTER IP Header】【INNER IP Header】【payload】

我们首先检查数据包长度是否合法，进入decrement_ttl（）函数之中，减少INNER IP Header中ttl，也就是减少内层ipHeader的路由跳数，如果ttl减一后变为0，我们就要丢弃数据包，重新计算校验和，返回。

我们进入decap_v4/6函数之中，解封IPIP数据包。

v6：old_eth指向*data的位置，new_eth指向*data+sizeof（struct ipv6hdr）的位置，将old的相关信息交给new，如果内层IP Header是ipv4，new的proto为BE_ETH_P_IP，反之为BE_ETH_P_IPV6，然后利用bpf_xdp_adjust_head函数，将xdp_md指针所指的大小缩减一个ipv6hdr的大小，这样就是将IPIP数据包解封的过程，将data和data_end指针调整位置，保证无误。调整成功返回true

v4：这个版本和v6的版本几乎一致，外层IP是v6，那么内层IP可以是v4或者v6，外层IP是v4，那么内层IP只能是v4。调整成功返回true

还有一种情况就是外层协议是IPV6，但是放在了IPIP数据包处理下处理。

```markdown
兼容IPv4的 IPv6地址:
这种IPv6地址的低32位携带一个IPv4的单播地址，一般主要使用于IPv4兼容IPv6 自动隧道，但由于每个主机都需要一个单播IPv4地址，且必须是公网IPv4地址，扩展性差，基本已经被6to4隧道取代。

映射IPv4的 IPv6地址：
这种地址的最前80bit全为0，后面 16bit全为 1，最后32bit是 IPv4地址（该处IPv4地址可以为任意的公有或者私有地址）。这种地址是把IPv4地址用IPv6表示。如
```

在处理完所有情况后，数量状态计数，如果pass为pass为true，将数据包放入到内核协议栈处理，这里的pass是我们在目的映射map中匹配了IP地址。最后循环处理（？）

根据protocol收集到的协议，是IPPROTO_IPV6数据包，处理逻辑与上述一致。

### 2.1.4 ：TCP/UDP解析：
在经历完IP层的检查和IPIP数据包的检查后，来到了TCP/UDP即l4层的检查。

```cpp
    if(protocol == IPPROTO_TCP) {
        if(!parse_tcp(data, data_end, is_ipv6, &pckt)) {
            return XDP_DROP;
        }
    } else if (protocol == IPPROTO_UDP) {
        if(!parse_udp(data, data_end, is_ipv6, &pckt)) {
            return XDP_DROP;
        }
#ifdef INLINE_DECAP_GUE
        if(pckt.flow.port16[1] == bpf_htons(GUE_DPORT)) { //目的端口是gue数据包传输的端口
            bool pass = true;
            action = check_decap_dst(&pckt, is_ipv6, &pass);
            if(action >= 0) {
                return action;
            }
            return process_encaped_gue_pckt(&data, &data_end, ctx, nh_off, is_ipv6, pass);
        }
#endif //INLINE_DECAP_GUE
    } else {
        return XDP_PASS; //交给内核栈
    }
```

```cpp
__attribute__((__always_inline__)) static inline bool//---------------√
                             parse_tcp(void *data,
                                      void *data_end,
                                      bool is_ipv6,
                                      struct packet_description *packet) {

    bool is_icmp = !((packet->flags & F_ICMP) == 0); //是否是icmp报文
    __u64 off = calc_offset(is_ipv6, is_icmp);
    struct tcphdr *tcp;
    tcp = data + off;
    if(tcp + 1 > data_end) {
        return false;
    }

    if(tcp->syn) {
        packet->flags |= F_SYN_SET;
    }
    if(!is_icmp) {
        packet->flow.port16[0] = tcp->source;
        packet->flow.port16[1] = tcp->dest;
    } else {
        packet->flow.port16[0] = tcp->dest;
        packet->flow.port16[1] = tcp->source;
    }

    return true;
}
```

```cpp
__attribute__((__always_inline__)) static inline bool//---------------√
                             parse_udp(void *data,
                                      void *data_end,
                                      bool is_ipv6,
                                      struct packet_description *packet) {
    bool is_icmp = !((packet->flags & F_ICMP) == 0); //是否是icmp报文
    __u64 off = calc_offset(is_ipv6, is_icmp); 
    struct udphdr* udp;
    udp = data + off;
    if(udp + 1 > data_end) {
        return false;
    }
    //source dest port 转换                                 
    if(!is_icmp) {
        packet->flow.port16[0] = udp->source;
        packet->flow.port16[1] = udp->dest;
    } else {
        packet->flow.port16[0] = udp->dest;
        packet->flow.port16[1] = udp->source;
    }
    return true;
}
```

在l4层，如果数据包时TCP传输的，我们进入parse_tcp函数之中，只是将tcp层的端口给记录下，保存到数据包描述结构体之中。如果时UDP传输的，我们进入parse_udp函数中，将udp层的端口记录下来，保存到结构体之中。

如果定义了INLINE_DECAP_GUE，那么我们解析GUE数据包。

看看GUE数据包的格式是什么样子的：

数据包：【Ethhdr】<font style="color:#E4495B;">【ip Header】【UDP Header】【GUE Header】【Inner IP/GRE Header】</font>【payload】

将GUE_PORT记录到数据流的目的端口之中，进入到decap_dst解析之中，判断是否进入内核栈处理。最后，进入process_encaped_gue_pckt函数之中。

```cpp
__attribute__((__always_inline__)) static inline int 
process_encaped_gue_pckt(
    void** data,
    void** data_end,
    struct xdp_md* ctx,
    __u64 nh_off,
    bool is_ipv6,
    bool pass
)
{
    int offset = 0;
    int action;
    bool inner_ipv6 = false;
    //外层是否是ipv6
    if(is_ipv6) {
        __u8 v6 = 0;
        offset = sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
        if((*data + offset + 1) > *data_end) {
            //1 个字节用于 gue v1 标记，用于确定什么是内部协议
            return XDP_DROP;
        }
        v6 = ((__u8*)(*data))[offset];
        v6 &= GUEV1_IPV6MASK;
        inner_ipv6 = v6 ? true : false;
        //内层是否是ipv6
        if(v6) {
           action = decrement_ttl(*data, *data_end, offset, true); //是ipv6
           if(!gue_decap_v6(ctx, data, data_end, false)) {
                return XDP_DROP;
           } 
        } else {
            action = decrement_ttl(*data, *data_end, offset, false); //是ipv4
            if(!gue_decap_v6(ctx, data, data_end, true)) {
                return XDP_DROP;
            }
        }
    } else {
        offset = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
        if((*data + offset) > *data_end) {
            return XDP_DROP;
        }
        action = decrement_ttl(*data, *data_end, offset, false);
        if(!gue_decap_v4(ctx, data, data_end)) {
            return XDP_DROP;
        }
    }

    __u32 stats_key = MAX_VIPS + DECAP_CNTR;
    struct lb_stats* data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if(!data_stats) {
        return XDP_DROP;
    }
    if(is_ipv6) {
        data_stats->v2++;
    } else {
        data_stats->v1++;
    }

    if(action >= 0) {
        return action;
    }

    if(pass) {
        incr_decap_vip_stats(*data, nh_off, *data_end, inner_ipv6);
        return XDP_PASS;
    }
    return recirculate(ctx);
}
#endif //INLINE_DECAP_GUE
```

```cpp
__attribute__((__always_inline__)) static inline bool
 gue_decap_v6(struct xdp_md *xdp, void **data, void **data_end, bool inner_v4) {//---------------√
    struct ethhdr *eth_new;
    struct ethhdr *eth_old;
    eth_old = *data;
    eth_new = *data + sizeof(struct ipv6hdr) + sizeof(struct udphdr);
    //RECORD_GUE_ROUTE(eth_old, eth_new, *data_end, true, false);//?
    memcpy(eth_new->h_source, eth_old->h_source, 6);
    memcpy(eth_new->h_dest, eth_old->h_dest, 6);
    //eth_new->proto = inner_v4 ? BE_ETH_P_IP : BE_ETH_P_IPV6;
    if (inner_v4) {
        eth_new->h_proto = BE_ETH_P_IP;
    } else {
        eth_new->h_proto = BE_ETH_P_IPV6;
    }
    if(XDP_ADJUST_HEAD_FUNC(xdp, (int)(sizeof(struct ipv6hdr) + sizeof(struct udphdr)))) {
        return false;
    }
    *data = (void *)(long)xdp->data;
    *data_end = (void *)(long)xdp->data_end;
    return true;
}
#endif //INLINE_DECAP_GUE
```

```cpp
__attribute__((__always_inline__)) static inline bool
 gue_decap_v4(struct xdp_md *xdp, void **data, void **data_end) {//---------------√
    struct ethhdr *eth_new;
    struct ethhdr *eth_old;
    eth_old = *data;
    eth_new = *data + sizeof(struct iphdr) + sizeof(struct udphdr);
    //RECORD_GUE_ROUTE(eth_old, eth_new, *data_end, true, true);//?
    memcpy(eth_new->h_source, eth_old->h_source, 6);
    memcpy(eth_new->h_dest, eth_old->h_dest, 6);
    eth_new->h_proto = BE_ETH_P_IP;
    if(XDP_ADJUST_HEAD_FUNC(xdp, sizeof(struct iphdr) + sizeof(struct udphdr))) {
        return false;
    }

    *data = (void *)(long)xdp->data;
    *data_end = (void *)(long)xdp->data_end;
    return true;
}
```

```cpp
__attribute__((__always_inline__)) static inline void
 incr_decap_vip_stats(
    void* data,
    __u64 nh_off,
    void* data_end,
    bool is_ipv6
)
{
    struct packet_description inner_pckt = {};
    struct vip_definition vip = {};
    struct vip_meta* vip_info;
    __u8 inner_protocol;
    __u16 inner_pckt_bytes;
    //分析l3层
    if(process_l3_headers(
        &inner_pckt, 
        &inner_protocol, 
        nh_off, 
        &inner_pckt_bytes,
        data, 
        data_end,
        is_ipv6) >= 0) {
        return;
    }
    if(is_ipv6) {
        memcpy(vip.vipv6, inner_pckt.flow.dstv6, 16);//收集目的ipv6地址
    } else {
        vip.vip = inner_pckt.flow.dst;
    }
    vip.proto = inner_pckt.flow.proto;

    //分析l4层
    if(inner_protocol == IPPROTO_TCP) {
        if(!parse_tcp(data, data_end, is_ipv6, &inner_pckt)) {
            return;
        }
    }
    if(inner_protocol == IPPROTO_UDP) {
        if(!parse_udp(data, data_end, is_ipv6, &inner_pckt)) {
            return;
        }
    }
    vip.port = inner_pckt.flow.port16[1]; //目的端口
    vip_info = bpf_map_lookup_elem(&vip_map, &vip);
    //存在记录
    if(vip_info) {
        __u32 vip_num = vip_info->vip_num;
        //通过hash序号查找并且更新状态
        struct lb_stats* decap_stats = bpf_map_lookup_elem(&decap_vip_stats, &vip_num);
        if(decap_stats) {
            decap_stats->v1 += 1; //记录状态
        }
    }
}
```

首先，下面这个图片是GUE封装的数据包的一般形式：

我们利用在Ethhdr，IPhdr/IPV6hdr，TCP/UDPhdr后面的四个字节来判断内层数据包是否是ipv6。ipv4hdr的前四个字节是0100，ipv6hdr的前四个字节是0110，逻辑上，通过前三个字节比较出协议类型。

```plain
0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\
   |        Source port            |      Destination port         | |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ UDP
   |           Length              |          Checksum             | |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+/
   |0|1|0|0|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |   Protocol    |   Header Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source IPv4 Address                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Destination IPv4 Address                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```plain
0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\
   |        Source port            |      Destination port         | |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ UDP
   |           Length              |          Checksum             | |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+/
   |0|1|1|0| Traffic Class |           Flow Label                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Payload Length        |     NextHdr   |   Hop Limit   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                        Source IPv6 Address                    +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   |                                                               |
   +                      Destination IPv6 Address                 +
   |                                                               |
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

接下来，根据协议，分别解包。

v6：通过将指针位置的变化，将原来的数据包分解为正常的数据包，重新构造ethhdr结构体。利用bpf_xdp_adjust_head调整缩小ip6hdr加上udphdr两个结构体的大小，调正data，data_end指针，返回true。

v4：与上述大概一致

如果pass变量为false，意味着在之前的decap_dst检查中匹配成功。反之，将数据包发往内核协议栈，在这之前，进入incr_decap_vip_stats（）函数。这个函数意味着GUE内层数据包是一个完整的数据包。经过一系列检查，统计数据。卡特兰只支持TCP和UDP协议，否则，交给内核栈处理。

### 2.1.5 Vip收集：
```cpp
    if(is_ipv6) {
        memcpy(vip.vipv6, pckt.flow.dstv6, 16);
    } else {
        vip.vip = pckt.flow.dst;
    }

    vip.port = pckt.flow.port16[1];
    vip.proto = pckt.flow.proto;
    vip_info = bpf_map_lookup_elem(&vip_map, &vip);
    if(!vip_info) {
        vip.port = 0;
        //在找一遍看有没有
        vip_info = bpf_map_lookup_elem(&vip_map, &vip);
        if(!vip_info) {
            return XDP_PASS; //交给内核栈
        }
        /*
        VIP，
        它不关心 dst 端口
        （所有发送到此 VIP 的数据包，
        带有不同的 dst 端口，
        但来自同一个 src 端口/ip 
        必须发送到同一个 real
        */
        if(!(vip_info->flags & F_HASH_DPORT_ONLY) &&
            !(vip_info->flags & F_HASH_SRC_DST_ONLY)) {
                pckt.flow.port16[1] = 0;
            }
    }
```

在经历过l3层解析，IPIP数据包解析，l4层解析，GUE数据包解析后，我们收集到了Vip的相关数据，我们从数据包结构体中得到的DST-IP，PORT，PROTO三个元素。这三个元素被我们收集在vip_map映射之中，我们通过三元素{VIP，PORT，PROTO}匹配找到vip的元数据{FLAGS, NUM}而元素，其中，NUM代表后端服务器hash值，FLAGS代表标志。如果没有在map找到相应的二元素，交给内核找处理。（vip_map这个映射需要在卡特兰开启时建立，是必须建立的映射）

注意：VIP不关系dst端口，意思是从多方而来的流量他们的目的端口都是不一样的，但是，来自同一个ip和端口的数据必须流向同一个后端服务器，保证了c/s架构的正确性。

### 2.1.6 数据包太大而引起的icmp报文：
```cpp
if(data_end - data > MAX_PCKT_SIZE) {
        //发出警告，暂且没有
#ifdef ICMP_TOOBIG_GENERATION
        __u32 stats_key = MAX_VIPS + ICMP_TOOBIG_CNTRS;
        data_stats = bpf_map_lookup_elem(&stats, &stats_key);
        if(!data_stats) {
            return XDP_DROP;//数据包超出限制大小，丢弃
        }
        if(is_ipv6) {
            data_stats->v2++; //计数
        } else {
            data_stats->v1++;
        }

        return send_icmp_too_big(ctx, is_ipv6, data_end - data);
#else
        return XDP_DROP;
#endif
    }
```

```cpp
__attribute__((__always_inline__)) static inline int//---------------√
 send_icmp_too_big(
    struct xdo_md* ctx,
    bool is_ipv6,
    int pckt_size
) {
    int offset = pckt_size;
    if(is_ipv6) {
        offset -= ICMP6_TOOBIG_SIZE;
    } else {
        offset -= ICMP_TOOBIG_SIZE;
    }

    //调整数据包
    //尾部调整 负数delta为收缩
    if(bpf_xdp_adjust_tail(ctx, 0 - offset)) {
        return XDP_DROP;
    }
    if(is_ipv6) {
        return send_icm6_too_big(ctx);
    } else {
        return send_icm_too_big(ctx);
    }
}
```

```cpp
__attribute__((__always_inline__)) static inline int 
 send_icm_too_big(
    struct xdp_md* ctx
) {
    int headroom = (int)sizeof(struct iphdr) + (int)sizeof(struct icmphdr);
    //增长头部
    if(XDP_ADJUST_HEAD_FUNC(ctx, 0 - headroom)) {
        return XDP_DROP;
    }
    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    if(data + (headroom + ICMP_TOOBIG_SIZE) > data_end) {
        return XDP_DROP;
    }

    struct iphdr* orig_ip_hdr, *ip_hdr;
    struct icmphdr* icmp_hdr;
    struct ethhdr* orig_eth_hdr;

    __u64 csum = 0;
    __u64 off = 0;

    //l2层
    orig_eth_hdr = data + headroom;
    swap_mac(data, orig_eth_hdr);

    off += sizeof(struct ethhdr);
    ip_hdr = data + off;
    off += sizeof(struct iphdr);
    icmp_hdr = data + off;
    off += sizeof(struct icmphdr);
    orig_ip_hdr = data + off;

    //l3层
    icmp_hdr->type = ICMP_DEST_UNREACH; //无法到达dst
    icmp_hdr->code = ICMP_FRAG_NEEDED; //icmp返回信息需要分片数据包，
    //icmp_hdr->icmp6_mtu = bpf_htons(ICMP_TOOBIG_SIZE - sizeof(struct ethhdr)); //1500字节
    icmp_hdr->un.frag.mtu = bpf_htons(ICMP_TOOBIG_SIZE - sizeof(struct ethhdr)); //1500字节
    icmp_hdr->un.frag.__unused = 0;
    icmp_hdr->checksum = 0;
    ipv4_csum(icmp_hdr, ICMP_TOOBIG_PAYLOAD_SIZE, &csum);
    icmp_hdr->checksum = csum;//校验和

    csum = 0;//重置

    ip_hdr->daddr = orig_ip_hdr->saddr;
    ip_hdr->saddr = orig_ip_hdr->daddr;
    ip_hdr->ttl = DEFAULT_TTL;
    ip_hdr->frag_off = 0;
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->tos = 0;
    ip_hdr->tot_len = bpf_htons(ICMP_TOOBIG_SIZE + headroom - sizeof(struct ethhdr));
    ip_hdr->id = 0;
    ip_hdr->check = 0;
    ipv4_csum(ip_hdr, sizeof(struct iphdr), &csum);
    ip_hdr->check = csum;
    return XDP_TX;
}
```

```cpp
__attribute__((__always_inline__)) static inline int 
 send_icm6_too_big(//---------------√
    struct xdp_md* ctx
)
{
    int headroom = (int)sizeof(struct ipv6hdr) + (int)sizeof(struct icmp6hdr);
    if(XDP_ADJUST_HEAD_FUNC(ctx, 0 - headroom)) {
        return XDP_DROP;
    }

    void* data = (void*)(long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    if(data + (ICMP6_TOOBIG_SIZE + headroom) > data_end) {
        return XDP_DROP;
    }

    struct ipv6hdr* ipv6_hdr, *orig_ipv6_hdr;
    struct ethhdr* orig_eth_hdr;
    struct icmp6hdr* icmp6_hdr;

    __u64 csum = 0;//校验和
    __u64 off = 0;

    //需要一张图片帮助理解：理解关键在于指针的移动，并非数据包真正的改变    
    //l2层
    orig_eth_hdr = data + headroom;
    swap_mac(data, orig_eth_hdr);

    off += sizeof(struct ethhdr);
    ipv6_hdr = data + off;
    off += sizeof(struct ipv6hdr);
    icmp6_hdr = data + off;
    off += sizeof(struct icmp6hdr);
    orig_ipv6_hdr = data + off;
    
    //l3层
    ipv6_hdr->version = 6;
    ipv6_hdr->priority = 0;
    ipv6_hdr->nexthdr = IPPROTO_ICMPV6;//后面跟着icmp6 header
    ipv6_hdr->hop_limit = DEFAULT_TTL; //默认跳数
    ipv6_hdr->payload_len = bpf_htons(ICMP6_TOOBIG_PAYLOAD_SIZE);
    memset(ipv6_hdr->flow_lbl, 0, sizeof(ipv6_hdr->flow_lbl));
    memcpy(ipv6_hdr->daddr.s6_addr32, orig_ipv6_hdr->saddr.s6_addr32, 16);
    memcpy(ipv6_hdr->saddr.s6_addr32, orig_ipv6_hdr->daddr.s6_addr32, 16);

    icmp6_hdr->icmp6_type = ICMPV6_PKT_TOOBIG;
    icmp6_hdr->icmp6_code = 0;
    icmp6_hdr->icmp6_mtu = bpf_htonl(MAX_PCKT_SIZE - sizeof(struct ethhdr)); //说白了1500字节
    icmp6_hdr->icmp6_cksum = 0;

    ipv6_csum(icmp6_hdr, ICMP6_TOOBIG_PAYLOAD_SIZE, &csum, ipv6_hdr);
    icmp6_hdr->icmp6_cksum = csum;
    return XDP_TX; //发送icmp数据包
}
```

首先，将数据包收缩，为什么？这个数据包太大了，我们需要调整，但是调整为多大呢？我们看：

第一步：offset等于数据包的大小，假设为1600。

第二部：将offset减去预先设定的大小，假设offset = 1600 - 98 = 1502

第三步：调整xdp_md的tail，调用bpf_xdp_adjust_tail函数将数据包缩小为98

第四步：调用发送icmp报文函数。

我们只分析icmpv4的函数：

我们调用bpf_xdp_adjust_head函数向前扩充iphdr加上icmphdr两个结构体大小

初始状态：

data                                     data_end

👇                                           👇

【ethhdr】【...】【....】【...】【...】

收缩后：

    data                  data_end

     👇                        👇

【ethhdr】【...】【....】

扩展后：

 data                                           data_end

👇                                                   👇 

【】【】【】【】【ethhdr】【...】【....】

{    headroom   }

new_eth_hdr = data

orig_eth_hdr = data + headroom

交换eth_hdr

ip_hdr = data + sizeof ethhdr

icmphdr = dataa + sizeof ethhdr + sizeof iphdr

orig_ip_hdr = data + szieof ethhdr + sizeof iphdr + sizeof icmphdr\

在上述工作处理完后，我们一次填充每个头部信息中的字段信息，检查校验和，并转发出去。至此，icmp too big 报文发送完成。

### 2.1.7 LRUmap状态的更新：
```cpp
__u32 stats_key = MAX_VIPS + LRU_CNTRS;
    data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if(!data_stats) {
        return XDP_DROP;
    }

    data_stats->v1++;

    if(vip_info->flags & F_HAHS_NO_SRC_PORT) {
        
        //service，其中 diff src 端口，但同一个 IP 必须去同一个 real，
        pckt.flow.port16[0] = 0;
    }
    vip_num = vip_info->vip_num; //hansh环的位置
    /*
    获取 SMP（对称多处理）处理器 ID。
    请注意，所有程序在禁用迁移的情况下运行，
    这意味着 SMP 处理器 ID 在程序执行期间是稳定的。
    返回
    运行该程序的处理器的 SMP ID。
    */
    __u32 cpu_num = bpf_get_smp_processor_id();
    void* lru_map_ = bpf_map_lookup_elem(&lru_mapping, &cpu_num);
    if(!lru_map_) {
        //没有找到
        lru_map_ = &fallback_cache;
        __u32 lru_stats_key = MAX_VIPS + FALLBACK_LRU_CNTRS;
        struct lb_stats* lru_stats = bpf_map_lookup_elem(&stats, &lru_stats_key);
        if(!lru_stats) {
            return XDP_DROP;
        }
        //我们无法检索每个 CPU/内核的 lru 并回退到
        //默认 1 个。这个计数器在 prod(生产环境) 中不应该是 0 以外的任何值。
        //我们将使用它来进行监控。
        lru_stats->v1++;
    }
```

保存后端节点num，在当前cpu下在lru_mapping映射中寻找lru_map是否存在，如果不存在，那么我们将当前cpu下的lru_mapping替换为我们事先准备好的fallback缓存。记录状态量。再次提醒，lru_map是flow流数据映射服务器的IP地址

LRUmap意味着我们xdp程序将充分利用每一个cpu，在每一个cpu上都有一个缓存，记录着flow流数据对应服务器的IP地址

### 2.1.8 QUIC协议的支持：
QUIC的Header：

QUIC LONG Header：

```c
0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+
   |1|X X X X X X X|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Version (32)                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | DCID Len (8)  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               Destination Connection ID (0..2040)           ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | SCID Len (8)  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Source Connection ID (0..2040)              ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |X X X X X X X X X X X X X X X X X X X X X X X X X X X X X X  ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

QUIC SHORT Header：

```c
0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+
   |0|X X X X X X X|
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                 Destination Connection ID (*)               ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |X X X X X X X X X X X X X X X X X X X X X X X X X X X X X X  ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```cpp
if(vip_info->flags & F_QUIC_VIP) {
        bool is_icmp = (pckt.flags & F_ICMP);
        if(is_icmp) {
            /*
            根据 rfc792，“Destination Unreachable Message”具有 Internet 报头加上原始数据报数据的前 64 位。
            因此，不能保证在 icmp 消息中具有完整的 quic 标头。
            此外，如果原始数据报中的 QUIC Headers 是短 Headers，
            则它没有服务器生成的可用于路由的连接 ID。
            回退到 CH 以路由 QUIC ICMP 消息。
            */
           __u32 stats_key = MAX_VIPS + QUIC_ICMP_STATS;
           struct lb_stats* data_stats = bpf_map_lookup_elem(&stats, &stats_key);
            if(!data_stats) {
                return XDP_DROP;
            }
            data_stats->v1++;
            if(ignorable_quic_icmp_code(data, data_end, is_ipv6)) {
                data_stats->v2++;
            }
        } else {
            __u32 quic_packets_stats_key = 0;
            struct lb_quic_packets_stats* quic_packets_stats = 
                bpf_map_lookup_elem(&quic_stats_map, &quic_packets_stats_key);
            if(!quic_packets_stats) {
                return XDP_DROP;
            }

            struct quic_parse_result quic_res = parse_quic(data, data_end, is_ipv6, &pckt);
            if(quic_res.server_id > 0) {
                //增加计数
                increment_quic_cid_version_stats(quic_packets_stats, quic_res.cid_version);
                __u32 key = quic_res.server_id;//以server_id为key，查找真实节点
                __u32* real_pos = bpf_map_lookup_elem(&server_id_map, &key);
                if(real_pos) {
                    key = *real_pos;
                    if(key == 0) {
                        //错误计数
                        quic_packets_stats->cid_invalid_server_id++;
                        quic_packets_stats->cid_invalid_server_id_sample = quic_res.server_id; //错误的server_id
                        quic_packets_stats->ch_routed++; //路由
                    } else {
                        pckt.real_index = key;//存储服务器的真实节点
                        dst = bpf_map_lookup_elem(&reals, &key);
                        if(!dst) {
                            quic_packets_stats->cid_unknown_real_dropped++;
                            //发出警告
                            return XDP_DROP; //丢弃数据包
                        }
                        int res = check_and_update_real_index_in_lru(&pckt, lru_map_);
                        if(res == DST_MATCH_IN_LRU) {
                            quic_packets_stats->dst_match_in_lru++;
                        } else if(res == DST_MISMATCH_IN_LRU) {
                            quic_packets_stats->dst_mismatch_in_lru++;
                            incr_server_id_routing_stats(vip_num, false, true);
                        } else {
                            quic_packets_stats->dst_not_found_in_lru++;
                        }
                        quic_packets_stats->cid_routed++;
                    }
                } else {
                    //无法得到服务器id的真实位置--real_pos
                    quic_packets_stats->cid_invalid_server_id++;
                    quic_packets_stats->cid_invalid_server_id_sample = quic_res.server_id;
                    quic_packets_stats->ch_routed++; //hash环错误计数
                }
            } else if (!quic_res.is_initial) {
                    //不需要初始化，意味着不是新的连接
                    quic_packets_stats->ch_routed++;
            } else {
                //需要初始化，是新的连接
                quic_packets_stats->cid_initial++;
                incr_server_id_routing_stats(vip_num, true, false);
            }
        }
    }
```

首先，如果带有QUIC标志，那么进入到QUIC分析阶段，我们首先忽略quic—icmp报文，记录相关数据量。

进入parse_quic函数解析quic协议：

```cpp
__attribute__((__always_inline__)) static inline struct quic_parse_result parse_quic(//---------------√
    void* data,
    void* data_end,
    bool is_ipv6,
    struct packet_description* pckt
) {
    struct quic_parse_result result = {
        .server_id = FURTHER_PROCESSING,
        .cid_version = 0xFF,
        .is_initial = false
    };

    bool is_icmp = (pckt->flags & F_ICMP);

    __u64 off = calc_offset(is_ipv6, is_icmp);

    if((data + off + sizeof(struct udphdr) + sizeof(__u8)) > data_end) {
        return result;
    }

    __u8* quic_data = data + off + sizeof(struct udphdr);
    __u8* pckt_type = quic_data;
    __u8* connId = NULL;

    /*
    CONN ID 的位置根据数据包是长报头还是短报头而变化。
    一旦我们计算了 conn id 的偏移量，只需读取固定长度，
    即使 connid len 可以是 0 或 4-18 字节，
    因为 czkatran 只关心 Dest Conn Id 中的前 16 位
    */
   //长头
   if((*pckt_type & QUIC_LONG_HEADER) == QUIC_LONG_HEADER) {
        if((quic_data + sizeof(struct quic_long_header)) > data_end) {
            return result;
        }
        if((*pckt_type & QUIC_PACKET_TYPE_MASK) < QUIC_HEADERMASK) {
            /*
            对于客户端初始数据包和 0RTT 数据包 - 回退以使用 C. 哈希，
            因为connection-id 不是服务器选择的 ID。
            */
            result.is_initial = true;
            return result;
        }

        struct quic_long_header* long_header = (struct quic_long_header*)quic_data;
        if(long_header->conn_id_lens < QUIC_MIN_CONNID_LEN) {
            return result;
        }
        connId = long_header->dst_connection_id;
   } else {
    //短头
    //直接读取connID
    if(quic_data + sizeof(struct quic_short_header) > data_end) {
        return result;
    }
    connId = ((struct quic_short_header*)quic_data)->dst_connection_id;
   }
   if(!connId) {
    return result;
   }

    //取前两位
   __u8 connIdVersion = (connId[0] >> 6);
   result.cid_version = connIdVersion;
   if(connIdVersion == QUIC_CONNID_VERSION_V1) {
        result.server_id = ((connId[0] & 0x3F) << 10) | (connId[1] << 2) | (connId[2] >> 6);
        return result;
   } else if(connIdVersion == QUIC_CONNID_VERSION_V2) {
        result.server_id = (connId[1] << 16) | (connId[2] << 8) | (connId[3]);
        return result;
   } else if (connIdVersion == QUIC_CONNID_VERSION_V3) {
        result.server_id = (connId[1] << 24) | (connId[2] << 16) | (connId[3] << 8) | (connId[4]);
   }
   return result;
}
```

进入函数中，检查数据包是否合法，我们读取固定量，不用关系quic是长报头还是断报头。我们读取并保存conn-id，这个是quic协议保持客户端和服务端的标识。

<font style="color:#000000;">提取connId的前两位作为版本号。根据版本号判断并计算server_id：</font>

    - <font style="color:#000000;">如果是V1版本，使用特定位运算组合connId的前3个字节。</font>
    - <font style="color:#000000;">如果是V2版本，使用特定位运算组合connId的前4个字节。</font>
    - <font style="color:#000000;">如果是V3版本，使用特定位运算组合connId的前5个字节。</font>

这部分中，有着许多状态量计数工作，我们不分析。我们分析在这里的映射关系：

server_id_map: server_id(quic 映射的server_id) ------------> real_pos(服务器的位置) 

reals: real_pos(服务器的位置)--------------> real_definition(数据包应该发送的位置IP)

lru_map:  {SRC_IP，DST_IP，PORT，PROTO}------------------------> {pos, atime } 

```cpp
__attribute__((__always_inline__)) static inline int check_and_update_real_index_in_lru(
    struct packet_description* pckt,
    void* lru_map
) {
    struct real_pos_lru* dst_lru = bpf_map_lookup_elem(lru_map, &pckt->flow);
    if(dst_lru) {
        if(dst_lru->pos == pckt->real_index) {
            return DST_MATCH_IN_LRU;
        } else {
            dst_lru->pos = pckt->real_index;
            return DST_MISMATCH_IN_LRU;
        }
    }
    __u64 cur_time;
    if(is_under_flood(&cur_time)) {
        return DST_NOT_FOUND_IN_LRU;
    }
    struct real_pos_lru new_dst_lru = {};
    new_dst_lru.pos = pckt->real_index;
    bpf_map_update_elem(lru_map, &pckt->flow, &new_dst_lru, BPF_ANY);
    return DST_NOT_FOUND_IN_LRU;
}

__attribute__((__always_inline__)) static inline bool is_under_flood(
    __u32* cur_time
) {
    __u32 conn_rate_key = MAX_VIPS + NEW_CONN_RATE_CNTR;
    struct lb_stats* conn_rate_stats = 
        bpf_map_lookup_elem(&stats, &conn_rate_key);
    if(!conn_rate_stats) {
        return true; //直截了当地判断syn攻击，待进一步优化
    }
    *cur_time = bpf_ktime_get_ns();
    /*
    我们将检查新连接速率是否低于预定义的速率
    价值;conn_rate_stats.v1 包含最后一个
    second， v2 - 上次 Quanta 开始的时间。
    */
    if((*cur_time - conn_rate_stats->v2) > ONE_SEC  /* 1 sec in nanosec*/) {
        conn_rate_stats->v1 = 1;
        conn_rate_stats->v2 = *cur_time; //存放的是时间
    } else {
        conn_rate_stats->v1++;
        /*
        我们正在超过最大连接速率。跳过 LRU 更新和源路由查找
        */
        if(conn_rate_stats->v1 > MAX_CONN_RATE) {
            return true;
        }
    }
    return false;
}
```

检查lru_map，通过flow流找到对应的real_lru_pos，这个是lru缓存，如果在lru_map中匹配，检查dst_lru存储的real_pos是否等于这个数据包描述结构体中存储的real_index(real_pos)，如果等于，返回DST_MATCH_IN_LRU，反之，将real_index赋给dst_lru缓存，返回DST_MISMATCH_IN_LRU，检查当前环境是否超出了处理能力，如果是的，返回DST_NOT_FOUND_IN_LRU。最后更新lru_map，插入一条记录，这个记录的key值为这个数据包的flow流数据，值为这个数据包应该流向的服务器的位置。

### 2.1.9 UDP_STABLE_ROUTING选项解析：
在经历了quic协议解析后，我们定义了UDP_STABLE_ROUTING选项，用于特定的数据包路由。

顾名思义，这种数据包使用了UDP来包装，而且是稳定路由的方式。他在数据包中携带了connid，这个字段被stable_routing_header所包裹在数据包中。相关代码如下：

```cpp
#ifdef UDP_STABLE_ROUTING
    if(pckt.flow.proto == IPPROTO_UDP && 
        vip_info->flags & F_UDP_STABLE_ROUTING_VIP) {
            process_udp_stable_routing(data, data_end, &dst, &pckt, is_ipv6);
    }
#endif //UDP_STABLE_ROUTING
```

```cpp
__attribute__((__always_inline__)) static inline bool process_udp_stable_routing(
    void* data,
    void* data_end,
    struct real_definition** dst,
    struct packet_description* pckt,
    bool is_ipv6
)
{
    __u32 stable_rt_stats_key = 0;
    struct lb_stable_rt_packets_stats* udp_lb_rt_stats = 
        bpf_map_lookup_elem(&stable_rt_stats, &stable_rt_stats_key);
    if(!udp_lb_rt_stats) {
        return XDP_DROP;
    }

    struct udp_stable_rt_result usr = 
        parse_udp_stable_rt_hdr(data, data_end, is_ipv6, pckt);
    
    if(usr.server_id > 0) {
        __u32 key = usr.server_id;
        __u32* real_pos = bpf_map_lookup_elem(&server_id_map, &key);
        if(real_pos) {
            //得到该server_id对应的real_pos
            key = *real_pos;
            if(key != 0) {
                pckt->real_index = key;
                //得到real_pos对应的real_definition
                *dst = bpf_map_lookup_elem(&reals, &key);
                if(!*dst) {
                    udp_lb_rt_stats->cid_unknown_real_dropped++;
                    return XDP_DROP;
                }
                udp_lb_rt_stats->cid_routed++;
            }
        } else {
            udp_lb_rt_stats->cid_invalid_server_id++;
            udp_lb_rt_stats->ch_routed++;
        }
    } else {
        if(!usr.is_stable_rt_pkt) {
            udp_lb_rt_stats->invalid_packet_type++;
        }
        udp_lb_rt_stats->ch_routed++;
    }
}
#endif


__attribute__((__always_inline__)) static inline struct udp_stable_rt_result parse_udp_stable_rt_hdr(
    void* data,
    void* data_end,
    bool is_ipv6,
    struct packet_description* pckt
)
{
    struct udp_stable_rt_result result = {
        .server_id = STABLE_RT_NO_SERVER_ID,
        .is_stable_rt_pkt = false
    };
    bool is_icmp = (pckt->flags & F_ICMP);
    __u64 off = calc_offset(is_ipv6, is_icmp);

    if((data + off + sizeof(struct udphdr) + sizeof(__u8)) > data_end) {
        return result;
    }

    __u8* udp_data = data + off + sizeof(struct udphdr);
    __u8* pkt_type = udp_data;
    __u8* connId = NULL;

    if((*pkt_type) == STABLE_ROUTING_HEADER) {
        //带有stable routing header的数据包
        if(udp_data + sizeof(struct stable_routing_header) > data_end) {
            return result;
        }
        connId = ((struct stable_routing_header*)udp_data)->connection_id;
        result.is_stable_rt_pkt = true;
    }
    if(!connId) {
        return result;
    }

    result.server_id = (connId[1] << 16) | (connId[2] << 8) | (connId[3]);
    return result;
}
```

我们去解析数据包，然后提取stable_routing_header结构体中的connid，收集起来，如果connid大于0，即合法，那我们通过connid去寻找real_pos即服务器的位置，通过server_id_map这个映射关系，再通过找到的real_pos在reals映射中寻找real相关的IP地址。最后记录下统计变量计数。

### 2.1.10 TCP_SERVER_ID_ROUTING选项解析：
按理来说，如果是quic数据包，那么我们如果一切顺利，我们应该找到了这个数据包应该发往的dst地址，如果不是quic协议类型的，我们又经历了UDP_STABLE_ROUTING选项的分析，看看能不能找到dst地址，以上都没有发生，那么，我们将要分析TCP_SERVER_ID_ROUTING选项的分析。

```cpp
#ifdef TCP_SERVER_ID_ROUTING  
        if(pckt.flow.proto == IPPROTO_TCP) {
            __u32 tpr_packets_stats_key = 0;
            struct lb_tpr_packets_stats* tpr_packets_stats_ = 
            bpf_map_lookup_elem(&tpr_stats_map, &tpr_packets_stats_key);
            if(!tpr_packets_stats_) {
                return XDP_DROP;
            }

            if(pckt.flags & F_SYN_SET) {
                tpr_packets_stats_->tcp_syn++;
                incr_server_id_routing_stats(
                    vip_num, true, false
                );
            } else {
                if(tcp_hdr_opt_lookup(ctx, is_ipv6, &dst, &pckt) == FURTHER_PROCESSING) {
                    tpr_packets_stats_->ch_routed++;
                } else {
                    if(lru_map_ && !(vip_info->flags & F_LRU_BYPASS)) {
                        int res = check_and_update_real_index_in_lru(&pckt, lru_map_);
                        if(res == DST_MISMATCH_IN_LRU) {
                            tpr_packets_stats_->dst_mismatch_in_lru++;
                            incr_server_id_routing_stats(vip_num, false, true);
                        }
                    }
                    tpr_packets_stats_->sid_routed++;
                } 
            }
        }
#endif
```

首先我们判断数据包的类型是不是TCP，在我们实现准备好的映射中找出tpr_packets_stats的值，以便后续计数变量。

如果数据包的标志中存在F）SYN_SET标志，初步判断是TCP的第一次连接。我们只是更新server_id_routing映射中的值。如果没有F_SYN_SET标志，那么意味着不是第一次连接的状态，也就是说是任何状态但不是第一次，那么，如果以切顺利，他会被我们LRU缓存下来，至此，我通过tcp_hdr_opt_lookup函数进行判断寻找server_id：

```cpp
#ifdef TCP_SERVER_ID_ROUTING
__attribute__((__always_inline__)) static inline int
 tcp_hdr_opt_lookup(
    struct xdp_md* ctx,
    bool is_ipv6,
    struct real_definition** dst,
    struct packet_description* pckt
)
{
    __u32 server_id = 0;
    int err = 0;
    if(tcp_hdr_opt_lookup_server_id(ctx, is_ipv6, &server_id) == FURTHER_PROCESSING) {
        return FURTHER_PROCESSING;
    }

    __u32 key = server_id;
    __u32* real_pos = bpf_map_lookup_elem(&server_id_map, &key);
    if(!real_pos) {
        return FURTHER_PROCESSING;
    }
    key = *real_pos;
    if(key == 0) {
        /*
        由于 server_id_map 是一个bpf_map_array因此其所有成员都是 0 初始化的，
        这可能导致不存在的键与索引 0 处的 real 错误匹配。
        因此，只需跳过值为 0 的 key 即可避免数据包路由错误。
        */
        return FURTHER_PROCESSING;
    }
    pckt->real_index = key;
    *dst = bpf_map_lookup_elem(&reals, &key);
    if(!(*dst)) {
        return FURTHER_PROCESSING;
    }
    return 0;
}
#endif // TCP_SERVER_ID_ROUTING'
```

我们首先进入到tcp_hdr_opt_lookup_server_id函数中寻找server_id，这个server_id被放在TCP Header的option选项部分。

```shell
//原本的tcp中的option端的格式为：
// kind/type (1 byte) | length (1 byte) | value 
//cap： the structure of header-option to save server_id
// kind/type (1 byte) | length (1 byte) | server_id (4 bytes)
```

option格式是一个字节的kind/type，一个字节的length，以及4个字节的server_id。

如果找到了sever_id,那么我们在server_id_map映射中寻找此id对应的服务器位置，通过位置序号，在reals映射中寻找dstIP地址，如果没能找到，继续处理分析。

接着我们分析如何寻找TCP中的option选项。

```shell
__always_inline static int tcp_hdr_opt_lookup_server_id(const struct xdp_md *xdp,
                                                        bool is_ipv6,
                                                        __u32 *server_id) {

    const void *data = (void *)(long)(xdp->data);
    const void *data_end = (void *)(long)(xdp->data_end);
    struct tcphdr *tcphdr;
    __u64 hdr_offset = 0;
    __u8 tcp_hdr_opt_len = 0;
    struct hdr_opt_state tcp_opt = {};
    int err = 0;

    hdr_offset = calc_offset(is_ipv6, false);
    tcphdr = (struct tcphdr *)(data + hdr_offset);
    //判断
    if(tcphdr + 1 > data_end) {
        return FURTHER_PROCESSING;
    }

    //doff 四位 单位为 4字节（32位）
    //doff * 4 再减去头部长度，如果为零，表示没有tcp选项
    tcp_hdr_opt_len = (tcphdr->doff * 4) - sizeof(struct tcphdr);
    if (tcp_hdr_opt_len < TCP_HDR_OPT_LEN_TPR) {
        return FURTHER_PROCESSING;
    }
    tcp_opt.hdr_bytes_remaining = tcp_hdr_opt_len;
    tcp_opt.bytes_offset = hdr_offset + sizeof(struct tcphdr); //指向选项的第一个字节

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0) || \
    !defined TCP_HDR_OPT_SKIP_UNROLL_LOOP
    //在提供的代码中，这段指令出现在两个函数中：tcp_hdr_opt_lookup和tcp_hdr_opt_lookup_skb。这两个函数的主要功能是从TCP数据包的选项字段中解析出服务器ID。由于BPF（Berkeley Packet Filter）程序的限制，特别是在Linux内核版本低于5.3的系统中，BPF验证器（verifier）无法验证循环的边界条件。因此，为了通过验证器的检查，编译器需要对循环进行完全展开，确保循环体中的每一部分都被正确地验证。
#pragma clang loop unroll(full)
#endif
    //循环解析TCP选项
    for (int i = 0; i < TCP_HDR_OPT_MAX_OPT_CHECKS; i++) {
        err = parse_hdr_opt(xdp, &tcp_opt);
        if (err || !tcp_opt.hdr_bytes_remaining) {
            break;
        }
    }
    if(!tcp_opt.server_id) {
        return FURTHER_PROCESSING;
    }
    *server_id = tcp_opt.server_id;
    return 0;
}
#endif //TCP_SERVER_ID_ROUTING || DECAP_TPR_STATS


#ifndef TCP_HDR_OPT_SKIP_UNROLL_LOOP
__always_inline
#endif
int parse_hdr_opt(struct xdp_md *xdp,
                  struct hdr_opt_state *tcp_state) {
    __u8 *tcp_opt, kind, hdr_len;

    const void *data = (void *)(long)xdp->data;
    const void *data_end = (void *)(long)xdp->data_end;
    return parse_hdr_opt_raw(data, data_end, tcp_state);
}


__attribute__((__always_inline__)) int
                     parse_hdr_opt_raw(const void *data,
                                      const void *data_end, 
                                      struct hdr_opt_state *tcp_state) {

    __u8 *tcp_opt, kind, hdr_len;

    if(!tcp_state) {
        return -1;
    }

    tcp_opt = (__u8 *)(data + tcp_state->bytes_offset);
    if(tcp_opt + 1 > data_end) {
        return -1;
    }

    kind = tcp_opt[0];
    if(kind == TCP_OPT_EOL) {
        return -1;
    }

    if(kind == TCP_OPT_NOP) {
        tcp_state->bytes_offset++;
        tcp_state->hdr_bytes_remaining--;
        return 0;
    }

    if(tcp_state->hdr_bytes_remaining < 2 || 
     tcp_opt + sizeof(__u8) + sizeof(__u8) > data_end) {
        // 选项长度至少为2字节 或者指针右移两位指向的value（server_id）超过了报文的末尾
        return -1;
    }

    hdr_len = tcp_opt[1];
    if(hdr_len > tcp_state->hdr_bytes_remaining) {
        return -1;
    }

    if(kind == TCP_HDR_OPT_KIND_TPR) {
        //再次检查
        if(hdr_len != TCP_HDR_OPT_LEN_TPR) {
            return -1;
        }
        if(tcp_opt + TCP_HDR_OPT_LEN_TPR > data_end) {
            return -1;
        }

        tcp_state->server_id = *(__u32 *)&tcp_opt[2];
        return 1;
    }
    
    tcp_state->bytes_offset += hdr_len;
    tcp_state->hdr_bytes_remaining -= hdr_len;
    return 0;
}
```

以上三个函数就是我们在数据包中寻找TCP的选项处理函数。

首先，我们判断数据包是否合法，找到TCP Header的地方，通过tcphdr->doff * 4 - sizeof tcphdr可以得到tcp头部携带的选项的长度。如果长度小于6，即type+length+server_id的长度，返回继续处理寻找dstIp地址。

我们使用一个结构体来存储三个变量：server_id, byte_offset, hdr_bytes_remaining,分别是服务器的id，字节偏移量，剩余字节数。

在这里注意，在内核版本小于5.3.0的版本的环境下，bpf验证器无法验证循环操作，卡特兰通过循环展开技术，

解析option，进入parse_hdr_opt函数，parse_hdr_opt函数调用parse_hdr_opt_raw函数。

进入到这个函数中，tcp_opt指针指向data加上字节偏移量，__u8*类型的指针，__u8*是一个字节指针，指向tcp Header opt的位置。如果遇到TCP_OPT_EOL标志，说明解析到底了。遇到TCP_OPT_NOP标志，说明没有。如果剩余的字节数小于2，或者只有两个字节在头部的option处，说明不存在server_id。如果遇到了TCP_HOR_OPT_KIND_TR标志，说明遇到了server_id的存储位置，安全判断长度是否合法。将tcp_state指针移动两个字节处，变更为四个字节的指针，将server_id保存到结构体之中，返回成功，否则，字节偏移量增加一个字节的长度，剩余字节数量减去一个字节的长度。

返回到主体函数中，如果在tcp_hdr_opt_lookup函数没能找到dstIP地址，我们要更新LRU缓存。

```shell
__attribute__((__always_inline__)) static inline int check_and_update_real_index_in_lru(
    struct packet_description* pckt,
    void* lru_map
) {
    struct real_pos_lru* dst_lru = bpf_map_lookup_elem(lru_map, &pckt->flow);
    if(dst_lru) {
        if(dst_lru->pos == pckt->real_index) {
            return DST_MATCH_IN_LRU;
        } else {
            dst_lru->pos = pckt->real_index;
            return DST_MISMATCH_IN_LRU;
        }
    }
    __u64 cur_time;
    if(is_under_flood(&cur_time)) {
        return DST_NOT_FOUND_IN_LRU;
    }
    struct real_pos_lru new_dst_lru = {};
    new_dst_lru.pos = pckt->real_index;
    bpf_map_update_elem(lru_map, &pckt->flow, &new_dst_lru, BPF_ANY);
    return DST_NOT_FOUND_IN_LRU;
}
```

再来看看这个函数，通过数据包的flow流数据在lru_map中寻找服务器位置，如果没能找到，计数更新，如果找到，也更新计数。再者，判断是否处于TCP洪水之中，为真，返回没能找到，否则，将flow流数据为key，数据包流向的服务器位置为value，更新到lru_map之中，返回未能找到。

### 2.1.11 如果dst没能找到，并不是第一次Tcp连接，没有LRU_PASS标志解析：
```shell
        if(!dst && 
        !(pckt.flags & F_SYN_SET) && 
        !(vip_info->flags & F_LRU_BYPASS)) {
            connecttion_table_lookup(&dst, &pckt, lru_map_, /*isGloballru*/false);
        }
```

这个时候我们会在全局连接表中寻找dstIP地址

```shell
__attribute__((__always_inline__)) static inline void connecttion_table_lookup(
    struct real_definition** dst,
    struct packet_description* pckt, 
    void* lru_map,
    bool is_Globallru
)
{   
    struct real_pos_lru* dst_lru;
    __u64 time;
    __u32 key;
    dst_lru = bpf_map_lookup_elem(lru_map, &pckt->flow);
    if(!dst_lru) {
        return;
    }
    if(!is_Globallru && pckt->flow.proto == IPPROTO_UDP) {
        time = bpf_ktime_get_ns();
        if(time - dst_lru->atime > LRU_UDP_TIMEOUT) {
            return;
        }
        dst_lru->atime = time;
    }

    key = dst_lru->pos;
    pckt->real_index = key;
    *dst = bpf_map_lookup_elem(&reals, &key);
    return;
}
```

我们在lru_map中以数据包的flow流数据为key，寻找对应的value，即为服务器的位置信息，

如果没能找到，返回，如果找到了，将dst_lru中的服务器的位置信息赋给数据包结构体中的real_index字段，通过更新后的real_index在reals中寻找dstIP地址信息。其中，我们还另外判断了是否是全局LRU并且数据包的类型是否是UDP类型，我们更新lru_map中real_pos_lru缓存的时间。

### 2.1.12 如果dst没能找到，并不是第一次Tcp连接，设置F_GLOBAL_LRU标志解析：
```shell
#ifdef GLOBAL_LRU_LOOKUP
        if(!dst && 
        !(pckt.flags & F_SYN_SET) && 
        (vip_info->flags & F_GLOBAL_LRU)) {
            int global_lru_lookup_result = 
                perform_global_lru_lookup(&dst, &pckt, cpu_num, vip_info, is_ipv6);
            if(global_lru_lookup_result >= 0) {
                return global_lru_lookup_result;
            }
        }
#endif //GLOBAL_LRU_LOOKUP
```

```c
#ifdef GLOBAL_LRU_LOOKUP
__attribute__((__always_inline__)) static inline int perform_global_lru_lookup(
    struct real_definition** dst,
    struct packet_description* pckt,
    __u32 cpu_num,
    struct vip_meta* vip_info,
    bool is_ipv6 
)
{
    void* g_lru_map = bpf_map_lookup_elem(&global_lru_map, &cpu_num);
    __u32 global_lru_stats_key = MAX_VIPS + REMOTE_ENCAP_CNTRS;

    struct lb_stats* global_lru_stats_ = 
        bpf_map_lookup_elem(&stats, &global_lru_stats_key);
    if(!global_lru_stats_) {
        return XDP_DROP;
    }
    if(!g_lru_map) {
        global_lru_stats_->v1++; //记录
        /*
        我们无法检索此 cpu 的全局 lru。
        这个计数器在 prod (生产环境)中不应该是 0 以外的任何值。
        我们将使用它 monitoring.global_lru_stats->v1 += 1; 
        此 CPU 不存在全局 LRU 映射
        */
        g_lru_map = &fallback_glru;
    }

    connecttion_table_lookup(dst, pckt, g_lru_map, true);
    if(*dst) {
        global_lru_stats_->v2++;
    }

    return FURTHER_PROCESSING;
}
#endif //GLOBAL_LRU_LOOKUP
```

我们将在这里进行全局lru_map的更新替换与寻找dstIP地址。

首先进入perform_global_lru_lookup函数，我们通过global_lru_map映射，找到此刻在运行的cpu上存储的lru_map缓存，同时也找到相应的计数映射，如果没能找到此cpu上的lru_map缓存，那么计数统计，使用我们fallback_lru映射代替。调用connection_table_lookuo函数，在lru_map中寻找dstIP地址，如果找到了地址，那么统计相应的计数。返回继续处理。

### 2.1.13 还是找不到dstIp地址的解析：
```shell
if(!dst) {
            if(pckt.flow.proto == IPPROTO_TCP) {
                __u32 lru_stats_key = MAX_VIPS + LRU_MISS_CNTRS;
                struct lb_stats* lru_stats = 
                    bpf_map_lookup_elem(&stats, &lru_stats_key);
                if(!lru_stats) {
                    return XDP_DROP;
                }

                if(pckt.flags & F_SYN_SET) {
                    //由于新的 TCP 会话而错过
                    lru_stats->v1++;
                } else {
                    /*
                    非 SYN TCP 数据包未命中。可能是因为 LRU
                    垃圾桶或因为另一个 katran 正在重新启动，并且所有
                    会话已重新洗牌
                    */
                   //报告丢失 no_syn_lru_miss
                   lru_stats->v2++;
                }
            }
            
            // 2025-2-6-21:56
            if(!get_packet_dst(&dst, &pckt, vip_info, is_ipv6, lru_map_)) {
                return XDP_DROP;
            }

            if(update_vip_lru_miss_stats(&vip, &pckt, vip_info, is_ipv6)) {
                return XDP_DROP;
            }
            data_stats->v2++;
        }
    }
```

首先，前提条件是没能找到dstIP地址，那么我们记录相关统计数据，调用get_packet_dst函数获得dstIP地址。

！！在源码注释中，有这么一段注释：

```shell
/*
非 SYN TCP 数据包未命中。可能是因为 LRU
垃圾桶或因为另一个 katran 正在重新启动，并且所有
会话已重新洗牌
*/
```

```shell
__attribute__((__always_inline__)) static inline bool get_packet_dst(
    struct real_defination** dst,
    struct packet_description* pckt,
    struct vip_meta* vip_info,
    bool is_ipv6,
    void *lru_map
)
{
    struct real_pos_lru new_dst = {};
    bool under_flood = false;
    bool src_found = false;
    __u64 cur_time = 0;
    __u32 key;
    __u32 hash;
    __u32* real_pos;
    under_flood = is_under_flood(&cur_time);

#ifdef LPM_SRC_LOOKUP
    if((vip_info->flags & F_SRC_ROUTING) && !under_flood) {
        __u32* lpm_val;
        if(is_ipv6) {
            struct v6_lpm_key lpm_key_v6 = {};
            lpm_key_v6.prefixlen = 128;
            memcpy(lpm_key_v6.addrv6, pckt->flow.srcv6, 16);
            lpm_val = bpf_map_lookup_elem(&lpm_src_v6, &lpm_key_v6);
        } else {
            struct v4_lpm_key lpm_key_v4 = {};
            lpm_key_v4.prefixle = 32;
            lpm_key_v4.addr = pckt->flow.src;
            lpm_val = bpf_map_lookup_elem(&lpm_src_v4, &lpm_key_v4);
        }
        
        if(lpm_val) {
            src_found = true;
            key = *lpm_val;
        }

        __u32 stats_key = MAX_VIPS + LPM_SRC_CNTRS;
        struct lb_stats* lpm_stats = 
            bpf_map_lookup_elem(&stats, &stats_key);
        if(lpm_stats) {
            if(src_found) {
                lpm_stats->v2++;
            } else {
                lpm_stats->v1++;
            }
        }
    }
#endif

    if(!src_found) {
        bool hahs_16bytes = is_ipv6;

        if(vip_info->flags & F_HASH_DPORT_ONLY) {
            /*
            仅使用 DST 端口进行哈希计算的服务
            例如，如果数据包具有相同的 DST 端口 ->则它们将发送到相同的 real。
            通常是 VoIP 相关服务。
            */
           pckt->flow.port16[0] = pckt->flow.port16[1];
           memset(pckt->flow.srcv6, 0, 16);
        }
        hash = get_packet_hash(pckt, hahs_16bytes) % RING_SIZE;
        key = RING_SIZE * (vip_info->vip_num) + hash;

        real_pos = bpf_map_lookup_elem(&ch_rings, &key);
        if(!real_pos) {
            return false;
        }
        key = *real_pos;
        if(key == 0) {
            //这里，0代表初始化，我们的real ids 从1开始
            /*
            真实 ID 从 1 开始，因此我们不会将 id 0 映射到任何真实 ID。这
            如果 VIP 的 CH 环未初始化，则可能会发生这种情况。
            */
           increment_ch_drop_real_0(); //计数
           return false;
        }
    }
    //key != 0
    pckt->real_index = key;
    *dst = bpf_map_lookup_elem(&reals, &key);
    if(!(*dst)) {
        increment_ch_drop_no_real(); //计数
        return false;
    }

    if(lru_map && !(vip_info->flags & F_LRU_BYPASS) && !under_flood) {
        if(pckt->flow.proto == IPPROTO_UDP) {
            new_dst.atime = cur_time;
        }
        new_dst.pos = key;
        //更新LRU
        bpf_map_update_elem(lru_map, &pckt->flow, &new_dst, BPF_ANY);
    }
    return true;
}
```

我们来剖析这个函数，什么时候会走到这里？一个数据包在通过上述的所有可能下都未能找到dstIP地址的时候，会走到这儿。前面的所有操作只是在映射中寻找服务器的位置，而并非计算位置，说明数据包并不是第一次经过负载均衡，走到这里，意味着第一次负载均衡，这也是为什么卡特兰高性能的一个重要因素。

第一，如果定义了LPM_SRC_LOOKUP，又叫做路由匹配算法，这里，通过LPM类型的映射，存储服务器的位置。看代码，如果数据包标志中带有F_SRC_ROUTING标志，同时不在洪水之中，那么根据ipv4/ipv6在我们的LPM_SRC_v4/6映射中，寻找匹配到的服务器位置，更新相关计数量统计。

如果src_foud为false，意味着LPM_map中没有找到服务器的位置，所以，这里我们使用hash算法来计算出一个hash值，这个hash值映射我们服务器的位置，通过这个hash值，在ch_rings映射中，通过hash为key，匹配到服务器的位置为value。找到了real_pos，也就是我们数据包应该发往的服务器的位置。通过reals映射，以real_pos为key，匹配找到dstIP地址，如果未能找到dstIp地址，更新相应的统计数据。在此之后，我们更新lru_map，以数据包的flow流数据为key，dst_Ip地址为value，更新到lru_map中。

返回到主函数中，更新vip_lru_miss_stats：

```shell
__attribute__((__always_inline__)) static inline int update_vip_lru_miss_stats(
    struct vip_definition* vip,
    struct packet_description* pckt,
    struct vip_meta* vip_info,
    bool is_ipv6
){
    __u32 vip_miss_stats_key = 0;
    struct vip_definition* lru_miss_stat_vip = 
        bpf_map_lookup_elem(&vip_miss_stats, &vip_miss_stats_key);
    if(!lru_miss_stat_vip) {
        return XDP_DROP;
    }

    bool address_match = (is_ipv6 && 
                            (lru_miss_stat_vip->vipv6[0] == vip->vipv6[0] &&
                            lru_miss_stat_vip->vipv6[1] == vip->vipv6[1] && 
                            lru_miss_stat_vip->vipv6[2] == vip->vipv6[2] && 
                            lru_miss_stat_vip->vipv6[3] == vip->vipv6[3]))
                     || (!is_ipv6 && lru_miss_stat_vip->vip == vip->vip);
    bool port_match = lru_miss_stat_vip->port == vip->port;
    bool proto_match = lru_miss_stat_vip->proto == vip->proto;
    bool vip_match = address_match && port_match && proto_match;
    if(vip_match) {
        __u32 lru_stats_key = pckt->real_index;
        __u32* lru_miss_stats_ = bpf_map_lookup_elem(&lru_miss_stats, &lru_stats_key);
        if(!lru_miss_stats_) {
            return XDP_DROP;
        }

        *lru_miss_stats_ += 1;
    }
    return FURTHER_PROCESSING;
}
```

### 2.1.14 更新一些数据：
```shell
    cval = bpf_map_lookup_elem(&ctl_array, &mac_addr_pos);

    if(!cval) {
        return XDP_DROP;
    }

    data_stats = bpf_map_lookup_elem(&stats, &vip_num); 
    {
        if(!data_stats) {
            return XDP_DROP;
        }
        data_stats->v1++;
        data_stats->v2+= pkt_bytes; //数据包的大小
    }

    data_stats = bpf_map_lookup_elem(&reals_stats, &pckt.real_index);
    if(!data_stats) {
        return XDP_DROP;
    }

    data_stats->v1++;
    data_stats->v2+= pkt_bytes;

    //local_delivery_optimization 本地配送优化
#ifdef LOCAL_DELIVERY_OPTIMIZATION
    if((vip_info->flags & F_LOCAL_VIP) && (dst->flags & F_LOCAL_REAL)) {
        return XDP_PASS;
    }
#endif
```

更新一些数据统计，并且判断dstIp地址的标志中是否存在F_LOCAL_REAL，如果有，交给内核栈处理。

### 2.1.15 封装数据包并且发送：
```shell
    //封装操作
    //恢复原始 sport 值，将其用作 GUE 运动的种子
    pckt.flow.port16[0] = original_sport;
    if(dst->flags & F_IPV6) {
        if(!PCKT_ENCAP_V6(ctx, cval, is_ipv6, &pckt, dst, pkt_bytes)) {
            return XDP_DROP;
        }
    } else {
        if(!PCKT_ENCAP_V4(ctx, cval, is_ipv6, &pckt, dst, pkt_bytes)) {
            return XDP_DROP;
        }
    }
```

```shell
__attribute__((__always_inline__)) static inline bool encap_v6(
    struct xdp_md* ctx,
    struct ctl_value* cval,
    bool is_ipv6,
    struct packet_description* pkt,
    struct real_definition* dst,
    __u32 pkt_bytes
)
{
    void* data;
    void* data_end;
    struct ipv6hdr* ip6_hdr;
    struct ethhdr* new_eth;
    struct ethhdr* old_eth;
    __u16 payload_len;
    __u32 saddr[4];
    __u8 proto;

    //向前扩张sizeof(struct ipv6hdr)大小
    if(XDP_ADJUST_HEAD_FUNC(ctx, 0 - (int)sizeof(struct ipv6hdr))) {
        return false;
    }
    data = (void*)(long)ctx->data;
    data_end = (void*)(long)ctx->data_end;
    new_eth = data; //(struct ethhdr*)data
    old_eth = data + sizeof(struct ipv6hdr);//(struct ethhdr*)(data + sizeof(struct ipv6hdr))
    ip6_hdr = data + sizeof(struct ethhdr);//(struct ipv6hdr*)(data + sizeof(struct ethhdr))

    if(new_eth + 1 > data_end || old_eth + 1 > data_end || ip6_hdr + 1 > data_end) {
        return false; //调整失败
    }
    
    //构建mac帧
    memcpy(new_eth->h_dest, cval->mac, 6);
    memcpy(new_eth->h_source, old_eth->h_dest, 6);

    new_eth->h_proto = BE_ETH_P_IPV6;

    //构建outer_ipv6的原IP地址
    if(is_ipv6) {
        proto = IPPROTO_IPV6; 
        create_encap_ipv6_src(pkt->flow.port16[0], pkt->flow.srcv6[3], saddr);
        payload_len = pkt_bytes + sizeof(struct ipv6hdr);
    } else {
        proto = IPPROTO_IPIP;
        create_encap_ipv6_src(pkt->flow.port16[0], pkt->flow.src, saddr);
        payload_len = pkt_bytes;
    }

    create_v6_hdr(ip6_hdr, pkt->tos, saddr, dst->dstv6, payload_len, proto);
    return true;
}

//~
//ipip encap
__attribute__((__always_inline__)) static inline bool encap_v4(
    struct xdp_md* ctx,
    struct ctl_value* cval,
    bool is_ipv6,
    struct packet_description* pkt,
    struct real_definition* dst,
    __u32 pkt_bytes
)
{
    void* data;
    void* data_end;
    struct iphdr* ip_hdr;
    struct ethhdr* new_eth, *old_eth;

    if(XDP_ADJUST_HEAD_FUNC(ctx, 0 - (int)sizeof(struct iphdr))) {
        return false;
    }

    data = (void*)(long)ctx->data;
    data_end = (void*)(long)ctx->data_end;
    new_eth = data;
    old_eth = data + sizeof(struct iphdr);
    ip_hdr = data + sizeof(struct ethhdr);
    
    if(new_eth + 1 > data_end || old_eth + 1 > data_end || ip_hdr + 1 > data_end) {
        return false;
    }

    memcpy(new_eth->h_dest, cval->mac, 6);
    memcpy(new_eth->h_source, old_eth->h_dest, 6);
    new_eth->h_proto = BE_ETH_P_IP;

    //私网ip
    __u32 ip_src = create_encap_ipv4_src(pkt->flow.port16[0], pkt->flow.src);
    create_v4_hdr(ip_hdr, pkt->tos, ip_src, dst->dst, pkt_bytes, IPPROTO_IPIP);

    return true;
}
```

```shell
//~
__attribute__((__always_inline__)) static inline void create_encap_ipv6_src(
    __u16 port, __be32 src, __u32* saddr
)
{
    saddr[0] = IPIP_V6_PREFIX1;
    saddr[1] = IPIP_V6_PREFIX2;
    saddr[2] = IPIP_V6_PREFIX3;
    saddr[3] = src ^ port;
}

//~
__attribute__((__always_inline__)) static inline __u32 create_encap_ipv4_src(
    __u16 port,
    __be32 src
)
{
    __u32 ip_suffix = bpf_htons(port);
    ip_suffix <<= 10;
    ip_suffix ^= src;
    return ((0xFFFF0000 & ip_suffix) | IPIP_V4_PREFIX);
}

//~
__attribute__((__always_inline__)) static inline void create_v4_hdr(
    struct iphdr* ip_hdr,
    __u8 tos,
    __u32 saddr,
    __u32 daddr,
    __u16 palyload_len,
    __u8 proto
)
{
    __u64 csum = 0;
    ip_hdr->version = 4;
    ip_hdr->ihl = 5;
    ip_hdr->frag_off = 0;//意味着不是分片的数据包
    ip_hdr->protocol = proto;
    ip_hdr->check = 0;//校验和

#ifdef COPY_INNER_PACKET_TOS
    ip_hdr->tos = tos;
#else   
    ip_hdr->tos = DEFAULT_TOS;
#endif
    ip_hdr->tot_len = bpf_htons(palyload_len + sizeof(struct iphdr)); //tot_len是头部长度加上负载量
    ip_hdr->id = 0;
    ip_hdr->saddr = saddr;
    ip_hdr->daddr = daddr;
    ip_hdr->ttl = DEFAULT_TTL;
    ipv4_csum_inline(ip_hdr, &csum);
    ip_hdr->check = csum;
}

//~
__attribute__((__always_inline__)) static inline void create_v6_hdr(
    struct ipv6hdr* ip6_hdr,
    __u8 tos,
    __u32* saddr,
    __u32* daddr,
    __u16 palyload_len,
    __u8 proto
)
{
    ip6_hdr->version = 6;
    memset(ip6_hdr->flow_lbl, 0, sizeof(ip6_hdr->flow_lbl));

#ifdef COPY_INNER_PACKET_TOS
    ip6_hdr->priority = (tos & 0xF0) >> 4;
    ip6_hdr->flow_lbl[0] = (tos & 0x0F) << 4;
#else
    ip6_hdr->priority = DEFAULT_TOS;
#endif
    ip6_hdr->nexthdr = proto;
    ip6_hdr->payload_len = bpf_htons(palyload_len);
    memcpy(ip6_hdr->saddr.s6_addr32, saddr, 16);
    memcpy(ip6_hdr->daddr.s6_addr32, daddr, 16);
}
```

以上代码是encap的过程。

我们以v6讲解：

首先，调用bpf_xdp_adjust_head函数，将xdp_md向前扩充一个ipv6hdr的大小：

    data                                data_end

    👇                                    👇

【.   .   .】【.  .  .】【.  .  .】【.  .  .】

扩充了一个ipv6hdr的大小后：

         data                                data_end

    					👇                                    👇

【.  .  .】【.  .  .】【.  .  .】【.   .   .】【.  .  .】【.  .  .】【.  .  .】



      old_ethhdr

new_ethhdr                   data                                data_end

    👇 				👇                                    👇

【.  .  .】【.  .  .】【.  .  .】【.   .   .】【.  .  .】【.  .  .】【.  .  .】



new_ethhdr   ipv6hdr      data        old_ipv6hdr          data_end

    👇 		👇		👇                 👇                   👇

【.  .  .】【.  .  .】【.  .  .】【.   .   .】【.  .  .】【.  .  .】【.  .  .】

接下来填充ipv6hdr中的各个字段。

### 2.1.16 总结xdp程序（暂时的总结，需要了解分析示例数据包，以及grpc的示例后再来总结）：
**外界的数据包经过上层处理，将数据包原来的目的IP地址设置为VIP，经过卡特兰的处理，找到这个数据包应该发往哪一个服务器的IP地址，然后卡特兰将数据包改造，源地址是私网地址，目的地址是卡特兰记录的服务器的IP地址**

