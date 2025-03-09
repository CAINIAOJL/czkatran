# 一，总体设计原则：
转发实现采用了XDP技术，转发架构采用了DSR模式，长连接保持技术采用了一致性哈希算法。

整体XDP + DSR + Consistent Hashing

关于XDP程序参考balancer.bpf.c程序的解析，大体上，katran采用了IPIP数据包，GUE数据包来实现数据转发，

其中，IPIP数据包有IPV4包裹IPV4，或者IPV6包裹者IPV6和IPV4的形式，或者将客户端发送过来的数据包封装在GUE数据包中，解封GUE数据包，实现转发。bpf程序不断查找这个数据包应该发送到那个后端节点上。

整体设计思路和架构选择参考了cloudflare设计。

特点：

采用XDP程序，无需经过内核协议栈的处理，在服务器的网卡接受阶段即可处理转发，替代内核的<font style="color:rgb(54, 70, 78);background-color:rgb(245, 245, 245);">iptables</font><font style="background-color:rgb(245, 245, 245);">功能</font>。

实现与提供应用程序服务的同一服务器融为一体，实现软件代替硬件，降低了物理负载均衡的成本。

如果服务器支持，可以实现numa与XDP程序融合，将cpu与内存节点绑定，实现服务高可用性（服务器一半的cpu进行io读写，一半的cpu进行数据包的处理），高效利用cpu节点。

根据实际业务，可以在XDP程序中添加防火墙功能，实现ip过滤，预防DDos攻击

利用bpf的pin map特性，实现bpf程序的持久化操作。用于进程间共享eBPF对象

健康检查平面用于检查数据包的状态。

作为七层负载均衡的补充，与七层负载均衡一并存在。l4层负载均衡不用处理数据包的有效负载，仅处理数据包头部信息，实现负载均衡

# 二，关于map映射总结：
1.chring：RING_SIZE * (vip_info->vip_num) + hash 映射服务器节点的位置

_讲解：_

```cpp
std::vector<RealPos> Vip::calculateHashRing(std::vector<Endpoint> endpoints) {
  std::vector<RealPos> delta;
  RealPos new_pos;
  if (endpoints.size() != 0) {
    auto new_ch_ring = chash->generateHashRing(endpoints, chRingSize_);

    // compare new and old ch rings. send back only delta between em.
    for (int i = 0; i < chRingSize_; i++) {
      if (new_ch_ring[i] != chRing_[i]) {
        new_pos.pos = i;
        new_pos.real = new_ch_ring[i];
        delta.push_back(new_pos);
        chRing_[i] = new_ch_ring[i];
      }
    }
  }
  return delta;
}
```

上述代码，首先通过maglev算法，得到查询表。

通过查询表，我们收集real_pos这个结构体，这个结构体是这样子的，

```cpp
struct RealPos {
  uint32_t real;
  uint32_t pos;
};
```

其中 pos 是查询表的序号，real是服务器的位置，返回delta这个存储RealPos向量。注意，根据maglev算法，这个delta向量中会出现多个序号对应同一个后端服务器位置。一致性哈希。

```cpp
void KatranLb::programHashRing(
    const std::vector<RealPos>& chPositions,
    const uint32_t vipNum) {
  if (chPositions.empty()) {
    return;
  }

  if (!config_.testing) {
    uint32_t updateSize = chPositions.size();
    uint32_t keys[updateSize];
    uint32_t values[updateSize];

    auto ch_fd = bpfAdapter_->getMapFdByName(KatranLbMaps::ch_rings);
    for (uint32_t i = 0; i < updateSize; i++) {
      keys[i] = vipNum * config_.chRingSize + chPositions[i].pos;
      values[i] = chPositions[i].real;
    }

    auto res = bpfAdapter_->bpfUpdateMapBatch(ch_fd, keys, values, updateSize);
    if (res != 0) {
      lbStats_.bpfFailedCalls++;
      LOG(INFO) << "can't update ch ring"
                << ", error: " << folly::errnoStr(errno);
    }
  }
}
```

这个函数中，解释了ch_ring映射是如何生成的。首先找到ch_ring的文件描述符，更新map，其中key是虚拟ip的序号乘上chRing的大小（查询表的长度）加上查询表的序号，value是后端服务器的位置。

ctl_array：存储mac地址

decap_dst：这个映射用来解析数据包的目的地址，我们自主导向。INLINE_DECAP_GENERIC标识

fallback_cache:这个映射是缓存映射，但我们的lru_map为空时，为了不造成错误，将这个缓存映射替换上。

global_lru：全局映射表，如果定义GLOBAL_LRU_LOOKUP标识。

lpm_src_v4：<font style="color:rgb(25, 27, 31);">最长掩码匹配映射，我们在xdp程序中，解析数据包的流向时，可能会用到这个最长掩码匹配寻找目的ip地址，其中，最长前缀时32位，注意大端序和小端序的问题。如果定义LPM_SRC_LOOKUP标识。</font>

<font style="color:rgb(25, 27, 31);">lpm_src_v6：</font><font style="color:rgb(25, 27, 31);">最长掩码匹配映射，我们在xdp程序中，解析数据包的流向时，可能会用到这个最长掩码匹配寻找目的ip地址，其中，最长前缀时128位，注意大端序和小端序的问题。如果定义LPM_SRC_LOOKUP标识。</font>

<font style="color:rgb(25, 27, 31);">lru_mapping：cpu映射lru_map，每个cpu上都有一份lru映射。</font>

<font style="color:rgb(25, 27, 31);">reals：服务器的位置映射服务器的ip地址，这个映射是我们xdp转发的核心代码。</font>

<font style="color:rgb(25, 27, 31);">server_id_map：应用于QIUIC协议，标识id映射服务器位置。</font>

<font style="color:rgb(25, 27, 31);">vip_map：vip_definition结构映射vip_meta元数据。记录vip的相关标识和vip位置</font>

```cpp
struct vip_meta {
  __u32 flags;
  __u32 vip_num;
};
```

```cpp
struct vip_definition {
  union {
    __be32 vip;
    __be32 vipv6[4];
  };
  __u16 port;
  __u8 proto;
};
```

其余的map都是一些检查，计数映射，存储xdp程序在分析数据包时的一些状态变量，用作健康检查。



