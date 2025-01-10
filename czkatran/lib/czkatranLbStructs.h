#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <set>

#include "CHHelper.h"


namespace czkatran {

constexpr uint32_t kDefaultPriority = 2307;

namespace {
constexpr uint32_t kDefaultKatranPos = 2;
constexpr uint32_t kDefaultMaxVips = 512;
constexpr uint32_t kDefaultMaxReals = 4096;
constexpr uint32_t kLbDefaultChRingSize = 65537;
constexpr uint32_t kDefaultMaxLpmSrcSize = 3000000;
constexpr uint32_t kDefaultMaxDecapDstSize = 6;
constexpr uint32_t kDefaultNumOfPages = 2;
constexpr uint32_t kDefaultMonitorQueueSize = 4096;
constexpr uint32_t kDefaultMonitorPcktLimit = 0;
constexpr uint32_t kDefaultMonitorSnapLen = 128;
constexpr unsigned int kDefaultLruSize = 8000000;
constexpr uint32_t kDefaultGlobalLruSize = 100000;
constexpr uint32_t kNoFlags = 0;
constexpr uint32_t kUnspecifiedInterfaceIndex = 0;
std::string kNoExternalMap = "";
std::string kDefaultHcInterface = "";
std::string kAddressNotSpecified = "";
} // namespace

enum class PcapStorageFormat {
    FILE,
    IOBUF,
    PIPE, 
};



/**
 * @param uint32_t nCpus number of cpus
 * @param uint32_t pages number of pages for even pipe shared memory
 * @param int mapFd descriptor of event pipe map
 * @param uint32_t queueSize size of mpmc queue between readers and pcap writer
 * @param uint32_t maxPackets to capture, 0 - no limit
 * @param uint32_t snapLen maximum number of bytes from packet to write.
 * @param uint32_t maxEvents maximum supported events/pcap writers
 * @param std::string path where pcap outputs are going to be stored
 *
 * katran monitoring config. being used if katran's bpf code was build w/
 * introspection enabled (-DKATRAN_INTROSPECTION)
 */
struct KatranMonitorConfig {
  uint32_t nCpus;
  uint32_t pages{kDefaultNumOfPages};
  int mapFd;
  uint32_t queueSize{kDefaultMonitorQueueSize};
  uint32_t pcktLimit{kDefaultMonitorPcktLimit};
  uint32_t snapLen{kDefaultMonitorSnapLen};
  //std::set<monitoring::EventId> events{monitoring::kAllEventIds};
  std::string path{"/tmp/czkatran_pcap"};
  PcapStorageFormat storage{PcapStorageFormat::FILE};
  uint32_t bufferSize{0};
};




/**
 * struct which contains all configurations for KatranLB
 * @param string mainInterface name where to attach bpf prog (e.g eth0)           
 * 主要接口名字，用来附加bpf prog，例如（eth0网口）
 * @param string v4TunInterface name for ipip encap (for healtchecks)
 * ipv4隧道接口名称，用于ipip数据包（用于健康检查）
 * @param string v6TunInterface name for ip(6)ip6 encap (for healthchecks)
 * ipv6隧道接口名称，用于ipip数据包（用于健康检查）
 * @param string balancerProgPath path to bpf prog for balancer
 * 负载均衡器bpf程序的路径
 * @param string healthcheckingProgPath path to bpf prog for healthchecking
 * 健康检查bpf程序的路径
 * @param std::vector<uint8_t> defaultMac mac address of default router
 * 默认mac地址，默认路由器的mac地址
 * @param uint32_t tc priority of healtchecking task
 * tc 任务的优先级
 * @param string rootMapPath path to pinned map from root xdp prog
 * pinned map的路径，来自根xdp prog（持久化操作）
 * @param rootMapPos position inside rootMap
 * pinned map位置（索引）在rootMap中
 * @param bool enableHc flag, if set - we will load healthchecking bpf prog
 * 是否加载健康检查
 * @param bool tunnelBasedHCEncap flag, if set - katran will redirect packets to
 * 隧道基于健康检查，如果设置，负载均衡器会将数据包重定向到隧道接口
 * v4TunInterface and v6TunInterface to encap v4 and v6 packets respectively
 * using the bpf prog to healthcheck backend reals.
 * (xdp) bpf program
 * @param uint32_t maxVips maximum allowed vips to configure
 * 最大允许vip数量（虚拟ip的数量）
 * @param uint32_t maxReals maximum allowed reals to configure
 * 最大允许reals的数量
 * @param uint32_t chRingSize size of ch ring for each real
 * 每个real的ch环大大小
 * @param bool testing flag, if true - don't program forwarding
 * 测试模式，如果为true，则不会编程转发
 * @param uint64_t LruSize size of connection table
 * 连接表的 LruSize 尺寸
 * @param std::vector<int32_t> forwardingCores responsible for forwarding
 * 
 * @param std::vector<int32_t> numaNodes mapping of cores to NUMA nodes
 * 
 * @param uint32_t maxLpmSrcSize maximum size of map for src based routing
 * 
 * @param uint32_t maxDecapDst maximum number of destinations for inline decap
 * 
 * @param std::string hcInterface interface where we want to attach hc bpf prog
 * 健康检查的接口名称，用于附加健康检查的bpf程序
 * @param KatranMonitorConfig monitorConfig for katran introspection
 * 
 * @param memlockUnlimited should katran set memlock to unlimited by default
 * 系统内存资源最大化锁定变量
 * @param katranSrcV4 string ipv4 source address for GUE packets
 * GUE数据包的ipv4源地址
 * @param katranSrcV6 string ipv6 source address for GUE packets
 * GUE数据包的ipv6源地址
 * @param std::vector<uint8_t> localMac mac address of local server
 * 本地服务器的mac地址
 * @param HashFunction hashFunction to create hash ring
 * 创建hash环的hash函数
 * @param flowDebug if set, creates and populates extra debugging maps
 * debug流数据的信息变量
 * @param globalLruSize sets the size of the per-cpu global lru maps
 * 全局LRU映射的大小（每个cpu上的）
 * @param uint32_t mainInterfaceIndex, if not specified (0) then
 * 主要接口的索引
 * we'll attempt to resolve mainInterface name to the interface index
 * @param uint32_t hcInterfaceIndex, if not specified (0) then
 * 检查检查接口的索引
 * we'll attempt to resolve hcInterface name to the interface index
 *
 * note about rootMapPath and rootMapPos:
 * katran has two modes of operation.
 * the first one is "standalone":
 * when it register itself as one and only xdp prog; this is
 * default. for this mode to work rootMapPath must be equal to "".
 * and we dont evaluate rootMapPos (so it could be any value).
 *
 * the second mode of operation - "shared" -
 * is when we have root xdp prog: which is
 * just doing bpf_tail_call for other xdp's progs, which must registers
 * (put their fd's into predifiened position inside rootMap).
 * in this case rootMapPath must be path to "pinned" map, which has been
 * used by root xdp prog, and rootMapPos is a position (index) of
 * katran's fd inside this map.
 *
 * by default, if hcInterface is not specified we are going to attach
 * healthchecking bpf program to the mainInterfaces
 * 
 * 
 * 我们将尝试将 hcInterface 名称解析为接口索引
 *
 * 关于 rootMapPath 和 rootMapPos 的说明：
 * Katran 有两种操作模式。
 * 第一个是 “standalone”：
 * 当它注册为一个且唯一的 XDP 程序时;这是
 * 所以。要使此模式正常工作，rootMapPath 必须等于 “”。
 * 并且我们不评估 rootMapPos （所以它可以是任何值）。
 *
 * 第二种操作模式 - “共享” -
 * 是当我们有根 XDP 程序时：即
 * 只是对其他 XDP 的 progs 执行bpf_tail_call，这些 progs 必须注册
 * （将它们的 fd 放在 rootMap 中的 predifiened 位置）。
 * 在这种情况下，rootMapPath 必须是指向 “pinned” map 的路径，该 map 已被
 * 由根 xdp prog 使用，rootMapPos 是
 * 此地图中的 Katran 的 FD。
 *
 * 默认情况下，如果未指定 hcInterface，我们将附加
 * healthcheck bpf 程序添加到 mainInterfaces
 * 
 * 
 */
struct czKatranConfig {
  std::string mainInterface;
  std::string v4TunInterface = kDefaultHcInterface;
  std::string v6TunInterface = kDefaultHcInterface;
  std::string balancerProgPath;
  std::string healthcheckingProgPath;
  std::vector<uint8_t> defaultMac;
  uint32_t priority = kDefaultPriority;
  std::string rootMapPath = kNoExternalMap;
  uint32_t rootMapPos = kDefaultKatranPos;
  bool enableHc = true;
  bool tunnelBasedHCEncap = true;
  uint32_t maxVips = kDefaultMaxVips;
  uint32_t maxReals = kDefaultMaxReals;
  uint32_t chRingSize = kLbDefaultChRingSize;
  bool testing = false;
  uint64_t LruSize = kDefaultLruSize;
  std::vector<int32_t> forwardingCores;
  std::vector<int32_t> numaNodes;
  uint32_t maxLpmSrcSize = kDefaultMaxLpmSrcSize;
  uint32_t maxDecapDst = kDefaultMaxDecapDstSize;
  std::string hcInterface = kDefaultHcInterface;
  uint32_t xdpAttachFlags = kNoFlags;
  struct KatranMonitorConfig monitorConfig;
  bool memlockUnlimited = true;
  std::string katranSrcV4 = kAddressNotSpecified;
  std::string katranSrcV6 = kAddressNotSpecified;
  std::vector<uint8_t> localMac;
  HashFunction hashFunction = HashFunction::Maglev;
  bool flowDebug = false;
  uint32_t globalLruSize = kDefaultGlobalLruSize;
  bool useRootMap = true;
  bool enableCidV3 = false;
  uint32_t mainInterfaceIndex = kUnspecifiedInterfaceIndex;
  uint32_t hcInterfaceIndex = kUnspecifiedInterfaceIndex;
  bool cleanupOnShutdown = true;
};

//用户空间追踪状态的结构体
// userspace related stats to track internals of katran library
//记录bpf system call 失败的次数
struct czKatranLbStats {
  uint64_t bpfFailedCalls {0};
  uint64_t addrValidationFailed {0};
};



}