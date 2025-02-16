#pragma once

#include <vector>
#include <cstdint>
#include <deque>

#include <folly/IPAddress.h>
#include <folly/Range.h>
#include <folly/container/F14Map.h>


#include "BaseBpfAdapter.h"
#include "czkatranLbStructs.h"
#include "Balancer_structs.h"
#include "BpfAdapter.h"
#include "Vip.h"
#include "czKatanMonitor.h"
#include "czkatranSimulator.h"


namespace czkatran {


/**
 * position of elements inside control vector
 */
constexpr int kMacAddrPos = 0;
constexpr int kIpv4TunPos = 1;
constexpr int kIpv6TunPos = 2;
constexpr int kMainIntfPos = 3;
constexpr int kHcIntfPos = 4;
constexpr int kIntrospectionGkPos = 5;

/**
 * constants are from balancer_consts.h
 */
constexpr uint32_t kLruCntrOffset = 0;
constexpr uint32_t kLruMissOffset = 1;
constexpr uint32_t kLruFallbackOffset = 3;
constexpr uint32_t kIcmpTooBigOffset = 4;
constexpr uint32_t kLpmSrcOffset = 5;
constexpr uint32_t kInlineDecapOffset = 6;
constexpr uint32_t kGlobalLruOffset = 8;
constexpr uint32_t kChDropOffset = 9;
constexpr uint32_t kDecapCounterOffset = 10;
constexpr uint32_t kQuicIcmpOffset = 11;
constexpr uint32_t kIcmpPtbV6Offset = 12;
constexpr uint32_t kIcmpPtbV4Offset = 13;


/**
 * LRU map related constants
 */
constexpr int kFallbackLruSize = 1024;
constexpr int kMapNoFlags = 0;
constexpr int kMapNumaNode = 4;
constexpr int kNoNuma = -1;

constexpr uint8_t V6DADDR = 1;
constexpr int kDeleteXdpProg = -1;
constexpr int kMacBytes = 6;
constexpr int kCtlMapSize = 16;
constexpr int kLruPrototypePos = 0;
constexpr int kMaxForwardingCores = 128;
constexpr int kFirstElem = 0;
constexpr int kError = -1;
constexpr uint32_t kMaxQuicIdV2 = 0x00fffffe; // 2^24-2
constexpr uint32_t kDefaultStatsIndex = 0;
constexpr folly::StringPiece kEmptyString = "";
constexpr uint32_t kSrcV4Pos = 0;
constexpr uint32_t kSrcV6Pos = 1;
constexpr uint32_t kRecirculationIndex = 0;
constexpr uint32_t kHcSrcMacPos = 0;
constexpr uint32_t kHcDstMacPos = 1;
constexpr folly::StringPiece kFlowDebugParentMapName = "flow_debug_maps";
constexpr folly::StringPiece kFlowDebugCpuLruName = "flow_debug_lru";
constexpr folly::StringPiece kGlobalLruMapName = "global_lru_maps";
constexpr folly::StringPiece kGlobalLruPerCpuName = "global_lru";

namespace {
constexpr folly::StringPiece KBalancerProgName = "balancer_ingress";
constexpr folly::StringPiece KHealthcheckerProgName = "healthcheck_encap";
}
//------------------------------------2025-2-14-------------------------------
namespace czKatranLbMaps {
constexpr auto ch_rings = "ch_rings";
constexpr auto ctl_array = "ctl_array";
constexpr auto decap_dst = "decap_dst";
constexpr auto event_pipe = "event_pipe";
constexpr auto fallback_cache = "fallback_cache";
constexpr auto fallback_glru = "fallback_glru";
constexpr auto flow_debug_lru = "flow_debug_lru";
constexpr auto flow_debug_maps = "flow_debug_maps";
constexpr auto global_lru = "global_lru";
constexpr auto global_lru_maps = "global_lru_maps";
constexpr auto hc_ctrl_map = "hc_ctrl_map";
constexpr auto hc_key_map = "hc_key_map";
constexpr auto hc_pckt_macs = "hc_pckt_macs";
constexpr auto hc_pckt_srcs_map = "hc_pckt_srcs_map";
constexpr auto hc_reals_map = "hc_reals_map";
constexpr auto hc_stats_map = "hc_stats_map";
constexpr auto czkatran_lru = "czkatran_lru";
constexpr auto lpm_src_v4 = "lpm_src_v4";
constexpr auto lru_mapping = "lru_mapping";
constexpr auto lru_miss_stats = "lru_miss_stats";
constexpr auto pckt_srcs = "pckt_srcs"; //packet_srcs !
constexpr auto per_hckey_stats = "per_hckey_stats";
constexpr auto reals = "reals";
constexpr auto server_id_map = "server_id_map";
constexpr auto stats = "stats";
constexpr auto vip_map = "vip_map";
constexpr auto vip_miss_stats = "vip_miss_stats";
} // namespace KatranLbMaps

namespace {

enum class czkatranMonitorState {
   DISABLED,
   ENABLED,
};

constexpr folly::StringPiece kBalancerProgName = "balancer_ingress";
constexpr folly::StringPiece kHealthcheckerProgName = "healthcheck_encap";

}
//------------------------------------2025-2-14-------------------------------
class czKatranLb {
    public:
//------------------------------------2025-2-14-------------------------------
        class RealsIdCallback {
            public:
                virtual ~RealsIdCallback() {}

                virtual void onRealAdded(const folly::IPAddress& real, uint32_t id) = 0;

                virtual void onRealDeleted(const folly::IPAddress& real, uint32_t id) = 0;
        };
//------------------------------------2025-2-14-------------------------------
        czKatranLb() = delete;

        explicit czKatranLb(const czKatranConfig& config,
                            std::unique_ptr<BaseBpfAdapter>&& bpfAdapter);
        

        ~czKatranLb(); 


        /**
         * @brief 统计数据
         * @brief v1: 我们未能获得全局 LRU 的次数 --核心映射 (v1)
         * @brief v2: 我们通过使用全局 LRU 来路由数据流的次数 --核心映射 (v2)
         * 
         */
        lb_stats getGlobalLruStats();


        int getHealthcheckerprogFd() {
                return bpfAdapter_->getProgFdByName(KHealthcheckerProgName.toString());
        }
//------------------------------------2025-2-14-------------------------------
        /**
         * @brief 增加一个新的真实服务器
         * @param real 真实服务器
         * @param vipNum vip 的编号
         */
        bool addRealForVip(
                const NewReal& real, 
                const VipKey& vip);
        
        /**
         * @brief 删除一个新的真实服务器
         * @param real 真实服务器
         * @param vipNum vip 的编号
         */
        bool deleteRealForVip(
                const NewReal& real, 
                const VipKey& vip);
        
        /**
         * @brief 修改真实服务器操作
         * @param action 操作类型
         * @param reals 真实服务器列表
         * @param vipNum vip 的编号
         */
        bool modifyRealsForVip(
                const ModifyAction action, 
                const std::vector<NewReal>& reals, 
                const VipKey& vip);
        
        /**
         * @brief 修改 quic 真实服务器操作
         * @param action 操作类型
         * @param reals quci 真实服务器列表
         */
        void modifyQuicRealsMapping(
                const ModifyAction action,
                const std::vector<QuicReal>& reals);
        
        /**
         * @brief 重启czkatran监控者
         * @param limit 限制
         */
        bool restartczKatranMonitor(
                uint32_t limit,
                std::optional<PcapStorageFormat> storage = std::nullopt);
        
        /**
         * @brief 添加vip
         * @param VipKey vip相关信息
         * @param flags 标志
         */
        bool addVip(const VipKey& vip, const uint32_t flags = 0);
//------------------------------------2025-2-14-------------------------------

//------------------------------------2025-2-15-------------------------------
        /**
         * @brief 修改vip标志
         * @param VipKey vip相关信息
         * @param flag 标志
         * @param set 是否设置标志
         */
        bool modifyVip(
                const VipKey& vip, 
                uint32_t flag, 
                bool set = true);
        
        /**
         * @brief 添加健康检查目标
         * @param somark somark
         * @param dst 目的地址
         */
        bool addHealthcheckerDst(
                const uint32_t somark, 
                const std::string& dst);
        /**
         * @brief 添加源路由规则
         * @param srcs 源路由规则
         * @param dst 目的地址
         */
        int addSrcRoutingRule(
                const std::vector<std::string>& srcs,
                const std::string& dst);
        
        int addSrcRoutingRule(
                const std::vector<folly::CIDRNetwork>& srcs,
                const std::string& dst);
        //删除源路由规则
        bool delSrcRoutingRule(const std::vector<std::string>& srcs);
        
        bool delSrcRoutingRule(const std::vector<folly::CIDRNetwork>& srcs);

        //增添decapDst
        bool addInlineDecapDst(const std::string& dst);
        
        bool modifyReal(
                const std::string& real, 
                uint8_t flags, 
                bool set = true);
        
        //为real组成五元组 flow流数据
        const std::string getRealForFlow(const czkatranFlow& flow);
//------------------------------------2025-2-15-------------------------------

//------------------------------------2025-2-16-------------------------------
        //加载bpf程序
        void loadBpfProgs();
        
        int getczKatranProgFd() {
                return bpfAdapter_->getProgFdByName(kBalancerProgName.toString());
        }
//--------------------------------------private---------------------------------
    private:
        //更新bpf-map
        bool updateRealsMap(
                const folly::IPAddress& real, 
                uint32_t num, 
                uint8_t flags = 0);
        
        /**
         * @brief 统计数据核心函数
         * @param position: 映射的位置
         * @param map: 映射map的名称，默认为 "stats"
         * @return lb_stats 统计数据
         */
        lb_stats getLbStats(uint32_t position, const std::string& map = "stats");

//------------------------------------2025-2-14-------------------------------
        //减少实际引用计数器
        void decreaseRefCountForReal(const folly::IPAddress& real);

        //增加实际引用计数器
        uint32_t increaseRefCountForReal(
                const folly::IPAddress& real,
                uint8_t flags = 0);
        
        /**
         * @brief 验证地址是否合法
         * @param address 地址
         * @param allowNetAddr 暂且不知
         */
        AddressType validateAddress(
                const std::string& address,
                bool allowNetAddr = false
        );

        /**
         * @brief 更新bpf-map（ch_ring）
         * @param chPositions ch_ring positions
         * @param VipNum vip 的编号
         */
        void programHashRing(
                const std::vector<RealPos>& chPositions,
                const uint32_t VipNum);
        
        /**
         * @brief 更改czkatran监控者转发平面的状态
         * @param state 状态
         */
        bool changeKatranMonitorForwardingState(czkatranMonitorState state);
        
        /**
         * @brief 更新vip map
         * @param action 操作类型
         * @param vip vip信息
         * @param meta vip meta信息
         */
        bool updateVipMap(
                const ModifyAction action,
                const VipKey& vip,
                vip_meta* meta = nullptr);

        /**
         * @brief 构造vip_definition
         * @param vip vip信息
         * @return vip_definition
         */
        vip_definition vipKeyToVipDefinition(const VipKey& vipKey);
//------------------------------------2025-2-14-------------------------------

//------------------------------------2025-2-15-------------------------------
        bool modifyLpmSrcRule(
                ModifyAction action,
                const folly::CIDRNetwork& src,
                uint32_t rnum);

        bool modifyLpmMap(
                const std::string& lpmMapNamePrefix,
                ModifyAction action,
                const folly::CIDRNetwork& addr,
                void* value);

        bool modifyDecapDst(
                ModifyAction action,
                const folly::IPAddress& dst,
                const uint32_t flags = 0);
        
//------------------------------------2025-2-16-------------------------------

        bool initSimulator();
        
        int getHealthcheckerProgFd() {
                return bpfAdapter_->getProgFdByName(kHealthcheckerProgName.toString());
        }

        void initLrus(
                bool flowDebug = false, 
                bool globalLru = false);
        
        int createLruMap(
                int size = kFallbackLruSize,
                int flags = kMapNoFlags,
                int numaNode = kNoNuma,
                int cpu = 0);

        void initFlowDebugMapForCore(
                int core, 
                int size, 
                int flags, 
                int numaNode);

        void initGlobalLruMapForCore(
                int core, 
                int size, 
                int flags, 
                int numaNode);

        void initFlowDebugPrototypeMap();

        void initGlobalLruPrototypeMap();

        void initialSanityChecking(
                bool flowDebug = false, 
                bool globalLru = false);

        void featureDiscovering();

        void setupGueEnvironment();

        void enableRecirculation();

        void setupHcEnvironment();

        void startIntrospectionRoutines();

        void attachLrus(
                bool flowDebug = false, 
                bool globalLru = false);

        void attachFlowDebugLru(int core);

        void attachGlobalLru(int core);
//------------------------------------2025-2-15-------------------------------

        // 配置信息
        czKatranConfig config_;
//----------------------------------ptr--------------------------------
        /**
         * BPF 适配器到程序转发平面
         */
        std::unique_ptr<BaseBpfAdapter> bpfAdapter_;
        
        /**
         * 监控程序
         */
        std::shared_ptr<czkatranMonitor> monitor_ {nullptr};

        /**
         * 模拟器
         */
        std::unique_ptr<czkatranSimulator> simulator_;

//----------------------------------other-----------------------------------
        /**
         * 存储czkatranLb 中的数据
         */
        czKatranLbStats lbStats_;

        // 特征结构体
        struct czkatranFeatrues features_;

        //ip地址------------------>RealMeta
        folly::F14FastMap<folly::IPAddress, RealMeta> reals_;

        //num(序号)----------------> ip地址
        folly::F14FastMap<uint32_t, folly::IPAddress> numToReals_;

        RealsIdCallback* realsIdCallback_ {nullptr};
//----------------------------------deque--------------------------------
        /**
         * * VIP、Reals 和 HCkeys 的未使用位置的向量。对于每个元素我们将从 vector 中弹出 position 的 num。对于已删除的 -将其推回（以便将来可以重复使用）
         */
        std::deque<uint32_t> vipNums_;
        std::deque<uint32_t> realNums_;
        std::deque<uint32_t> hcKeysNums_;

//----------------------------------bool/int---------------------------------
        /**
         * 若果是持久化模式下，会有一个root map
         */
        int rootMapFd_;
        /**
         * 是不是持久化模式
         */
        bool standalone_;

        /**
         * 是否已经加载了 BPF 程序
         */
        bool progsAttached_;

        /**
         * 是否已经加载了 BPF 程序
         */
        bool progsLoaded_{false};

        /**
         * 是否加载了监控器
         */
        bool introspectionStarted_{false};

        /**
         * 全局lru的fallback map
         */
        int globalLruFallbackFd_{-1};
//----------------------------------vector-------------------------------
        /**
         * 存储mac地址，ifindex信息的向量
         */
        std::vector<ctl_value> ctlValues_;

        /**
         * * 转发 CPU 的向量（负责 NIC 的 CPU/内核, IRQ 处理）
         */
        std::vector<int32_t> forwardingCores_;

        /**
         * * 可选向量，其中包含将核心转发到 NUMA NUMA 的映射此向量的长度必须为零（在本例中我们不使用它）或等于 forwardingCores_ 的长度
         */
        std::vector<int32_t> numaNodes_;
        /**
         * LRU maps 的文件描述符的向量
         */
        std::vector<int> lruMapsFd_;

        /**
         * 调试流数据的maps的文件描述符的向量
         */
        std::vector<int> flowDebugMapsFd_;

        /**
         * 全局 LRU maps 的文件描述符的向量
         */
        std::vector<int> globalLruMapsFd_;


//----------------------------------unorder_map-------------------------------
        //VipKey----------------->vip
        std::unordered_map<VipKey, Vip, VipKeyHasher> vips_;
        
        std::unordered_map<uint32_t, folly::IPAddress> quciMapping_; 
        
        std::unordered_map<uint32_t, folly::IPAddress> hcReals_;

        std::unordered_map<folly::CIDRNetwork, uint32_t> lpmSrcMapping_;

        std::unordered_set<folly::IPAddress> decapDsts_;
};




}