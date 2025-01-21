#pragma once

#include <vector>
#include <cstdint>
#include <deque>

#include "BaseBpfAdapter.h"
#include "czkatranLbStructs.h"
#include "Balancer_structs.h"
#include "BpfAdapter.h"
#include <folly/Range.h>

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

class czKatranLb {

    public:
        czKatranLb() = delete;

        explicit czKatranLb(const czKatranConfig& config,
                            std::unique_ptr<BaseBpfAdapter>&& bpfAdapter);
        

        ~czKatranLb(); 


        /**
         * @brief 统计数据核心函数
         * @brief position: 映射的位置
         * @brief map: 映射map的名称，默认为 "stats"
         * @return lb_stats 统计数据
         */
        lb_stats getLbStats(uint32_t position, const std::string& map = "stats");


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




    private:
        // 配置信息
        czKatranConfig config_;

        /**
         * BPF 适配器到程序转发平面
         */
        std::unique_ptr<BaseBpfAdapter> bpfAdapter_;

        /**
         * 存储czkatranLb 中的数据
         */
        czKatranLbStats lbStats_;
//----------------------------------deque--------------------------------
        /**
         * * VIP、Reals 和 HCkeys 的未使用位置的向量。对于每个元素我们将从 vector 中弹出 position 的 num。对于已删除的 -将其推回（以便将来可以重复使用）
         */
        std::deque<uint32_t> vipNums_;
        std::deque<uint32_t> realNums_;
        std::deque<uint32_t> hcKeysNums_;

        /**
         * 若果是持久化模式下，会有一个root map
         */
        int rootMapFd_;
//----------------------------------bool---------------------------------
        /**
         * 是不是持久化模式
         */
        bool standalone_;

        /**
         * 是否已经加载了 BPF 程序
         */
        bool progsAttached_;
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
        std::vector<int> globalLruMapsFd;

};




}