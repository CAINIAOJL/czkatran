#pragma once

#include <unordered_map>
#include <vector>
#include <cstdint>
#include "CHHelper.h"


namespace czkatran {

struct RealPos {
    uint32_t reals;
    uint32_t pos;
};


enum class ModifyAction {
    ADD,
    DEL,
};


struct UpdateReal {
    ModifyAction action;
    Endpoint updateReal;
};

//存储后端节点的weight和hash值
struct VipRealMeta {
    uint32_t weight;
    uint64_t hash;
};


class Vip {
    public:
        explicit Vip(uint32_t vipNum,
                    uint32_t vipFlags = 0,
                    uint32_t ringsize = kDefaultChRingSize,
                    HashFunction func = HashFunction::Maglev);

        //getters
        uint32_t getVipNum() const {
            return vipNum_;
        }
        uint32_t getVipFlags() const {
            return vipFlags_;
        }
        uint32_t getRingSize() const {
            return ringsize_;
        }

        /**
         * @brief 设置vip的flag
         */
        void setVipFlags(const uint32_t flags) {
            vipFlags_ |= flags;
        }
        /**
         * @brief 清除所有标志
         */
        void clearVipFlags() {
            vipFlags_ = 0;
        }
        /**
         * @brief 去除标志
         */
        void unsetVipFlags(const uint32_t flags) {
            vipFlags_ &= ~flags;
        }
        
        std::vector<uint32_t> getReals();

        std::vector<Endpoint> getRealsAndWeights();

        /**
         * @brief 添加真实节点
         * @param real 真实节点的endpoint
         * @return 返回真实节点在hash ring中的位置
         */
        std::vector<RealPos> addReal(Endpoint real);

        /**
         * @brief 删除真实节点
         * @param realNum 真实节点在hash ring中的位置
         */
        std::vector<RealPos> delReal(uint32_t realNum);

        /**
         * @brief 删除并且添加真实节点
         */
        std::vector<RealPos> batchRealsupdate(std::vector<UpdateReal>& ureals);

        /**
         * @brief 设置hash函数
         */
        void setHashFunction(HashFunction func);

        /**
         * @brief 重新计算hash ring
         */
        std::vector<RealPos> recalculateHashRing();


    private:
        
        std::vector<Endpoint> getEndpoint(std::vector<UpdateReal>& ureals);

        std::vector<RealPos> calculateHashRing(std::vector<Endpoint> endpoints);
        
        //vip的编号
        uint32_t vipNum_;

        //vip的flag
        uint32_t vipFlags_;
        
        //vip的hash函数
        uint32_t ringsize_;

        //标号和真实节点的映射
        std::unordered_map<uint32_t, VipRealMeta> reals_;

        //用于此 VIP 的 ch 环。我们将使用它用于增量计算（新旧 CH 环之间）
        std::vector<int> chRing_;

        std::unique_ptr<ConsistentHashing> chash; 
};


}