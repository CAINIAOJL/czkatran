#pragma once

#include <cstdint>
#include <vector>

#include "MaglevBase.h"

namespace czkatran {

class MaglevHashV2 : public MaglevBase {
    public:
        MaglevHashV2() {}

        /**
         * @brief 生成一致性哈希环
         * @param endpoints 节点列表
         * @param ring_size 环大小
         * @return 一致性哈希环
         */
        std::vector<int> generateHashRing(
            std::vector<Endpoint> endpoints,
            const uint32_t ring_size = kDefaultChRingSize
        ) override;
};

}