#pragma once
#include <cstdint>
#include <vector>


#include "CHHelper.h"

// 2025-1-6-22:00
namespace czkatran {

class MaglevBase: public ConsistentHashing {
    public:
        MaglevBase() {}

    /**
     * @brief 为每个后端节点生成一个偏好序列
     * @param permutation: the container of the generated permutation. 又称偏好序列
     * @param endpoints: the endpoints of the service. 权重
     * @param pos: the postion of the endpoint in the ring. 位置
     * @param ring_size: the size of the ring. 环的大小
     * @return 返回格式【offset1， skip1，offset2，skip2，offset3，skip3......】
     */
        static void genMaglevPermutation(
            std::vector<uint32_t>& permutation,
            const Endpoint& endpoint,
            const uint32_t pos,
            const uint32_t ring_size
        );
};


}