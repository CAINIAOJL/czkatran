#pragma once

#include <cstdint>
#include <memory>
#include <vector>


namespace czkatran {


constexpr uint32_t kDefaultChRingSize = 65537;

/**
 * struct 来描述后端，则每个后端都有唯一的编号，
 * 权重（我们看到此端点的频率的度量
 * 在 CH 环上）和哈希值，将用作种子值
 * （它应该是每个端点的唯一值，以便 CH 按预期工作）
 */
struct Endpoint {
    uint32_t num;
    uint32_t weight;
    uint64_t hash;
};

//一致性哈希算法接口
class ConsistentHashing {
    public:
        virtual std::vector<int> generateHashRing(
            std::vector<Endpoint> endpoints,
            const uint32_t ring_size = kDefaultChRingSize
        ) = 0;

        virtual ~ConsistentHashing() = default;
};

enum class HashFunction {
    Maglev,
    Maglev2,
};

//CH工厂类
class CHFactory {
    public:
        static std::unique_ptr<ConsistentHashing> make(HashFunction func);
};

}