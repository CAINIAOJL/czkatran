#include "MaglevBase.h"
#include "MurmurHash3.h"



namespace czkatran {

namespace {
constexpr uint32_t kHashSeed0 = 0;
constexpr uint32_t kHashSeed1 = 2307;
constexpr uint32_t kHashSeed2 = 42;
constexpr uint32_t kHashSeed3 = 2718281828;
}

void MaglevBase:: genMaglevPermutation(
            std::vector<uint32_t>& permutation,
            const Endpoint& endpoint,
            const uint32_t pos,
            const uint32_t ring_size
        )
{
    //参考/home/jianglei/czkatran/explain/一致性哈希算法（四）- Maglev一致性哈希法 _ 春水煎茶.pdf
    /**
     * M 需要是一个质数
     * offset = h1(b) % M
     * skip = h2(b) % (M - 1) + 1
     * 
     * premutation = (offset + j * skip) % M !! （在这里，不计算permutation的实际值，在填表时计算）
     */
    
    auto offset_hash = MurmuHash3_x64_64(endpoint.hash, kHashSeed2, kHashSeed0);

    auto offset = offset_hash % ring_size;

    auto skip_hash = MurmuHash3_x64_64(endpoint.hash, kHashSeed3, kHashSeed1);

    auto skip = skip_hash % (ring_size - 1) + 1;

    //用一个长列表代替填表过程伪代码中的二维数组
    permutation[2 * pos] = offset;
    permutation[2 * pos + 1] = skip;
    //格式
    // 【offset1， skip1，offset2，skip2，offset3，skip3......】
}

}


