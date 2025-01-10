#include "MaglevHash.h"

namespace czkatran {

std::vector<int> MaglevHash::generateHashRing(
            std::vector<Endpoint> endpoints,
            const uint32_t ring_size
        ) 
{
    std::vector<int> hash_ring(ring_size, - 1); //返回的哈希环

    if(endpoints.size() == 0) {
        return hash_ring;
    } else if (endpoints.size() == 1) {
        for (auto & v : hash_ring) {
            v = endpoints[0].num;
        }
        return hash_ring;
    }

    uint32_t runs = 0;
    std::vector<uint32_t> permutation(endpoints.size() * 2, 0);
    std::vector<uint32_t> next(endpoints.size(), 0);

    for (int i = 0; i < endpoints.size(); i++) {
        //生成偏好列表
        genMaglevPermutation(permutation, endpoints[i], i, ring_size);
    }

    for (; ;) {
        for(int i = 0; i < endpoints.size(); i++) {
            auto offset = permutation[2 * i];
            auto skip = permutation[2 * i + 1];
            for(int j = 0; j < endpoints[i].weight; j++) {
                auto cur = (offset + next[i] * skip) % ring_size;
                while(hash_ring[cur] >= 0) {
                    next[i] += 1;
                    cur = (offset + next[i] * skip) % ring_size;
                }
                hash_ring[cur] = endpoints[i].num;
                next[i] += 1;
                runs++;

                if(runs == ring_size) {
                    return hash_ring;
                }
            }
            endpoints[i].weight = 1;
        }
    }
    return {};
}

}