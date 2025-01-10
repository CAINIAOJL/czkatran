#include "MaglevHashV2.h"


namespace czkatran {

std::vector<int> MaglevHashV2::generateHashRing(
            std::vector<Endpoint> endpoints,
            const uint32_t ring_size
        )
{
    std::vector<int> hash_ring(ring_size, -1);

    if(endpoints.size() == 0) {
        return hash_ring;
    } else if (endpoints.size() == 1) {
        for(auto &v : hash_ring) {
            v = endpoints[0].num;
        }
        return hash_ring;
    }


    auto max_weight = 0;
    for(auto &code : endpoints) {
        if (code.weight > max_weight) {
            max_weight = code.weight;
        }
    }

    uint32_t runs = 0;
    std::vector<uint32_t> permutation(endpoints.size() * 2, 0);
    std::vector<uint32_t> next(endpoints.size(), 0);
    std::vector<uint32_t> csumweight(endpoints.size(), 0);


    for(int i = 0; i < endpoints.size(); i++) {
        genMaglevPermutation(permutation, endpoints[i], i, ring_size);
    }

    for(; ; ) {
        //不同担心前面权重低的节点，无限循环会走到前面
        //权重越高，先被处理的概率越大
        for(int i = 0; i < endpoints.size(); i++) {
            csumweight[i] += endpoints[i].weight;
            if (csumweight[i] > max_weight) {
                auto offset = permutation[2 * i];
                auto skip = permutation[2 * i + 1];
                auto cur = (offset + next[i] * skip)  % ring_size;
                while(hash_ring[cur] >= 0) {
                    next[i]++;
                    cur = (offset + next[i] * skip) % ring_size;
                }     
                hash_ring[cur] = endpoints[i].num;
                next[i]++;
                runs++;
                if(runs == ring_size) {
                    return hash_ring;
                }
            }
        }
    }
    return {};
}







}