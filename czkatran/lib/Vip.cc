#include "Vip.h"

#include <algorithm>

namespace czkatran {

bool compareEndpoints(const Endpoint& a, const Endpoint& b) {
    return a.hash < b.hash;
}

Vip::Vip(uint32_t vipNum,
        uint32_t vipFlags,
        uint32_t ringsize ,
        HashFunction func): 
        vipNum_(vipNum), 
        vipFlags_(vipFlags), 
        ringsize_(ringsize), 
        chRing_(ringsize, -1) {
    chash = CHFactory::make(func); //工厂
}

void Vip::setHashFunction(HashFunction func) {
    chash = CHFactory::make(func);
}

std::vector<RealPos> Vip::calculateHashRing(std::vector<Endpoint> endpoints) {
    std::vector<RealPos> delta;
    RealPos new_pos;

    if(endpoints.size() != 0) {
        auto new_ch_ring = chash->generateHashRing(endpoints);

        for(int i = 0; i < ringsize_; i++) {
            if(new_ch_ring[i] != chRing_[i]) {
                new_pos.pos = i;
                new_pos.reals = new_ch_ring[i];
                delta.push_back(new_pos);
                chRing_[i] = new_ch_ring[i];
            }
        }
    }
    return delta;
}

std::vector<Endpoint> Vip::getEndpoint(std::vector<UpdateReal>& ureals) {
    Endpoint endpoint;
    std::vector<Endpoint> endpoints;

    bool reals_changed = false;

    for(auto& ureal : ureals) {
        if(ureal.action == ModifyAction::DEL) {
            reals_.erase(ureal.updateReal.num);
            reals_changed = true;
        } else if(ureal.action == ModifyAction::ADD) {
            auto cur_weight = reals_[ureal.updateReal.num].weight;
            if(cur_weight != ureal.updateReal.weight) {
                reals_[ureal.updateReal.num].weight = ureal.updateReal.weight;
                reals_[ureal.updateReal.num].hash = ureal.updateReal.hash;
                reals_changed = true;
            }
        }
    }

    if(reals_changed) {
        for(auto& real : reals_) {
            if(real.second.weight != 0) {
                endpoint.num = real.first;
                endpoint.weight = real.second.weight;
                endpoint.hash = real.second.hash;
                endpoints.push_back(endpoint);
            }
        }
    }
    std::sort(endpoints.begin(), endpoints.end(), compareEndpoints);
    return endpoints;
}


std::vector<RealPos> Vip::batchRealsupdate(std::vector<UpdateReal>& ureals) {
    auto endpoints = getEndpoint(ureals);
    return calculateHashRing(endpoints);
}

std::vector<Endpoint> Vip::getRealsAndWeights() {
    std::vector<Endpoint> endpoints(reals_.size());
    int i = 0;
    Endpoint endpoint;
    for(auto& real : reals_) {
        endpoint.num = real.first;
        endpoint.weight = real.second.weight;
        endpoint.hash = real.second.hash;
        endpoints[i++] = endpoint;
    }
    std::sort(endpoints.begin(), endpoints.end(), compareEndpoints);
    return endpoints;
}

std::vector<RealPos> Vip::recalculateHashRing() {
    auto reals = getRealsAndWeights();
    return calculateHashRing(reals);
}

std::vector<RealPos> Vip::addReal(Endpoint real) {
    std::vector<UpdateReal> reals;
    UpdateReal ureal;
    ureal.action = ModifyAction::ADD;
    ureal.updateReal = real;
    reals.push_back(ureal);
    return batchRealsupdate(reals);
}

std::vector<RealPos> Vip::delReal(uint32_t realNum) {
    std::vector<UpdateReal> reals;
    UpdateReal ureal;
    ureal.action = ModifyAction::DEL;
    ureal.updateReal.num = realNum;
    reals.push_back(ureal);
    return batchRealsupdate(reals);
}

std::vector<uint32_t> Vip::getReals() {
    std::vector<uint32_t> reals_num(reals_.size());
    int i = 0;
    for(auto &real : reals_) {
        reals_num[i++] = real.first;
    }
    return reals_num;
}

}