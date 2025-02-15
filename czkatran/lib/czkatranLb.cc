#include "czkatranLb.h"

#include <vector>
#include <cstdint>
#include <stdexcept> //异常处理头文件
#include <algorithm>

#include <fmt/core.h>
#include <folly/String.h>
#include <folly/IPAddress.h>
#include <glog/logging.h>

#include "czkatranLbStructs.h"
#include "IpHelpers.h"

namespace czkatran {

czKatranLb::czKatranLb(const czKatranConfig& config,
                            std::unique_ptr<BaseBpfAdapter>&& bpfAdapter):
                       config_(config),
                       bpfAdapter_(std::move(bpfAdapter)),
                       ctlValues_(kCtlMapSize),
                       standalone_(true),
                       forwardingCores_(config.forwardingCores),
                       numaNodes_(config.numaNodes),
                       lruMapsFd_(kMaxForwardingCores),
                       flowDebugMapsFd_(kMaxForwardingCores),
                       globalLruMapsFd(kMaxForwardingCores)
{   
    //对象构造的时候，先将三个队列填满，我们需要从队列中取出元素，在我们不需要的时候，将元素放回队列之中
    //比较巧妙的一种思想技术
    for(uint32_t i = 0; i < config.maxVips; i++) {
        vipNums_.push_back(i);
        if(config.enableHc) {
            hcKeysNums_.push_back(i);
        }
    }
    
  // realNums_ is a deque of available real indices.
  // Each index points to an entry in reals array.
  // When a new real (server) is added, it acquires the first available real
  // index from the queue and assigns it to this real server, and inserts the
  // real entry to the reals array at this particular index. In the datapath
  // (XDP) there are two primary ways for picking destination real for incoming
  // packets: i) Consisting hashing (with CH_Ring), and ii) reverse lookup of
  // server_id (with server_id_map) if present in the packets, such as for QUIC,
  // where server_id is bound to a real server. In either case, the mappings
  // from CH_Ring to real server and the mapping from server_id to real server
  // are independent of what is in realNums_.
  //
  // Example 1:
  //    Say, realNums_ initialized to {0, 1, 2}
  // After registering 3 quic servers, it will have server_id_map and reals
  // array as follows:
  //    reals = {10.0.0.1, 10.0.0.2, 10.0.0.3}
  //    server_id_map = {{101=>0}, {102=>1}, {103=>2}}
  // So 101, resolves to real server 10.0.0.1
  // Now if we change realNums_ to {1, 2, 3},
  // after registering 3 quic servers, it will have server_id_map and reals
  // array as follows:
  //    reals = {<reserved>, 10.0.0.1, 10.0.0.2, 10.0.0.3}
  //    server_id_map = {{101=>1}, {102=>2}, {103=>3}}
  // server_id 101 still resolves to 10.0.0.1
  //
  // Example 2:
  //    Say, realNums_ is {0, 1, 2}
  // Further, suppose there is 1 vip with 3 real servers with weights {2, 2, 3}.
  // CH_ring size is 2 + 2 + 3 = 7.
  // After CH_ring population, we get CH_ring (without shuffling) and reals
  // array as below
  //    CH_ring = {0, 0, 1, 1, 2, 2, 2}
  //    reals = {10.0.0.1, 10.0.0.2, 10.0.0.3}
  // Thus, from CH_ring index 0, which resolves to real-id 0, we get 10.0.0.1
  // Now we change realNums_ to {1, 2, 3}
  // After CH_ring population, we get CH_ring and reals array as below
  //    CH_ring = {1, 1, 2, 2, 3, 3, 3}
  //    reals = {<reserved>, 10.0.0.1, 10.0.0.2, 10.0.0.3}
  // CH_ring at index 0 it resolves to real-id 1, which still resolves
  // to 10.0.0.1
  //
  // Why avoid real-id 0?
  // BPF arrays are initialized with value of 0. So it's hard to disambiguate
  // issues where '0' is returned as server at index 0 vs error cases where it
  // couldn't find the server. So we preserve 0 as the invalid entry to reals
  // array.


    for(uint32_t i = 0; i < config_.maxReals; i++) {
        realNums_.push_back(i);
    }

    //判断是不是持久化操作
    if(!config_.rootMapPath.empty()) {
        standalone_ = false;
    }

    if(config_.hcInterface.empty()) {
        config_.hcInterface = config_.mainInterface;
    }

    if(!config_.testing) {
        ctl_value ctl;
        uint32_t res;

        //检查mac地址
        if(config_.defaultMac.size() != 6) {
            throw std::invalid_argument("mac's size is not equal to six !");
        }
        for(int i = 0; i < 6; i++) {
            ctl.mac[i] = config_.defaultMac[i];
        }
        //记录这个位置的mac地址
        ctlValues_[kMacAddrPos] = ctl;

        //需要健康检查
        if(config_.enableHc) {
            res = config_.hcInterfaceIndex;
            if(res == 0) {
                res = bpfAdapter_->getInterfaceIndex(config_.hcInterface);
                if(res == 0) {
                    throw std::invalid_argument(fmt::format("can not resolve ifindex for healthcheck interface {}, error: {}", \
                                                            config_.hcInterface, 
                                                            folly::errnoStr(errno)));
                }
            }
            //将相关信息存储到ctlValues_中
            ctl.ifindex = res;
            ctlValues_[kHcIntfPos] = ctl;
            //ipv4
            if(config_.tunnelBasedHCEncap) {
                res = bpfAdapter_->getInterfaceIndex(config_.v4TunInterface);
                if(!res) {
                    throw std::invalid_argument(fmt::format("can not resolve infindex for v4tunel inf, error: {}",
                                                folly::errnoStr(errno)));
                }
                ctl.ifindex = res;
                ctlValues_[kIpv4TunPos] = ctl;

                //将相关信息存储到ctlValues_中
                //ipv6
                res = bpfAdapter_->getInterfaceIndex(config_.v6TunInterface);
                if(!res) {
                    throw std::invalid_argument(fmt::format("can not resolve infindex for v6tunel inf, error: {}",
                                                folly::errnoStr(errno)));
                }
                ctl.ifindex = res;
                ctlValues_[kIpv6TunPos] = ctl;
            }
        }

        res = config_.mainInterfaceIndex;
        if(res == 0) {
            res = bpfAdapter_->getInterfaceIndex(config_.mainInterface);
            if (res == 0) {
                throw std::invalid_argument(fmt::format("can't resolve ifindex for main intf {}, error: {}",
                                                     config_.mainInterface, 
                                                     folly::errnoStr(errno)));
            }
        }
        //将相关信息存储到ctlValues_中
        ctl.ifindex = res;
        ctlValues_[kMainIntfPos] = ctl;
    }
}


czKatranLb::~czKatranLb() {
    if(!config_.testing && progsAttached_ && config_.cleanupOnShutdown) {
        int res;
        auto mainIfindex = ctlValues_[kMainIntfPos].ifindex;
        auto hcIfindex = ctlValues_[kHcIntfPos].ifindex;
        
        //是不是持久化操作
        if(standalone_) {
            res = bpfAdapter_->detachXdpProgram(mainIfindex, config_.xdpAttachFlags);
        } else {
            res = bpfAdapter_->bpfMapDeleteElement(rootMapFd_, &config_.rootMapPos);
        }

        if(res != 0) {
            LOG(INFO) << fmt::format("can not delete main bpf prog, error: {}", 
                                    folly::errnoStr(errno));
        }

        //需要健康检查
        //2025-1-8-22:31
        if(config_.enableHc) {
            res = bpfAdapter_->deleteTcBpfFilter(
                getHealthcheckerprogFd(),
                hcIfindex,
                "czkatran-healthchecker",
                config_.priority,
                TC_EGRESS
            );
            if(res != 0) {
                LOG(INFO) << fmt::format("can not delete hc bpf prog, error: {}",
                                        folly::errnoStr(errno));
            }
        }
    }
}


lb_stats czKatranLb:: getGlobalLruStats() {
    return getLbStats(config_.maxVips + kGlobalLruOffset);
}

lb_stats czKatranLb:: getLbStats(
        uint32_t position, 
        const std::string& map) {
    unsigned int nr_cpus = BpfAdapter::getPossibleCpus();
    if(nr_cpus < 0) {
        LOG(ERROR) << "getLbStats error: can't get number of possible cpus";
        return lb_stats();
    }
    lb_stats stats[nr_cpus];
    lb_stats sum_stats = {};

    if(!config_.testing) {
        auto res = bpfAdapter_->bpfMapLookUpElement(
            bpfAdapter_->getMapFdByName(map),
            &position,
            stats
        );
        if(!res) {
            for(auto &s : stats) {
                sum_stats.v1 += s.v1;
                sum_stats.v2 += s.v2;
            }
        } else {
            lbStats_.bpfFailedCalls++;
        }
    }
    return sum_stats;
}


//------------------------------------2025-2-14-------------------------------
AddressType czKatranLb:: validateAddress(//--------------------------√
    const std::string& address,
    bool allowNetAddr
)
{
    if(!folly::IPAddress::validate(address)) {
        if(allowNetAddr && (features_.srcRouting || config_.testing)) {
            auto res = folly::IPAddress::tryCreateNetwork(address);
            if(res.hasValue()) {
                return AddressType::NETWORK; 
            }
        }
        lbStats_.addrValidationFailed++;
        LOG(ERROR) << "invalid address : " << address;
        return AddressType::INVALID;
    }
    return AddressType::HOST;
}

bool czKatranLb:: addRealForVip(//--------------------------√
    const NewReal& real, 
    const VipKey& vip)
{
    std::vector<NewReal> reals;
    reals.push_back(real);
    return modifyRealsForVip(ModifyAction::ADD, reals, vip);
}

bool czKatranLb:: deleteRealForVip(//--------------------------√
    const NewReal& real, 
    const VipKey& vip)
{
    std::vector<NewReal> reals;
    reals.push_back(real);
    return modifyRealsForVip(ModifyAction::DEL, reals, vip);
}

void czKatranLb:: decreaseRefCountForReal(const folly::IPAddress& real)//--------------------------√
{
    auto real_iter = reals_.find(real);
    if(real_iter == reals_.end()) {
        return;
    }
    real_iter->second.refCount--;
    if(real_iter->second.refCount == 0) {
        auto num = real_iter->second.num;
        //循环利用
        realNums_.push_back(num); //放入队列
        reals_.erase(real_iter); //删除
        numToReals_.erase(num);

        if(realsIdCallback_) {
            realsIdCallback_->onRealDeleted(real, num);
        }
    }
}

bool czKatranLb::updateRealsMap(//--------------------------√
    const folly::IPAddress& real,
    uint32_t num,
    uint8_t flags)
{
    auto real_addr = IpHelpers::parseAddrToBe(real);
    flags &= ~V6DADDR;
    real_addr.flags |= flags;
    auto res = bpfAdapter_->bpfUpdateMap(
        bpfAdapter_->getMapFdByName("reals"),
        &num,
        &real_addr
    );
    if(res != 0) {
        LOG(INFO) << "can not add new reals, error" << folly::errnoStr(errno);
        lbStats_.bpfFailedCalls++;
        return false;
    }
    return true;

}

uint32_t czKatranLb:: increaseRefCountForReal(//--------------------------√
    const folly::IPAddress& real,
    uint8_t flags)
{
    auto real_iter = reals_.find(real);
    flags &= ~V6DADDR;
    if(real_iter != reals_.end()) {
        real_iter->second.refCount++; //计数器加一
        return real_iter->second.num; //返回序号
    } else {
        if(realNums_.size() == 0) {
            return config_.maxReals;
        }
        RealMeta rmeta;
        auto rnum = realNums_[0];
        realNums_.pop_front();
        numToReals_[rnum] = real;
        rmeta.refCount = 1;
        rmeta.num = rnum;
        rmeta.flags = flags;
        reals_[real] = rmeta;
        if(!config_.testing) {//不是测试，更新bpf-map
            updateRealsMap(real, rnum, flags);
        }
        if(realsIdCallback_) {
            realsIdCallback_->onRealAdded(real, rnum);
        }
        return rnum;
    }
}


bool czKatranLb:: modifyRealsForVip(//--------------------------√
    const ModifyAction action, 
    const std::vector<NewReal>& reals, 
    const VipKey& vip
)
{
    UpdateReal ureal;
    std::vector<UpdateReal> ureals;
    ureal.action = action;

    auto vip_it = vips_.find(vip);
    if(vip_it == vips_.end()) {
        LOG(INFO) << fmt::format("can not find vip {}", vip.address);
        return false;
    }
    auto cur_reals = vip_it->second.getReals();

    for(const auto& real : reals) {
        if(validateAddress(real.address) == AddressType::INVALID) {
            LOG(ERROR) << "Invalid real's address " << real.address;
            continue; 
        }
        folly::IPAddress raddr(real.address);
        VLOG(4) << fmt::format(
            "modifying real {} with weight {} for vip {} : {} : {}. action is {}",
            real.address,
            real.weight,
            vip.address,
            vip.port,
            vip.proto,
            action == ModifyAction::ADD ? "add" : "delete"
        );

        if(action == ModifyAction::DEL) {
            //删除
            auto real_iter = reals_.find(raddr);
            if(real_iter == reals_.end()) {
                LOG(INFO) << "can not find real to delete real (non-existing real)";
                continue;
            }
            if(std::find(cur_reals.begin(), cur_reals.end(), real_iter->second.num) == cur_reals.end()) {
                LOG(INFO) << fmt::format(
                    "can not delete real (non-existing real) for the Vip: {}", vip.address
                );
                continue;
            }
            ureal.updateReal.num = real_iter->second.num;
            decreaseRefCountForReal(raddr);
        } else {
            //增加
            auto real_iter = reals_.find(raddr);
            if(real_iter != reals_.end()) {
                if(std::find(cur_reals.begin(), cur_reals.end(), real_iter->second.num) == cur_reals.end()) {
                    //新的节点对于虚拟ip而言
                    increaseRefCountForReal(raddr, real.flags);
                    //复用问题，
                    cur_reals.push_back(real_iter->second.num);
                }
                ureal.updateReal.num = real_iter->second.num;
            } else {
                auto rnum = increaseRefCountForReal(raddr, real.flags);
                if(rnum == config_.maxReals) {
                    LOG(INFO) << "exhausted real's space";
                    continue;
                }
                ureal.updateReal.num = rnum;
            }
            ureal.updateReal.weight = real.weight;
            ureal.updateReal.hash = raddr.hash();
        }
        ureals.push_back(ureal);
    }

    //更新xdp程序中的ch_ring map
    auto ch_positions = vip_it->second.batchRealsupdate(ureals);
    auto vip_num = vip_it->second.getVipNum(); //得到虚拟ip的序号
    programHashRing(ch_positions, vip_num);
    return true;
}

void czKatranLb:: programHashRing(//--------------------------√
    const std::vector<RealPos>& chPositions,
    const uint32_t VipNum)
{
    if(chPositions.size() == 0) {
        return;
    }

    //不是测试
    if(!config_.testing) {
        uint32_t updateSize = chPositions.size();
        uint32_t keys[updateSize];
        uint32_t values[updateSize];

        auto ch_fd = bpfAdapter_->getMapFdByName(czKatranLbMaps::ch_rings);
        for(uint32_t i = 0; i < updateSize; i++) {
            //bpf balancer.bpf.c: 对应
            //key = RING_SIZE * (vip_info->vip_num) + hash;
            keys[i] = VipNum * config_.chRingSize + chPositions[i].pos;
            values[i] = chPositions[i].real;
        }

        auto res = bpfAdapter_->bpfUpdateMapBatch(ch_fd, keys, values, updateSize);
        if(res != 0) {
            lbStats_.bpfFailedCalls++;
            LOG(INFO) << "can not update ch ring map, errno = " << folly::errnoStr(errno);
        }
    }   
}

void czKatranLb:: modifyQuicRealsMapping(//--------------------------√
    const ModifyAction action,
    const std::vector<QuicReal>& reals)
{
    std::unordered_map<uint32_t, uint32_t> to_update;
    for(const auto& real : reals) {
        if(validateAddress(real.address) == AddressType::INVALID) {
            LOG(ERROR) << "Invalid quic real's address " << real.address;
            continue; 
        }
        if(!config_.enableCidV3 && (real.id > kMaxQuicIdV2)) {
            LOG(ERROR) << "(out of assigned space)Invalid quic real's id " << real.id;
            continue;
        }

        VLOG(4) << fmt::format(
            "modifying quic real {} with id 0x{:x}. action is {}",
            real.address,
            real.id,
            action == ModifyAction::ADD ? "add" : "delete"
        );
        auto raddr = folly::IPAddress(real.address); //folly::IPAddress
        auto real_iter = quciMapping_.find(real.id);
        if(action == ModifyAction::DEL) {
            //DEL
            if(real_iter == quciMapping_.end()) {
                LOG(ERROR) << fmt::format(
                    "can not find quic real to delete real (non-existing real) for id 0x{:x} and IPAddress is {}",
                    real.id,
                    real.address
                );
                continue;
            }
            if(real_iter->second != raddr) {
                LOG(ERROR) << fmt::format(
                    "different IPAddress for the same id 0x{:x}, and IPAddress in mapping is {}, and given IPAddress is {}",
                    real.id,
                    real_iter->second.str(),
                    real.address  
                );
                continue;
            }
            decreaseRefCountForReal(raddr); //计数器减一
            quciMapping_.erase(real_iter);
        } else {
            //ADD
            if(real_iter != quciMapping_.end()) {
                if(real_iter->second == raddr) {
                    continue;
                }
                LOG(WARNING) << fmt::format(
                    "overriding IPAddress {} for existing mapping id {}, mapping IPAddress {}",
                    real.address,
                    real.id,
                    real_iter->second.str()
                );
                decreaseRefCountForReal(real_iter->second);
            }
            auto rnum = increaseRefCountForReal(raddr);
            if(rnum == config_.maxReals) {
                LOG(ERROR) << "exhausted real's space";
                continue;
            }
            to_update[real.id] = rnum;
            quciMapping_[real.id] = raddr; //更新mapping
        }
    }
    //不是在测试，要去更新bpf-map
    if(!config_.testing) {
        auto server_id_map_fd = 
            bpfAdapter_->getMapFdByName(czKatranLbMaps::server_id_map);
        uint32_t id, rnum;
        int res;
        for(auto& mapping : to_update) {
            id = mapping.first;
            rnum = mapping.second;
            res = bpfAdapter_->bpfUpdateMap(server_id_map_fd, &id, &rnum);
            if(res != 0) {
                LOG(ERROR) << "can not update quci mapping, error : " << folly::errnoStr(errno);
                lbStats_.bpfFailedCalls++;
            }
        }
    }
}

bool czKatranLb:: changeKatranMonitorForwardingState(czkatranMonitorState state)//--------------------------√
{
    uint32_t key = kIntrospectionGkPos;
    struct ctl_value value;
    switch(state) {
        case czkatranMonitorState::ENABLED:
            value.value = 1;
            break;
        case czkatranMonitorState::DISABLED:
            value.value = 0;
            break;
    }

    auto res = bpfAdapter_->bpfUpdateMap(
        bpfAdapter_->getMapFdByName(czKatranLbMaps::ctl_array),
        &key,
        &value
    );
    if(res != 0) {
        LOG(INFO) << "can not change state of introspection forwarding plane";
        lbStats_.bpfFailedCalls++;
        return false;
    }
    return true;
}

bool czKatranLb:: restartczKatranMonitor(//--------------------------√
    uint32_t limit,
    std::optional<PcapStorageFormat> storage)
{
    if(!monitor_) {
        return false;
    }
    if(!changeKatranMonitorForwardingState(czkatranMonitorState::ENABLED)) {
        return false; //关闭监视者
    }
    monitor_->restartMonitor(limit, storage);
    return true;
}

vip_definition czKatranLb:: vipKeyToVipDefinition(const VipKey& vipKey)//--------------------------√
{
    auto vip_addr = IpHelpers::parseAddrToBe(vipKey.address);
    vip_definition vip_def = {};
    if((vip_addr.flags & V6DADDR) > 0) {
        //ipv6
        std::memcpy(&vip_def.vipv6, &vip_addr.v6daddr, 16);
    } else {
        vip_def.vip = vip_addr.daddr;
    }
    vip_def.proto = vipKey.proto;
    //vip_def.port = vipKey.port;
    vip_def.port = folly::Endian::big(vipKey.port); //大端序
    return vip_def;
}

bool czKatranLb:: updateVipMap(//--------------------------√
    const ModifyAction action,
    const VipKey& vip,
    vip_meta* meta)
{
    struct vip_definition vip_def = vipKeyToVipDefinition(vip);
    if(action == ModifyAction::ADD) {
        //add
        auto res = bpfAdapter_->bpfUpdateMap(
            bpfAdapter_->getMapFdByName(czKatranLbMaps::vip_map),
            &vip_def,
            &meta
        );
        if(res != 0) {
            LOG(INFO) << "can not add new element into vip_map, error: " << folly::errnoStr(errno);
            lbStats_.bpfFailedCalls++;
            return false;
        }
    } else {
        //del
        auto res = bpfAdapter_->bpfMapDeleteElement(
            bpfAdapter_->getMapFdByName(czKatranLbMaps::vip_map),
            &vip_def
        );
        if(res != 0) {
            LOG(INFO) << "can not delete element from vip_map, error: " << folly::errnoStr(errno);
            lbStats_.bpfFailedCalls++;
            return false;
        }
    }
    return true;
}

bool czKatranLb:: addVip(const VipKey& vip, const uint32_t flags = 0)//--------------------------√
{
    if(validateAddress(vip.address) == AddressType::INVALID) {
        LOG(ERROR) << "Invalid vip's address " << vip.address;
        return false;
    }
    LOG(INFO) << fmt::format(
        "adding new vip: address {}: prot {}: proto{}",
        vip.address,
        vip.port,
        vip.proto
    );
    //deque
    if(vipNums_.size() == 0) {
        LOG(INFO) << "exhausted vip's space";
        return false;
    }
    if(vips_.find(vip) != vips_.end()) {
        LOG(INFO) << "vip already exists";
        return false;
    }
    auto vip_num = vipNums_[0]; //队列的前面
    vipNums_.pop_front();
    vips_.emplace(
        vip, Vip(vip_num, flags, config_.chRingSize, config_.hashFunction)
    );
    if(!config_.testing) {
        vip_meta meta;
        meta.flags = flags;
        meta.vip_num = vip_num;
        updateVipMap(ModifyAction::ADD, vip, &meta);
    }
    return true;
}
//------------------------------------2025-2-14-------------------------------

//------------------------------------2025-2-15-------------------------------

bool czKatranLb:: modifyVip(//--------------------------√
    const VipKey& vip, 
    uint32_t flag, 
    bool set)
{
    LOG(INFO) << fmt::format(
        "modifyVip vip : IPAddress {} port {} proto {}",
        vip.address,
        vip.port,
        vip.proto
    );

    auto vip_iter = vips_.find(vip);
    if(vip_iter == vips_.end()) {
        LOG(INFO) << fmt::format(
            "vip not found Vip : {}",
            vip.address
        );
        return false;
    }

    if(set) {
        vip_iter->second.setVipFlags(flag);
    } else {
        vip_iter->second.unsetVipFlags(flag);
    }

    if(!config_.testing) {
        vip_meta meta;
        meta.vip_num = vip_iter->second.getVipNum();
        meta.flags = vip_iter->second.getVipFlags();
        return updateVipMap(ModifyAction::ADD, vip, &meta);
    }
    return true;
}

bool czKatranLb:: addHealthcheckerDst(//--------------------------√
    const uint32_t somark, 
    const std::string& dst)
{
    if(!config_.enableHc) {
        LOG(INFO) << "healthchecking is disabled ! ";
        return false;
    }
    if(validateAddress(dst) == AddressType::INVALID) {
        LOG(ERROR) << "Invalid healthchecker's address " << dst;
        return false;
    }
    VLOG(4) << fmt::format(
        "adding new healthchecker with somark {} and dst {} ",
        somark,
        dst
    );

    folly::IPAddress hcaddr (dst);
    uint32_t key = somark;
    beaddr addr;

    auto hc_iter = hcReals_.find(somark);
    if(hc_iter == hcReals_.end() && hcReals_.size() == config_.maxReals) {
        LOG(INFO) << "healthchecker's space exhausted";
        return false;
    }

    if(hcaddr.isV4() && !features_.directHealthchecking) {
        addr = IpHelpers::parseAddrToint(hcaddr);
    } else {
        addr = IpHelpers::parseAddrToBe(hcaddr);
    }

    if(!config_.testing) {
        auto res = bpfAdapter_->bpfUpdateMap(
            bpfAdapter_->getMapFdByName(czKatranLbMaps::hc_reals_map),
            &key,
            &addr
        );
        if(res != 0) {
            LOG(INFO) << "can not add new element into hc_reals_map, error: " << folly::errnoStr(errno);
            lbStats_.bpfFailedCalls++;
            return false;
        }
    }
    hcReals_[somark] = hcaddr;
    return true;
}

int czKatranLb:: addSrcRoutingRule(//--------------------------√
    const std::vector<std::string>& srcs,
    const std::string& dst)
{
    int num_errors = 0;
    if(!features_.srcRouting && !config_.testing) {
        LOG(ERROR) << "Source based routing is not enabled for xdp forwarding plane";
        return kError;
    }
    if(validateAddress(dst) == AddressType::INVALID) {
        LOG(ERROR) << fmt::format(
            "Invalid dst address: {} for src routing rule",
        dst);
        return kError;
    }

    std::vector<folly::CIDRNetwork> src_networks;
    for(auto& src : srcs) {
        if(validateAddress(src, true) != AddressType::NETWORK) {
            LOG(ERROR) << fmt::format(
                "Invalid src address: {} for src routing rule",
                src
            );
            num_errors++;
            continue;
        }
        if(lpmSrcMapping_.size() + src_networks.size() + 1 > config_.maxLpmSrcSize) {
            LOG(ERROR) << "Source based routing space exhausted";
            num_errors += (srcs.size() - src_networks.size()); //剩下的
            break;
        }
        src_networks.push_back(folly::IPAddress::createNetwork(src));
    }
    auto val = addSrcRoutingRule(src_networks, dst);
    if(val == kError) {
        num_errors = val;
    }
    return num_errors;
}

int czKatranLb:: addSrcRoutingRule(//--------------------------√
    const std::vector<folly::CIDRNetwork>& srcs,
    const std::string& dst)
{
    if(!features_.srcRouting && !config_.testing) {
        LOG(ERROR) << "Source based routing is not enabled for xdp forwarding plane";
        return kError;
    }

    if(validateAddress(dst) == AddressType::INVALID) {
        LOG(ERROR) << fmt::format(
            "Invalid dst address: {} for src routing rule",
        dst);
        return kError;
    }

    for(auto& src : srcs) {
        if(lpmSrcMapping_.size() + 1 > config_.maxLpmSrcSize) {
            LOG(ERROR) << "Source based routing space exhausted";
            return kError;
        }
        auto rnum = increaseRefCountForReal(folly::IPAddress(dst));
        if(rnum == config_.maxReals) {
            LOG(ERROR) << "Source based routing space exhausted";
            return kError;
        }
        lpmSrcMapping_[src] = rnum;
        if(!config_.testing) {
            modifyLpmSrcRule(ModifyAction::ADD, src, rnum);
        }
    }
    return 0;
}

bool czKatranLb:: modifyLpmSrcRule(//--------------------------√
    ModifyAction action,
    const folly::CIDRNetwork& src,
    uint32_t rnum)
{
    return modifyLpmMap("lpm_src", action, src, &rnum);
}

bool czKatranLb:: modifyLpmMap(//--------------------------√
    const std::string& lpmMapNamePrefix,
    ModifyAction action,
    const folly::CIDRNetwork& addr,
    void* value)
{
    auto lpm_addr = IpHelpers::parseAddrToBe(addr.first.str());
    if(addr.first.isV4()) {
        //ipv4
        struct v4_lpm_key key = {
            .prefixlen = addr.second,
            .addr = lpm_addr.daddr
        };
        std::string mapName = lpmMapNamePrefix + "_v4"; //bpf-map name
        if(action == ModifyAction::ADD) {
            //add
            auto res = bpfAdapter_->bpfUpdateMap(
                bpfAdapter_->getMapFdByName(mapName),
                &key,
                value
            );
            if(res != 0) {
                LOG(INFO) << " can not add new element into " << mapName << ", error is " << folly::errnoStr(errno);
                lbStats_.bpfFailedCalls++;
                return false;
            }
        } else {
            auto res = bpfAdapter_->bpfMapDeleteElement(
                bpfAdapter_->getMapFdByName(mapName),
                &key
            );
            if(res != 0) {
                LOG(INFO) << " can not delete element from " << mapName << ", error is " << folly::errnoStr(errno);
                lbStats_.bpfFailedCalls++;
                return false;
            }
        }
    } else {
        struct v6_lpm_key key = {
            .prefixlen = addr.second
        };
        std::string mapName = lpmMapNamePrefix + "_v6";
        std::memcpy(&key.addr, &lpm_addr.v6daddr, 16);
        if(action == ModifyAction::ADD) {
            //add
            auto res = bpfAdapter_->bpfUpdateMap(
                bpfAdapter_->getMapFdByName(mapName),
                &key,
                value
            );
            if(res != 0) {
                LOG(INFO) << " can not add new element into " << mapName << ", error is " << folly::errnoStr(errno);
                lbStats_.bpfFailedCalls++;
                return false;
            }
        } else {
            auto res = bpfAdapter_->bpfMapDeleteElement(
                bpfAdapter_->getMapFdByName(mapName),
                &key
            );
            if(res != 0) {
                LOG(INFO) << " can not delete element from " << mapName << ", error is " << folly::errnoStr(errno);
                lbStats_.bpfFailedCalls++;
                return false;
            }
        }
    }
    return true;
}

bool czKatranLb:: delSrcRoutingRule(const std::vector<std::string>& srcs)//--------------------------√
{
    if(!features_.srcRouting && !config_.testing) {
        LOG(ERROR) << "Source based routing is not enabled for xdp forwarding plane";
        return kError;
    }

    std::vector<folly::CIDRNetwork> src_networks;
    for (auto& src : srcs) {
        auto network = folly::IPAddress::tryCreateNetwork(src);
        if(network.hasValue()) {
            src_networks.push_back(network.value()); //提取value
        }
    }
    return delSrcRoutingRule(src_networks);
}

bool czKatranLb:: delSrcRoutingRule(const std::vector<folly::CIDRNetwork>& srcs)//--------------------------√
{
    if(!features_.srcRouting && !config_.testing) {
        LOG(ERROR) << "Source based routing is not enabled for xdp forwarding plane";
        return kError;
    }

    for(auto& src : srcs) {
        auto src_iter = lpmSrcMapping_.find(src);
        if(src_iter == lpmSrcMapping_.end()) {
            LOG(ERROR) << "can not find src: " << src.first.str() << " in lpmSrcMapping";
            continue;
        }

        auto dst = numToReals_[src_iter->second];
        decreaseRefCountForReal(dst);
        if(!config_.testing) {
            modifyLpmSrcRule(ModifyAction::DEL, src, src_iter->second);
        }
        lpmSrcMapping_.erase(src_iter);
    }
    return true;
}

bool czKatranLb:: addInlineDecapDst(const std::string& dst)//--------------------------√
{
    if(!features_.inlineDecap && !config_.testing) {
        LOG(ERROR) << "Inline decap is not enabled for xdp forwarding plane";
        return false;
    }
    if(validateAddress(dst) == AddressType::INVALID) {
        LOG(ERROR) << fmt::format(
            "Invalid dst address: {} for inline decap",
        dst);
        return false;
    }

    folly::IPAddress daddr (dst);
    if(decapDsts_.find(daddr) != decapDsts_.end()) {
        LOG(ERROR) << fmt::format(
            "dst address: {} for inline decap already exists",
        dst);
        return false;
    }
    if(decapDsts_.size() + 1 > config_.maxDecapDst) {
        LOG(ERROR) << "decapDst space exhausted";
        return false;
    }

    VLOG(2) << "adding dst: " << dst << " to decapDsts_";
    decapDsts_.insert(daddr);
    if(!config_.testing) {
        modifyDecapDst(ModifyAction::ADD, daddr);
    }
    return true;
}

bool czKatranLb:: modifyDecapDst(//--------------------------√
    ModifyAction action,
    const folly::IPAddress& dst,
    uint32_t flags)
{
    auto addr = IpHelpers::parseAddrToBe(dst);

    if(action == ModifyAction::ADD) {
        auto res = bpfAdapter_->bpfUpdateMap(
            bpfAdapter_->getMapFdByName(czKatranLbMaps::decap_dst),
            &addr,
            &flags
        );
        if(res != 0) {
            LOG(ERROR) << " can not add new element into decap_dst, error is " << folly::errnoStr(errno);
            lbStats_.bpfFailedCalls++;
            return false;
        }
    } else {
        auto res = bpfAdapter_->bpfMapDeleteElement(
            bpfAdapter_->getMapFdByName(czKatranLbMaps::decap_dst),
            &addr
        );
        if(res != 0) {
            LOG(ERROR) << " can not delete element from decap_dst, error is " << folly::errnoStr(errno);
            lbStats_.bpfFailedCalls++;
            return false;
        }
    }  
    return true;
}

bool czKatranLb:: modifyReal(//--------------------------√
    const std::string& real, 
    uint8_t flags, 
    bool set)

{
    if(validateAddress(real) == AddressType::INVALID) {
        LOG(ERROR) << fmt::format("Invalid real address: {}", real);
        return false;
    }

    VLOG(4) << fmt::format(
        "modifying real: {}",
        real
    );
    folly::IPAddress raddr(real);
    auto real_iter = reals_.find(raddr);
    if(real_iter == reals_.end()) {
        LOG(INFO) << fmt::format(
            "can not find real: {} in reals_",
            real
        );
        return false;
    }

    flags &= ~V6DADDR;
    if(set) {
        real_iter->second.flags |= flags;
    } else {
        real_iter->second.flags &= ~flags;
    }
    reals_[raddr].flags = real_iter->second.flags;
    if(!config_.testing) {
        updateRealsMap(raddr, real_iter->second.num, real_iter->second.flags);
    }
    return true;
}

const std::string czKatranLb:: getRealForFlow(const czkatranFlow& flow)
{
    //auot pckt = crea
}


}