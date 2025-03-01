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
#include "Balancer_structs.h"
#include "IpHelpers.h"

namespace czkatran {
namespace {
    constexpr int kMaxInvalidServerIds = 10000;
}



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
                       globalLruMapsFd_(kMaxForwardingCores)
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
  // Example 1:讨论去除首位为零的情况
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


    for(uint32_t i = 1; i < config_.maxReals; i++) {
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
            LOG(INFO) << fmt::format("quicMapping_ delete iter: id {}, IpAddress {}", real_iter->first, real_iter->second.str());
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
            LOG(INFO) << fmt::format("quicMapping_ added iter: id {}, IpAddress {}", real.id, raddr.str());
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

bool czKatranLb:: addVip(const VipKey& vip, const uint32_t flags)//--------------------------√
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

const std::string czKatranLb:: getRealForFlow(const czkatranFlow& flow)//--------------------------√
{
    //auot pckt = crea
    std::string result;
    if(!initSimulator()) {
        return result;
    }
    result = simulator_->getRealForFlow(flow);
    return result;
}
//------------------------------------2025-2-15-------------------------------


//------------------------------------2025-2-16-------------------------------
bool czKatranLb:: initSimulator()//--------------------------√
{
    if(!progsLoaded_) {
        LOG(ERROR) << "bpf programs are not loaded";
        return false;
    }
    simulator_ = std::make_unique<czkatranSimulator>(getczKatranProgFd());
    return true;
}

void czKatranLb:: initFlowDebugPrototypeMap()//--------------------------√
{
    int flow_proto_fd, res;
    if(forwardingCores_.size() != 0) {
        flow_proto_fd = flowDebugMapsFd_[forwardingCores_[kFirstElem]];
    } else {
        VLOG(3) << "create generic flow debug lru";
        flow_proto_fd = bpfAdapter_->createNamedBpfMap(
            czKatranLbMaps::flow_debug_lru,
            kBpfMapTypeLruHash,
            sizeof(struct flow_key),
            sizeof(struct flow_debug_info),
            czkatran::kFallbackLruSize,
            kMapNoFlags,
            kNoNuma
        );
    }
    if(flow_proto_fd < 0) {
        throw std::runtime_error(fmt::format(
            "can not create flow_Debug_lru prototype, error is {}",
            folly::errnoStr(errno)
        ));
    }
    res = bpfAdapter_->setInnerMapProtoType(
        czKatranLbMaps::flow_debug_maps, flow_proto_fd
    );
    if(res < 0) {
        throw std::runtime_error(fmt::format(
            "can not set inner map prototype map_fd for flow_Debug_lru map, error is {}",
            folly::errnoStr(errno)
        ));
    }
    VLOG(3) << "created flow_Debug_lru prototype";
}


void czKatranLb:: initGlobalLruPrototypeMap()//--------------------------√
{
    VLOG(0) << __func__;
    int prog_fd;
    if(forwardingCores_.size() != 0) {
        prog_fd = globalLruMapsFd_[forwardingCores_[kFirstElem]];
    } else {
        VLOG(3) << "create generic global_lru";
        prog_fd = bpfAdapter_->createNamedBpfMap(
            czKatranLbMaps::global_lru,
            kBpfMapTypeLruHash,
            sizeof(struct flow_key),
            sizeof(uint32_t),
            czkatran::kFallbackLruSize,
            kMapNoFlags,
            kNoNuma
        );
    }
    if(prog_fd < 0) {
        throw std::runtime_error(fmt::format(
            "can not create global_lru prototype, error is {}",
            folly::errnoStr(errno)
        ));
    }
    int res = bpfAdapter_->setInnerMapProtoType(
        czKatranLbMaps::global_lru_maps, prog_fd
    );
    if(res < 0) {
        throw std::runtime_error(fmt::format(
            "can not set inner map proto type for global_lru_map, error is {}",
            folly::errnoStr(errno)
        ));
    }
    VLOG(1) << "created global_lru prototype";
}

void czKatranLb:: initialSanityChecking(//--------------------------√
    bool flowDebug, 
    bool globalLru)
{
    int res;
    std::vector<std::string> maps;

    maps.push_back(czKatranLbMaps::ctl_array);
    maps.push_back(czKatranLbMaps::vip_map);
    maps.push_back(czKatranLbMaps::ch_rings);
    maps.push_back(czKatranLbMaps::reals);
    maps.push_back(czKatranLbMaps::stats);
    maps.push_back(czKatranLbMaps::lru_mapping);
    maps.push_back(czKatranLbMaps::server_id_map);
    maps.push_back(czKatranLbMaps::lru_miss_stats);
    maps.push_back(czKatranLbMaps::vip_miss_stats);

    if(flowDebug) {
        maps.push_back(czKatranLbMaps::flow_debug_maps);
    }
    if(globalLru) {
        maps.push_back(czKatranLbMaps::global_lru_maps);
    }

    res = getczKatranProgFd();
    if(res < 0) {
        throw std::invalid_argument(fmt::format(
            "can not get katran prog fd, error is {}",
            folly::errnoStr(errno)
        ));
    }

    if(config_.enableHc) {
        res = getHealthcheckerProgFd();
        if(res < 0) {
            throw std::invalid_argument(fmt::format(
                "can not get healthchecker prog fd, error is {}",
                folly::errnoStr(errno)
            ));
        }
        maps.push_back(czKatranLbMaps::hc_ctrl_map);
        maps.push_back(czKatranLbMaps::hc_reals_map);
        maps.push_back(czKatranLbMaps::hc_stats_map);
    }

    //检查xdp程序中的map是否存在
    for(auto& map : maps) {
        res = bpfAdapter_->getMapFdByName(map);
        if(res < 0) {
            VLOG(4) << fmt::format(
                "this map: {} is not in xdp prog",
                map
            );
            throw std::invalid_argument(fmt::format(
                "map not found in xdp prog, error is {}",
                folly::errnoStr(errno)
            ));
        }
    }
}

void czKatranLb:: featureDiscovering()//--------------------------√
{
    std::string xdp = kBalancerProgName.toString();
    std::string hctc = kHealthcheckerProgName.toString();
    if(bpfAdapter_->isMapInProg(
        xdp,
        czKatranLbMaps::lpm_src_v4
    )){
        VLOG(2) << "source bassed routing is supported";
        features_.srcRouting = true;
    } else {
        features_.srcRouting = false;
    }

    if(bpfAdapter_->isMapInProg(
        xdp,
        czKatranLbMaps::decap_dst
    )) {
        VLOG(2) << "inline decap is supported";
        features_.inlineDecap = true;
    } else {
        features_.inlineDecap = false;
    }
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    if(bpfAdapter_->isMapInProg(
        xdp,
        czKatranLbMaps::event_pipe
    )) {
        VLOG(2) << "event pipe is supported";
        features_.introspection = true;
    } else {
        features_.introspection = false;
    }

    if(bpfAdapter_->isMapInProg(
        xdp, 
        czKatranLbMaps::pckt_srcs
    )) {
        VLOG(2) << "GUE encapsulation is supported";
        features_.gueEncap = true;
    } else {
        features_.gueEncap = false;
    }

    if(bpfAdapter_->isMapInProg(
        hctc,
        czKatranLbMaps::hc_pckt_srcs_map
    )) {
        VLOG(2) << "direct healthchecking is supported";
        features_.directHealthchecking = true;
    } else {
        features_.directHealthchecking = false;
    }
    if(bpfAdapter_->isMapInProg(
        xdp,
        czKatranLbMaps::flow_debug_maps
    )) {
        VLOG(2) << "flow debug is supported";
        features_.flowDebug = true;
    } else {
        features_.flowDebug = false;
    }
}


void czKatranLb:: setupGueEnvironment()//--------------------------√
{
    if(config_.katranSrcV4.empty() && config_.katranSrcV6.empty()) {
        throw std::runtime_error(fmt::format(
            "can not setup GUE environment, srcV4 and srcV6 are empty"
        ));
    }

    if(!config_.katranSrcV4.empty()) {
        //转换成网络序
        auto srcV4 = 
            folly::IPAddress(config_.katranSrcV4);
        auto srcV4Be = IpHelpers::parseAddrToBe(srcV4);
        uint32_t key = kSrcV4Pos;
        auto res = bpfAdapter_->bpfUpdateMap(
            bpfAdapter_->getMapFdByName(czKatranLbMaps::pckt_srcs),
            &key,
            &srcV4Be
        );
        if(res < 0) {
            throw std::runtime_error(fmt::format(
                "can not update srcV4 in pckt_srcs map, error is {}",
                folly::errnoStr(errno)
            ));
        } else {
            LOG(INFO) << fmt::format(
                "updated srcV4: {} in pckt_srcs map",
                config_.katranSrcV4
            );
        }
    } else {
        LOG(ERROR) << "empty IPV4 address for GUE as source address";
    }

    if(!config_.katranSrcV6.empty()) {
        //转换成网络序
        auto srcV6 = 
            folly::IPAddress(config_.katranSrcV6);
        auto srcV6Be = IpHelpers::parseAddrToBe(srcV6);
        uint32_t key = kSrcV6Pos;
        auto res = bpfAdapter_->bpfUpdateMap(
            bpfAdapter_->getMapFdByName(czKatranLbMaps::pckt_srcs),
            &key,
            &srcV6Be
        );
        if(res < 0) {
            throw std::runtime_error(fmt::format(
                "can not update srcV6 in pckt_srcs map, error is {}",
                folly::errnoStr(errno)
            ));
        } else {
            LOG(INFO) << fmt::format(
                "updated srcV6: {} in pckt_srcs map",
                config_.katranSrcV6
            );
        }
    } else {
        LOG(ERROR) << "empty IPV6 address for GUE as source address";
    }

    LOG(INFO) << "czkatran GUE evrionment is ready!";
}

void czKatranLb:: enableRecirculation()//--------------------------√
{
    uint32_t key = kRecirculationIndex;
    //int balancerProgFd = bpfAdapter_->getProgFdByName(
        //kBalancerProgName.toString()
    //);
    int balancerProgfd = getczKatranProgFd();
    auto res = bpfAdapter_->bpfUpdateMap(
        bpfAdapter_->getMapFdByName("subprograms"),
        &key,
        &balancerProgfd
    );
    if(res < 0) {
        throw std::runtime_error(fmt::format(
            "can not update recirculation in subprograms map, error is {}",
            folly::errnoStr(errno)
        ));
    }
}

void czKatranLb:: setupHcEnvironment()//--------------------------√
{
    auto map_fd = bpfAdapter_->getMapFdByName(czKatranLbMaps::hc_pckt_srcs_map);
    if(config_.katranSrcV4.empty() && config_.katranSrcV6.empty()) {
        throw std::runtime_error(fmt::format(
            "No source address provided for direct healthchecking"
        ));
    }
    if(!config_.katranSrcV4.empty()) {
        auto srcV4 = 
            IpHelpers::parseAddrToBe(folly::IPAddress(config_.katranSrcV4));
        uint32_t key = kSrcV4Pos;
        auto res = bpfAdapter_->bpfUpdateMap(
            map_fd,
            &key,
            &srcV4
        );
        if(res < 0) {
            throw std::runtime_error(fmt::format(
                "can not update srcV4: {} in hc_pckt_srcs_map, error is {}",
                config_.katranSrcV4,
                folly::errnoStr(errno)
            ));
        } else {
            LOG(INFO) << fmt::format(
                "Update srcV4: {} in hc_pckt_srcs_map for direct healthchecking",
                config_.katranSrcV4
            );
        }
    } else {
        LOG(ERROR) << "empty IPV4 address for direct healthchecking";
    }

    if(!config_.katranSrcV6.empty()) {
        auto srcV6 = 
            IpHelpers::parseAddrToBe(folly::IPAddress(config_.katranSrcV6));
        uint32_t key = kSrcV6Pos;
        auto res = bpfAdapter_->bpfUpdateMap(
            map_fd,
            &key,
            &srcV6
        );
        if(res < 0) {
            throw std::runtime_error(fmt::format(
                "can not update srcV6: {} in hc_pckt_srcs_map, error is {}",
                config_.katranSrcV6,
                folly::errnoStr(errno)
            ));
        } else {
            LOG(INFO) << fmt::format(
                "Update srcV6: {} in hc_pckt_srcs_map for direct healthchecking",
                config_.katranSrcV6
            );
        }
    } else {
        LOG(ERROR) << "empty IPV6 address for direct healthchecking";
    }

    std::array<struct hc_mac, 2> macs;
    if(config_.localMac.size() != 6) {
        throw std::invalid_argument(fmt::format(
            "src mac's size is not equal to 6 bytes, src mac is {} {} {} {} {} {}",
            config_.localMac[0],
            config_.localMac[1],
            config_.localMac[2],
            config_.localMac[3],
            config_.localMac[4],
            config_.localMac[5]
        ));
    }

    for(int i = 0; i < 6; i++) {
        macs[kHcSrcMacPos].mac[i] = config_.localMac[i];
        macs[kHcDstMacPos].mac[i] = config_.defaultMac[i];
    }

    //两个位置
    for(auto position : {kHcSrcMacPos, kHcDstMacPos}) {
        auto res = bpfAdapter_->bpfUpdateMap(
            bpfAdapter_->getMapFdByName(czKatranLbMaps::hc_pckt_macs),
            &position,
            &macs[position]
        );
        if(res < 0) {
            throw std::runtime_error(fmt::format(
                "can not update mac in hc_pckt_macs, error is {}",
                folly::errnoStr(errno)
            ));
        }
    }
}

void czKatranLb:: startIntrospectionRoutines()//--------------------------√
{
    auto monitor_config = config_.monitorConfig;
    monitor_config.nCpus = czkatran::BpfAdapter::getPossibleCpus();
    monitor_config.mapFd = bpfAdapter_->getMapFdByName(
        czKatranLbMaps::event_pipe
    );
    monitor_ = std::make_unique<czkatranMonitor> (monitor_config);
}

void czKatranLb:: attachFlowDebugLru(int core)//--------------------------√
{
    int map_fd, res, key;
    key = core;
    map_fd =flowDebugMapsFd_[core];
    if(map_fd < 0) {
        throw std::runtime_error(fmt::format(
            "can not attach flow_debug_map [core: {} map_fd(flow_debug_lru's): {}], map fd is invalid",
            key,
            map_fd
        ));
    }
    res = bpfAdapter_->bpfUpdateMap(
        bpfAdapter_->getMapFdByName(czKatranLbMaps::flow_debug_maps),
        &key,
        &map_fd
    );
    if(res < 0) {
        throw std::runtime_error(fmt::format(
            "can not update flow_debug_map, error is {}",
            folly::errnoStr(errno)
        ));
    }
    VLOG(3) << fmt::format(
        "set cpu core: {} to flow debug map map_fd {}",
        core,
        map_fd 
    );
}

void czKatranLb:: attachGlobalLru(int core)//--------------------------√
{
    VLOG(0) << __func__;
    int key = core;
    int map_fd = globalLruMapsFd_[core];
    if(map_fd < 0) {
        throw std::runtime_error(fmt::format(
            "can not attach global_lru_map [core: {} map_fd(global_lru's): {}], map fd is invalid",
            key,
            map_fd
        ));
    }
    auto res = bpfAdapter_->bpfUpdateMap(
        bpfAdapter_->getMapFdByName(czKatranLbMaps::global_lru_maps),
        &key,
        &map_fd
    );
    if(res < 0) {
        throw std::runtime_error(fmt::format(
            "can not update global_lru_map, error is {}",
            folly::errnoStr(errno)
        ));
    }
    VLOG(1) << fmt::format(
        "set cpu core: {} to global_lru_map map_fd {}",
        core,
        map_fd 
    );
}

void czKatranLb:: attachLrus(//--------------------------√
    bool flowDebug, 
    bool globalLru)
{
    if(!progsLoaded_) {
        throw std::runtime_error(
            "can not attach lrus, bpf progs are not loaded"
        );
    }

    int map_fd, res, key;
    //先更新主要的lru_mapping
    for(const auto& core : forwardingCores_) {
        key = core; //key 对听cpu核心
        map_fd = lruMapsFd_[core]; //每个核心对应的lru_hash的map-fd
        res = bpfAdapter_->bpfUpdateMap(
            bpfAdapter_->getMapFdByName(czKatranLbMaps::lru_mapping),
            &key, 
            &map_fd
        );
        if(res < 0) {
            throw std::runtime_error(fmt::format(
                "can not update lru_mapping map to forwarding core, error is {}",
                folly::errnoStr(errno)
            ));
        }
        if(flowDebug) {
            //选择更新flow_debug_map
            attachFlowDebugLru(core);
        }
        if(globalLru) {
            //选择更新global_lru_map
            attachGlobalLru(core);
        }
    }

    if(globalLru) {
        globalLruFallbackFd_ = 
            bpfAdapter_->getMapFdByName(czKatranLbMaps::fallback_glru);
    }
}

void czKatranLb:: loadBpfProgs()//--------------------------√
{
    int res;
    bool flowDebugInProg = false;
    bool globalLruInProg = false;
    //flowDebugInProg = bpfAdapter_->isMapInBpfObject(
        //config_.balancerProgPath,
        //czKatranLbMaps::flow_debug_maps
    //);
    globalLruInProg = bpfAdapter_->isMapInBpfObject(
        config_.balancerProgPath,
        czKatranLbMaps::global_lru_maps
    );
    //1.初始化lru，包含“lru_mapping, global_lru_map, flow_debug_map”，将对应的数组填充初始化
    initLrus(/*false*/flowDebugInProg, /*true*/globalLruInProg);

    if(flowDebugInProg) {
        //2.初始化flow_debug_map中的flow_debug_lru map, 将对应的数组填充初始化
        initFlowDebugPrototypeMap();
    }
    if(globalLruInProg) {
        //3.初始化global_lru_map中的global_lru map, 将对应的数组填充初始化
        initGlobalLruPrototypeMap();
    }
    //4.加载bpf程序
    res = bpfAdapter_->loadBpfProg(config_.balancerProgPath);
    if(res) {
        throw std::invalid_argument(fmt::format(
            "can not load balancer bpf prog, error is {}",
            folly::errnoStr(errno)
        ));
    }

    if(config_.enableHc) {
        //5.加载健康检查程序
        res = bpfAdapter_->loadBpfProg(config_.healthcheckingProgPath);
        if(res) {
            throw std::invalid_argument(fmt::format(
                "can not load healthchecking bpf prog, error is {}",
                folly::errnoStr(errno)
            ));
        }
    }
    //6.检测所有的bpf-map
    initialSanityChecking(flowDebugInProg, globalLruInProg);
    //7.探测特征值
    featureDiscovering();

    if(features_.gueEncap) {
        //8.设置GUE环境
        setupGueEnvironment();
    }

    if(features_.inlineDecap) {
        //9.设置Recirculation map
        enableRecirculation();
    }   

    //update ctl_array
    std::vector<uint32_t> balancer_ctl_key = {kMacAddrPos};

    for(auto& ctl_key : balancer_ctl_key) {
        res = bpfAdapter_->bpfUpdateMap(
            bpfAdapter_->getMapFdByName(czKatranLbMaps::ctl_array),
            &ctl_key,
            &ctlValues_[ctl_key]
        );

        if(res < 0) {
            throw std::invalid_argument(fmt::format(
                "can not update ctl_array, error is {}",
                folly::errnoStr(errno)
            ));
        }
    }

    if(config_.enableHc) {
        std::vector<uint32_t> hc_ctl_key = {kMainIntfPos};
        if(config_.tunnelBasedHCEncap) {
            hc_ctl_key.push_back(kIpv4TunPos);
            hc_ctl_key.push_back(kIpv6TunPos);
        }
        for(auto& hc_key : hc_ctl_key) {
            res = bpfAdapter_->bpfUpdateMap(
                bpfAdapter_->getMapFdByName(
                    czKatranLbMaps::hc_ctrl_map
                ),
                &hc_key,
                &ctlValues_[hc_key].ifindex
            );
            if(res < 0) {
                throw std::invalid_argument(fmt::format(
                    "can not update hc_ctrl_map, error is {}",
                    folly::errnoStr(errno)
                ));
            }
        }
        if(features_.directHealthchecking) {
            //10.设置健康检查环境
            setupHcEnvironment();
        }
    }
    progsLoaded_ = true; //加载xdp对象成功
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    if(features_.introspection) {
        //11.开启监控器
        startIntrospectionRoutines(); 
        introspectionStarted_ = true;
    }

    //12.在xdp程序中，通过我们之前在类对象中存储的向量值，更新lru_mapping，flow_debug_map中的flow_debug_lru map, global_lru_map中的global_lru map, 
    attachLrus(flowDebugInProg, globalLruInProg);

    vip_definition vip_def;
    memset(&vip_def, 0, sizeof(vip_definition));
    uint32_t key = 0;
    res = bpfAdapter_->bpfUpdateMap(
        bpfAdapter_->getMapFdByName(czKatranLbMaps::vip_miss_stats),
        &key,
        &vip_def
    );
    if(res) {
        LOG(ERROR) << fmt::format("can not update vip_miss_stats map, error is {}", folly::errnoStr(errno));
    }
}

int czKatranLb:: createLruMap(//--------------------------√
    int size,
    int flags,
    int numaNode,
    int cpu)
{
    return bpfAdapter_->createNamedBpfMap(
        czKatranLbMaps::czkatran_lru + std::to_string(cpu),
        kBpfMapTypeLruHash,
        sizeof(struct flow_key),
        sizeof(struct real_pos_lru),
        size,
        flags,
        numaNode
    );
}

void czKatranLb:: initFlowDebugMapForCore(//--------------------------√
    int core, 
    int size, 
    int flags, 
    int numaNode)
{
    int lru_fd;
    VLOG(3) << "create flow debug lru for core: " << core;
    lru_fd = bpfAdapter_->createNamedBpfMap(
        czKatranLbMaps::flow_debug_lru,
        kBpfMapTypeLruHash,
        sizeof(struct flow_key),
        sizeof(struct flow_debug_info),
        size,
        flags,
        numaNode
    );
    if(lru_fd < 0) {
        LOG(ERROR) << "can not create flow debug lru for core: " << core;
        throw std::runtime_error(fmt::format(
            "can not create flow debug lru map for core, error : {}",
            folly::errnoStr(errno)
        ));
    }
    VLOG(3) << "flow debug lru map for core: " << core << " created";
    flowDebugMapsFd_[core] = lru_fd;
}

void czKatranLb:: initGlobalLruMapForCore(//--------------------------√
    int core, 
    int size, 
    int flags, 
    int numaNode)
{
    VLOG(0) << __func__;
    int lru_fd;
    VLOG(3) << "create global lru for core: " << core;
    lru_fd = bpfAdapter_->createNamedBpfMap(
        czKatranLbMaps::global_lru,
        kBpfMapTypeLruHash,
        sizeof(struct flow_key),
        sizeof(uint32_t),
        size,
        flags,
        numaNode
    );
    if(lru_fd < 0) {
        LOG(ERROR) << "can not create global lru for core: " << core;
        throw std::runtime_error(fmt::format(
            "can not create global lru for core, error : {}",
            folly::errnoStr(errno)
        ));
    }
    VLOG(3) << "global lru for core: " << core << " created";
    globalLruMapsFd_[core] = lru_fd;
}


void czKatranLb:: initLrus(//--------------------------√
        bool flowDebug, 
        bool globalLru)
{
    bool forwarding_cores_specified {false};
    bool numa_mapping_specified {false};

    if(forwardingCores_.size() != 0) {
        if(numaNodes_.size() != 0) {
            if(numaNodes_.size() != forwardingCores_.size()) {
                throw std::runtime_error("numa nodes and forwarding cores are not equal");
            }
            numa_mapping_specified = true;
        }
        auto per_core_lru_size = config_.LruSize / forwardingCores_.size();
        VLOG(2) << "per core lru size: " << per_core_lru_size;
        for (int i = 0; i < forwardingCores_.size(); i++) {
            auto core = forwardingCores_[i];
            if((core > kMaxForwardingCores) || core < 0) {
                LOG(FATAL) << "got core# " << core 
                           << "whitch is not in [0, "
                           << kMaxForwardingCores << "]";
                throw std::runtime_error("unsuported number of forwarding cores");
            }
            int numa_node = kNoNuma;
            int lru_map_falgs = 0;
            if(numa_mapping_specified) {
                numa_node = numaNodes_[i];
                lru_map_falgs |= BPF_F_NUMA_NODE;
            }
            int lru_fd = 
                createLruMap(per_core_lru_size, lru_map_falgs, numa_node, core);
            if(lru_fd < 0) {
                LOG(FATAL) << "can not create lru map for core: " << core;
                throw std::runtime_error(fmt::format(
                    "can not create lru map for core, error : {}",
                    folly::errnoStr(errno)
                ));
            }
            lruMapsFd_[core] = lru_fd; //收集
            if(flowDebug) {
                initFlowDebugMapForCore(
                    core, 
                    per_core_lru_size, 
                    lru_map_falgs, 
                    numa_node
                );
            }
            if(globalLru) {
                initGlobalLruMapForCore(
                    core,
                    per_core_lru_size,
                    lru_map_falgs,
                    numa_node
                );
            }
        }
        forwarding_cores_specified = true;
    }

    int lru_map_fd;
    if(forwarding_cores_specified) {
        //只有一个元素
        //生产环境
        lru_map_fd = lruMapsFd_[forwardingCores_[kFirstElem]];
    } else {
        //测试流程走到这
        lru_map_fd = createLruMap();
        if(lru_map_fd < 0) {
            throw std::runtime_error(fmt::format(
                "can not create lru map, error : {}",
                folly::errnoStr(errno)
            ));
        }
    }
    int res = bpfAdapter_->setInnerMapProtoType(
        czKatranLbMaps::lru_mapping, lru_map_fd
    );

    if(res < 0) {
        throw std::runtime_error(fmt::format(
            "can not set inner map proto type, error : {}",
            folly::errnoStr(errno)
        ));
    }
}
//------------------------------------2025-2-16-------------------------------

//------------------------------------2025-2-17/9-------------------------------
czkatranBpfMapStats czKatranLb:: getBpfMapStats(const std::string& map)//--------------------------√
{
    czkatranBpfMapStats stats;
    auto res = bpfAdapter_->getBpfMapMaxSize(map);
    if(res < 0) {
        throw std::runtime_error(fmt::format(
            "can not get bpf map:{} max size, error : {}",
            map,
            folly::errnoStr(errno)
        ));
    } else {
        stats.maxEntries = res;
    }
    res = bpfAdapter_->getBpfMapUsedSize(map);
    if(res < 0) {
        throw std::runtime_error(fmt::format(
            "can not get bpf map:{} used size, error : {}",
            map,
            folly::errnoStr(errno)
        ));
    } else {
        stats.currentEntries = res;
    }
    return stats;
}

lb_stats czKatranLb:: getStatsForVip(const VipKey& vip)//--------------------------√
{
    auto vip_iter = vips_.find(vip);
    if(vip_iter == vips_.end()) {
        LOG(INFO) << fmt::format(
            "vip: address {} port {} proto {} not found",
            vip.address,
            vip.port,
            vip.proto
        );
    }
    auto num = vip_iter->second.getVipNum();
    return getLbStats(num);
}

lb_stats czKatranLb:: getLruStats()//--------------------------√
{
    return getLbStats(config_.maxVips + kLruCntrOffset);
}

lb_stats czKatranLb:: getLruMissStats()//--------------------------√
{
    return getLbStats(config_.maxVips + kLruMissOffset);
}

lb_stats czKatranLb:: getLruFallbackStats()//--------------------------√
{
    return getLbStats(config_.maxVips + kLruFallbackOffset);
}

lb_stats czKatranLb:: getIcmpTooBigStats()//--------------------------√
{
    return getLbStats(config_.maxVips + kIcmpTooBigOffset);
}

lb_stats czKatranLb:: getInlineDecapStats()//--------------------------√
{
    return getLbStats(config_.maxVips + kInlineDecapOffset);
}

lb_stats czKatranLb:: getSrcRoutingStats()//--------------------------√
{
    return getLbStats(config_.maxVips + kLpmSrcOffset);
}

lb_tpr_packets_stats czKatranLb:: getTcpServerIdRoutingStats()//--------------------------√
{
    unsigned int nr_cpus = BpfAdapter::getPossibleCpus();
    if(nr_cpus < 0) {
        LOG(ERROR) << fmt::format(
            "can not get number of cpus, error : {}",
            folly::errnoStr(errno)
        );
    }
    lb_tpr_packets_stats stats[nr_cpus];
    lb_tpr_packets_stats sum = {};
    if(!config_.testing) {
        int position = 0;
        auto res = bpfAdapter_->bpfMapLookUpElement(
            bpfAdapter_->getMapFdByName("tpr_stats_map"),
            &position,
            stats
        );
        if(!res) {
            for(auto& s : stats) {
                sum.ch_routed += s.ch_routed;
                sum.dst_mismatch_in_lru += s.dst_mismatch_in_lru;
                sum.sid_routed += s.sid_routed;
                sum.tcp_syn += s.tcp_syn;
            }
        } else {
            LOG(ERROR) << fmt::format(
                "can not get tpr stats, error : {}",
                folly::errnoStr(errno)
            );
            lbStats_.bpfFailedCalls++;
        }
    }
    return sum;
}

lb_quic_packets_stats czKatranLb:: getLbQuicPacketsStats()//--------------------------√
{
    unsigned int nr_cpus = BpfAdapter::getPossibleCpus();
    if(nr_cpus < 0) {
        LOG(ERROR) << fmt::format(
            "can not get number of cpus, error : {}",
            folly::errnoStr(errno)
        );
    }
    lb_quic_packets_stats stats[nr_cpus];
    lb_quic_packets_stats sum = {};

    if(!config_.testing) {
        int position = 0;
        auto res = bpfAdapter_->bpfMapLookUpElement(
            bpfAdapter_->getMapFdByName("quic_stats_map"),
            &position,
            stats
        );
        if(!res) {
            for(auto s : stats) {
                sum.ch_routed += s.ch_routed;
                sum.cid_initial += s.cid_initial;
                sum.cid_invalid_server_id += s.cid_invalid_server_id;
                if(s.cid_invalid_server_id_sample && 
                    (invalidServerIds_.find(s.cid_invalid_server_id_sample) == invalidServerIds_.end()) &&
                    invalidServerIds_.size() < kMaxInvalidServerIds)
                {
                    LOG(ERROR) << fmt::format(
                        "Invalid server id : {}, in quic packet",
                        s.cid_invalid_server_id_sample
                    );
                    invalidServerIds_.insert(s.cid_invalid_server_id_sample);
                    if(invalidServerIds_.size() == kMaxInvalidServerIds) {
                        LOG(ERROR) << fmt::format(
                            "Too many invalid server ids, drop the rest"
                        );
                    }
                }
                sum.cid_routed += s.cid_routed;
                sum.cid_unknown_real_dropped += s.cid_unknown_real_dropped;
                sum.cid_v0 += s.cid_v0;
                sum.cid_v1 += s.cid_v1;
                sum.cid_v2 += s.cid_v2;
                sum.cid_v3 += s.cid_v3;
                sum.dst_match_in_lru += s.dst_match_in_lru;
                sum.dst_mismatch_in_lru += s.dst_mismatch_in_lru;
                sum.dst_not_found_in_lru += s.dst_not_found_in_lru;
            }
        } else {
            LOG(ERROR) << fmt::format(
                "can not get quic stats, error : {}",
                folly::errnoStr(errno)
            );
            lbStats_.bpfFailedCalls++;
        }
    }
    return sum;
}

int64_t czKatranLb:: getIndexForReal(const std::string& real)//--------------------------√
{
    if(validateAddress(real) != AddressType::INVALID) {
        folly::IPAddress raddr(raddr);
        auto real_iter = reals_.find(raddr);
        if(real_iter != reals_.end()) {
            return real_iter->second.num; //后端服务器ip对应的hash节点值
        }
    }
    return kError;
}

lb_stats czKatranLb:: getRealStats(uint32_t index)//--------------------------√
{
    return getLbStats(index, "reals_stats");
}

bool czKatranLb:: stopKatranMonitor()//--------------------------√
{
    if(!monitor_) {
        return false;
    }
    if(!changeKatranMonitorForwardingState(czkatranMonitorState::DISABLED)) {
        return false;
    }
    monitor_->stopMonitor();
    return true;
}

std::unique_ptr<folly::IOBuf> czKatranLb:: getczKatranMonitorEventBuffer(//--------------------------√
    monitoring::EventId event)
{
    if(!monitor_) {
        return nullptr;
    }
    return monitor_->getEventBuffer(event);
}

czkatranMonitorStats czKatranLb:: getKatranMonitorStats()//--------------------------√
{
    struct czkatranMonitorStats stats;
    if(!monitor_) {
        return stats;
    }
    auto writer_stats = monitor_->getPcapWriterStats();
    stats.amount = writer_stats.amount;
    stats.limit = writer_stats.limit;
    stats.bufferFull = writer_stats.bufferfull;
    return stats;
}

lb_stable_rt_packet_stats czKatranLb:: getUdpStableRoutingStats()//--------------------------√
{
    unsigned int nr_cpus = BpfAdapter::getPossibleCpus();
    if(nr_cpus < 0) {
        LOG(ERROR) << fmt::format(
            "can not get number of cpus, error : {}",
            folly::errnoStr(errno)
        );
    }
    lb_stable_rt_packet_stats stats[nr_cpus];
    lb_stable_rt_packet_stats sum = {};
    
    if(!config_.testing) {
        int position = 0;
        auto res = bpfAdapter_->bpfMapLookUpElement(
            bpfAdapter_->getMapFdByName("stable_rt_stats"),
            &position,
            stats
        );
        if(!res) {
            sum.ch_routed += stats->ch_routed;
            sum.cid_invalid_server_id += stats->cid_invalid_server_id;
            sum.cid_routed += stats->cid_routed;
            sum.cid_unknown_real_dropped += stats->cid_unknown_real_dropped;
        } else {
            LOG(ERROR) << fmt::format(
                "can not get stable rt stats, error : {}",
                folly::errnoStr(errno)
            );
            lbStats_.bpfFailedCalls++;
        }
    }
    return sum;
}

bool czKatranLb:: hasFeature(czkatranFeatureEnum feature)//--------------------------√
{
    switch(feature) {
        case czkatranFeatureEnum::LocalDeliveryOptimization :
            return features_.localDeliveryOptimization;
        case czkatranFeatureEnum::SrcRouting :
            return features_.srcRouting;
        case czkatranFeatureEnum::InlineDecap :
            return features_.inlineDecap;
        case czkatranFeatureEnum::GueEncap :
            return features_.gueEncap;
        case czkatranFeatureEnum::Introspection :
            return features_.introspection;
        case czkatranFeatureEnum::FlowDebug :
            return features_.flowDebug;
        case czkatranFeatureEnum::DirectHealthchecking :
            return features_.directHealthchecking;
    }
    folly::assume_unreachable();
}

std::string czKatranLb:: toString(czkatranFeatureEnum feature) {//--------------------------√
    switch (feature)
    {
    case czkatranFeatureEnum::SrcRouting :
        return "SrcRouting";
        break;
    case czkatranFeatureEnum::InlineDecap :
        return "InlineDecap";
        break;
    case czkatranFeatureEnum::Introspection :
        return "Introspection";
        break;
    case czkatranFeatureEnum::GueEncap :
        return "GueEncap";
        break;
    case czkatranFeatureEnum::LocalDeliveryOptimization :
        return "LocalDeliveryOptimization";
        break;
    case czkatranFeatureEnum::FlowDebug :
        return "FlowDebug";
        break;
    case czkatranFeatureEnum::DirectHealthchecking : 
        return "DirectHealthchecking";
        break;
    default:
        return "UNKNOWN";
        break;
    }
    folly::assume_unreachable();
}

bool czKatranLb:: reloadBalancerProg(//--------------------------√
    const std::string& path,
    std::optional<czKatranConfig> config)
{
    auto res = bpfAdapter_->reloadBpfProg(path);
    if(res) {
        return false;
    }
    if(config.has_value()) {
        config_ = *config;
    }

    config_.balancerProgPath = path;
    bool flowDebugInProg = 
        bpfAdapter_->isMapInBpfObject(path, czKatranLbMaps::flow_debug_maps);

    bool globalLruInProg = 
        bpfAdapter_->isMapInBpfObject(path, czKatranLbMaps::global_lru_maps);

    initialSanityChecking(flowDebugInProg, globalLruInProg);
    featureDiscovering();

    if(features_.gueEncap) {
        setupGueEnvironment();
    }

    if(features_.inlineDecap) {
        enableRecirculation();
    }

    if(features_.introspection && !introspectionStarted_) {
        startIntrospectionRoutines();
        introspectionStarted_ = true;
    }
    progsReloaded_ = true;
    return true;
}

void czKatranLb:: attachBpfProgs()//--------------------------√
{
    if(!progsLoaded_) {
        throw std::invalid_argument("can not attach bpf progs before loading them");
    }
    int res;
    auto main_fd = bpfAdapter_->getProgFdByName(KBalancerProgName.toString());
    auto interface_index = ctlValues_[kMainIntfPos].ifindex;
    if(standalone_) {
        res = bpfAdapter_->modifyXdpProg(main_fd, interface_index, config_.xdpAttachFlags);
        if(res != 0) {
            throw std::invalid_argument(fmt::format(
                "can not attach main xdp prog, error : {}",
                folly::errnoStr(errno)
            ));
        }
    } else if(config_.useRootMap) {
        rootMapFd_ = bpfAdapter_->getPinnedBpfObject(config_.rootMapPath);
        if(rootMapFd_ < 0) {
            throw std::invalid_argument(fmt::format(
                "can not get root map fd, error : {}",
                folly::errnoStr(errno)
            ));
        }
        res = bpfAdapter_->bpfUpdateMap(rootMapFd_, &config_.rootMapPos, &main_fd);
        if(res) {
            throw std::invalid_argument(fmt::format(
                "can not update root map, error : {}",
                folly::errnoStr(errno)
            ));
        }
    }
    if(config_.enableHc && !progsReloaded_) {
        auto hc_fd = getHealthcheckerProgFd();
        res = bpfAdapter_->addTcBpfFilter(
            hc_fd,
            ctlValues_[kHcIntfPos].ifindex,
            "katran-healthchecker",
            config_.priority,
            TC_EGRESS
        );
        if(res != 0) {
            if(standalone_) {
                bpfAdapter_->detachXdpProgram(interface_index, config_.xdpAttachFlags);
            } else {
                bpfAdapter_->bpfMapDeleteElement(rootMapFd_, &config_.rootMapPos);
            }
            throw std::invalid_argument(fmt::format(
                "can not attach healthchecker prog, error : {}",
                folly::errnoStr(errno)
            ));
        }
    }
    progsAttached_ = true;
}

bool czKatranLb:: installFeature(//--------------------------√
    czkatranFeatureEnum feature,
    const std::string& prog_path)
{
    if(hasFeature(feature)) {
        LOG(INFO) << fmt::format(
            "feature {} already installed",
            toString(feature)
        );
        return true;
    }
    if(prog_path.empty()) {
        LOG(ERROR) << "can not install feature: empty prog path";
        return false;
    }
    auto original_balancer_prog = config_.balancerProgPath;
    if(!reloadBalancerProg(prog_path)) {
        LOG(ERROR) << fmt::format(
            "can not reload balancer prog with feature {}",
            toString(feature)
        );
        if(!reloadBalancerProg(original_balancer_prog)) {
            LOG(ERROR) << fmt::format(
                "can not reload original balancer prog after failed reload with feature {}",
                toString(feature)
            );
            return false;
        }
    }
    if(!config_.testing) {
        attachBpfProgs();
    }
    return hasFeature(feature);
}

bool czKatranLb:: removeFeature(//--------------------------√
    czkatranFeatureEnum feature,
    const std::string& prog_path)

{
    if(!hasFeature(feature)) {
        return true;
    }
    if(prog_path.empty()) {
        LOG(ERROR) << fmt::format(
            "can not remove feature {} with empty prog path",
            toString(feature)
        );
        return false;
    }
    auto original_balancer_prog = config_.balancerProgPath;
    if(!reloadBalancerProg(prog_path)) {
        LOG(ERROR) << fmt::format(
            "can not reload balancer prog with feature {}",
            toString(feature)
        );
        if(!reloadBalancerProg(original_balancer_prog)) {
            LOG(ERROR) << fmt::format(
                "can not reload original balancer prog after failed reload with feature {}",
                toString(feature)
            );
            return false;
        }
    }
    if(!config_.testing) {
        attachBpfProgs();
    }
    return !hasFeature(feature);
}

//------------------------------------2025-2-17/9-------------------------------

//------------------------------------2025-2-28-------------------------------
bool czKatranLb:: changeMac(const std::vector<uint8_t>& mac)
{
    uint32_t key = kMacAddrPos;

    VLOG(4) << "change mac address";

    if(mac.size() != kMacBytes) {
        return false;
    }
    for(int i = 0; i < kMacBytes; i++) {
        ctlValues_[key].mac[i] = mac[i];
    }
    if(!config_.testing) {
        auto res = bpfAdapter_->bpfUpdateMap(
            bpfAdapter_->getMapFdByName(czKatranLbMaps::ctl_array),
            &key,
            &ctlValues_[kMacAddrPos].mac
        );
        if(res != 0) {
            lbStats_.bpfFailedCalls++;
            VLOG(4) << "can not update ctl array for mac address";
            return false;
        }
        if(features_.directHealthchecking) {
            key = kHcDstMacPos;
            auto res = bpfAdapter_->bpfUpdateMap(
                bpfAdapter_->getMapFdByName(czKatranLbMaps::hc_pckt_macs),
                &key,
                &ctlValues_[kMacAddrPos].mac
            );
            if(res != 0) {
                lbStats_.bpfFailedCalls++;
                VLOG(4) << "can not update hc_pckt_macs for mac address";
                return false;
            }
        }
    }
    return true;
}

std::vector<uint8_t> czKatranLb:: getMac()
{
    return std::vector<uint8_t>(
        std::begin(ctlValues_[kMacAddrPos].mac),
        std::end(ctlValues_[kMacAddrPos].mac)
    );
}

std::map<int, uint32_t> czKatranLb:: getIndexOfNetworkInterfaces()
{
    std::map<int, uint32_t> result;
    result[kMainIntfPos] = ctlValues_[kMainIntfPos].ifindex;
    if(config_.enableHc) {
        result[kHcIntfPos] = ctlValues_[kHcIntfPos].ifindex;
        if(config_.tunnelBasedHCEncap) {
            result[kIpv4TunPos] = ctlValues_[kIpv4TunPos].ifindex;
            result[kIpv6TunPos] = ctlValues_[kIpv6TunPos].ifindex;
        }
    }
    return result;
}

bool czKatranLb:: delVip(const VipKey& vip)
{
    LOG(INFO) << fmt::format("deleting vip: {}: {}: {}", vip.address, vip.port, vip.proto);

    auto iter = vips_.find(vip);
    if(iter == vips_.end()) {
        LOG(INFO) << "vip: {}: {}: {} not found";
        return false;
    }

    auto vip_reals = iter->second.getReals();
    for(auto& real : vip_reals) {
        auto real_num = numToReals_[real];//找到对应的后端服务器IP地址
        decreaseRefCountForReal(real_num);
    }
    vipNums_.push_back(iter->second.getVipNum()); //放回到vipNums_中，准备下次使用
    if(!config_.testing) {
        updateVipMap(ModifyAction::DEL, vip);
    }
    vips_.erase(iter);
    return true;
}

std::vector<NewReal> czKatranLb:: getRealsForVip(const VipKey& vip)
{
    auto iter = vips_.find(vip);
    if(iter == vips_.end()) {
        throw std::invalid_argument(fmt::format(
            "vip: address {} port {} proto {} not found",
            vip.address,
            vip.port,
            vip.proto
        ));
    }
    std::vector<NewReal> result;
    NewReal r;
    auto reals = iter->second.getRealsAndWeights();
    for(auto& real : reals) {
        r.address = numToReals_[real.num].str();
        r.flags = reals_[numToReals_[real.num]].flags;
        r.weight = real.weight;
        result.push_back(r);
    }
    return result;
}

uint32_t czKatranLb:: getVipFlags(const VipKey& vip)
{
    auto iter = vips_.find(vip);
    if(iter == vips_.end()) {
        throw std::invalid_argument(fmt::format(
            "vip: address {} port {} proto {} not found",
            vip.address,
            vip.port,
            vip.proto
        ));
    }
    return iter->second.getVipFlags();
}

std::vector<VipKey> czKatranLb:: getAllVips()
{
    std::vector<VipKey> result;
    for(auto& vip: vips_) {
        result.push_back(vip.first);
    }
    return result;
}

const std::unordered_map<uint32_t, std::string> czKatranLb:: getNumToRealMap()
{
    std::unordered_map<uint32_t, std::string> result;
    for(auto& [num, real] : numToReals_) {
        result[num] = real.str(); 
    }
    return result;
}

std::vector<QuicReal> czKatranLb:: getQuicRealsMapping()
{
    std::vector<QuicReal> result;
    QuicReal r;
    for(auto& real: quciMapping_) {
        r.id = real.first;
        r.address = real.second.str();
        result.push_back(r);
    }
    return result;
}

std::unordered_map<uint32_t, std::string> czKatranLb:: getHealthcheckersDst()
{
    std::unordered_map<uint32_t, std::string> result;
    for(auto& [somark, addr]: hcReals_) {
        result[somark] = addr.str();
    }
    return result;
}

std::unordered_map<std::string, std::string> czKatranLb::getSrcRoutingRule()
{
    std::unordered_map<std::string, std::string> result;
    if(!features_.srcRouting && !config_.testing) {
        LOG(ERROR) << "src routing is not enabled";
        return result;
    }
    for(auto& [cidr, num] : lpmSrcMapping_) {
        auto real = numToReals_[num];
        //"10.0.0.0/24"
        //cidr.first = "10.0.0.0"
        //cidr.second = 24
        auto src_network = fmt::format("{}/{}", cidr.first.str(), cidr.second);
        result[src_network] = real.str();
    }
    return result;
}

std::unordered_map<folly::CIDRNetwork, std::string> czKatranLb:: getSrcRoutingRuleCidr()
{
    std::unordered_map<folly::CIDRNetwork, std::string> result;
    if(!features_.srcRouting && !config_.testing) {
        LOG(ERROR) << "src routing is not enabled";
        return result;
    }

    for(auto& [cidr, num] : lpmSrcMapping_) {
        auto real = numToReals_[num];
        result[cidr] = real.str();
    }
    return result;
}

bool czKatranLb:: clearAllSrcRoutingRules()
{
    if(!features_.srcRouting && !config_.testing) {
        LOG(ERROR) << "src routing is not enabled";
        return false;
    }
    for(auto& [cidr, num] : lpmSrcMapping_) {
        auto real = numToReals_.find(num);
        if(real != numToReals_.end()) {
            decreaseRefCountForReal(real->second);
            if(!config_.testing) {
                modifyLpmSrcRule(ModifyAction::DEL, cidr, num);
            }
        }
    }
    lpmSrcMapping_.clear();
    return true;
}

bool czKatranLb:: delInlineDecapDst(const std::string& dst)
{
    if(!features_.inlineDecap && !config_.testing) {
        LOG(ERROR) << "inline decap is not enabled";
        return false;
    }
    if(validateAddress(dst) == AddressType::INVALID) {
        LOG(ERROR) << fmt::format("invalid address: {}", dst);
        return false;
    }

    folly::IPAddress addr(dst);
    auto real = decapDsts_.find(addr);
    if(real == decapDsts_.end()) {
        LOG(ERROR) << "inline decap dst: {} not found" << dst;
        return false;
    }
    VLOG(2) << "deleting inline decap dst: " << dst;
    decapDsts_.erase(real);
    if(!config_.testing) {
        modifyDecapDst(ModifyAction::DEL, addr);
    }
    return true;
}

std::vector<std::string> czKatranLb:: getInlineDecapDst()
{   
    std::vector<std::string> result;
    if(!features_.inlineDecap && !config_.testing) {
        LOG(ERROR) << "inline decap is not enabled";
        return result;
    }
    for(auto& addr : decapDsts_) {
        result.push_back(addr.str());
    }
    return result;
}

bool czKatranLb:: delHealthcheckerDst(const uint32_t somark)
{
    if(!config_.enableHc) {
        return false;
    }

    VLOG(4) << fmt::format("deleting healthchecker dst: {}", somark);

    uint32_t key = somark;
    auto hc_iter = hcReals_.find(key);
    if(hc_iter == hcReals_.end()) {
        LOG(ERROR) << fmt::format("somark: {} not found", somark);
        return false;
    }
    if(!config_.testing) {
        auto res = bpfAdapter_->bpfMapDeleteElement(
            bpfAdapter_->getMapFdByName(czKatranLbMaps::hc_reals_map),
            &key
        );
        if(res != 0) {
            LOG(INFO) << "can not delete healthchecker dst";
            lbStats_.bpfFailedCalls++;
            return false;
        }
    }
    hcReals_.erase(hc_iter);
    return true;
}

}