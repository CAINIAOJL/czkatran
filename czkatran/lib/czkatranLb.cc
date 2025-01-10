#include "czkatranLb.h"

#include <vector>
#include <cstdint>
#include <stdexcept> //异常处理头文件


#include <fmt/core.h>
#include <folly/String.h>
#include <glog/logging.h>
#include "czkatranLbStructs.h"

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

lb_stats czKatranLb:: getLbStats(uint32_t position, const std::string& map) {
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

}