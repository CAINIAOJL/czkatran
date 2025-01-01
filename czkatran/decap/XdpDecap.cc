#include <glog/logging.h>
#include <cstdint>

#include "czkatran/decap/XdpDecap.h"

namespace czkatran {

//注意这个bpfAdapter_私有变量
XdpDecap:: XdpDecap(const XdpDecapConfig& config): config_(config), bpfAdapter_(true, true) {
    //判断是否为独立模式
    if(!config_.mapPath.empty()) {
        isStandalone = false; 
    } else {
        auto ifindex = bpfAdapter_.getInterfaceIndexByName(config.interface);
        if(!ifindex) {
            LOG(FATAL) << "can not resolve to infindex interface: "
                       << config_.interface;
            return;
        }
    }
}

XdpDecap:: ~XdpDecap() {
    if(isAttached_) {
        //defaultNoExit == false
        if(!config_.defaultNoExit) {
            LOG(INFO) << "No need to datach XDP program to interface : " 
                      << config_.interface
                      << " as it is already detached";
            return;
        }
        //defaultNoExit == true
        if(!isStandalone) {
            auto res = bpfAdapter_.detachXdpProgram(config_.interface);
            if(res) {
                LOG(ERROR) << "failed to detach this XDPDecap progtam";
            }
        } else {
            //bpf程序可以pin到一个路径上，实现持久化操作
            auto prog_fd = bpfAdapter_.getPinnedBpfObject(config_.mapPath);
            if(prog_fd >= 0) {
                auto res = bpfAdapter_.bpfMapDeleteElement(prog_fd, &config_.progPos);
                if(res) {
                    LOG(ERROR) << "failed to delete element from pinned map!";
                }
            }
        }
    }
}

void XdpDecap:: loadXdpDecap() {
    if(isLoaded_) {
        LOG(ERROR) << "XdpDecap program has already been loaded!";
        return;
    }
    auto res = bpfAdapter_.loadBpfProg(config_.progPath); //缺省参数 type, use_name 
    if(res) {
        LOG(FATAL) << "failed to load XDP program from " 
                   << config_.progPath;
        return;
    }

    if(bpfAdapter_.getProgFdByName("xdpdecap") < 0) {
        LOG(FATAL) << "failed to find XDP program in kernel form " 
                   << config_.progPath;
        return;
    }

    if(bpfAdapter_.getMapFdByName("decap_counters") < 0) {
        LOG(FATAL) << "failed to find decap_counters map in kernel from"
                   << config_.progPath;
        return;
    }
    isLoaded_ = true;
}

void XdpDecap:: attachXdpDecap() {
    if(!isLoaded_ || isAttached_) {
        LOG(FATAL) << "XdpDecap program has not been loaded or is already attached!";
        return;
    }

    auto prog_fd = bpfAdapter_.getProgFdByName("xdpdecap");
    if(isStandalone) {
        if(bpfAdapter_.attachXdpProgram(prog_fd, config_.interface)) {
            LOG(FATAL) << "failed to attach XDP program to interface "
                       << config_.interface;
            return;
        }
    } else {
        auto map_fd = bpfAdapter_.getPinnedBpfObject(config_.mapPath);
        if(map_fd < 0) {
            LOG(FATAL) << "failed to get pinned map from " 
                       << config_.mapPath;
            return;
        }
        if(bpfAdapter_.bpfUpdateMap(map_fd, &config_.progPos, &prog_fd)) {
            LOG(FATAL) << "failed to update map element with XDP program, bpf map path: " 
                       << config_.mapPath
                       << ", with the element on position: " 
                       << config_.progPos;
            return;
        }
    }
    isAttached_ = true;
}

decap_stats XdpDecap:: getXdpDecapStats() {
    struct decap_stats stats = {};
    uint32_t key = 0;
    if(!isLoaded_) {
        LOG(ERROR) << "XdpDecap program has not been loaded!";
        return stats;
    }

    //考虑到perf_event的多cpu问题
    auto nr_cpus = bpfAdapter_.getPossibleCpus();
    if(nr_cpus < 0) {
        LOG(ERROR) << "failed to get number of possible cpus!";
        return stats;
    }

    struct decap_stats percpu_stats[nr_cpus];
    if(bpfAdapter_.bpfMapLookUpElement(bpfAdapter_.getMapFdByName("decap_counters"), &key, &percpu_stats)) {
        for (auto &stat: percpu_stats) {
            stats.decap_v4 += stat.decap_v4;
            stats.decap_v6 += stat.decap_v6;
            stats.total += stat.total;
            stats.tpr_misrouted += stat.tpr_misrouted;
            stats.tpr_total += stat.tpr_total;
        }
    } else {
        LOG(ERROR) << "failed to look up element from decap_counters map";
    }
    return stats;
}

int XdpDecap:: getXdpDecapFd() {
    return bpfAdapter_.getProgFdByName("xdpdecap");
}

void XdpDecap:: setServerId(int id) {
    auto map_fd = bpfAdapter_.getMapFdByName("tpr_server_id");
    uint32_t key = 0;
    uint32_t value = id;
    if(bpfAdapter_.bpfUpdateMap(map_fd, &key, &value)) {
        LOG(FATAL) << "failed to update map element with XDP program, bpf map path: " 
                    << config_.mapPath
                    << ", with the element on position: " 
                    << config_.progPos;
        return;
    }
}


}