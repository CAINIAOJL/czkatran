#include "BaseBpfAdapter.h"
#include "Netlink.h"


#include <folly/String.h>
#include <folly/ScopeGuard.h>
#include <glog/logging.h>
#include <libmnl/libmnl.h>





extern "C" {
#include <sys/resource.h>
#include <net/if.h>
#include <linux/netlink.h>         //与内核通信
#include <linux/rtnetlink.h>       //与路由表通信
#include <linux/if_link.h>         //与网络设备通信
#include <linux/tc_act/tc_gact.h>  //与tc交互
#include <linux/pkt_sched.h>       //与调度器交互
}

namespace {

}


namespace czkatran {

static bool flagPrintBpfDbg = false;

int libbpf_print(enum libbpf_print_level level,
                 const char *format,
                 va_list args) {
    if(level == LIBBPF_DEBUG && !VLOG_IS_ON(6) && !flagPrintBpfDbg) {
        return 0;
    }
    return vfprintf(stderr, format, args);
}

static int NetlinkRoudtrip(const NetlinkMessage& msg) {
    const struct nlmsghdr* hdr = reinterpret_cast<const struct nlmsghdr*>(msg.data());
    struct mnl_socket* nlsock = mnl_socket_open(NETLINK_ROUTE); //与内核路由通信
    if(!nlsock) {
        PLOG(ERROR) << "Failed to open netlink socket";
        return -1;
    }
    
    SCOPE_EXIT {
        mnl_socket_close(nlsock);
    };

    
    if(mnl_socket_bind(nlsock, 0, MNL_SOCKET_AUTOPID) < 0) {
        PLOG(ERROR) << "Failed to bind netlink socket";
        return -1;
    }

    unsigned int portid = mnl_socket_get_portid(nlsock);

    if(VLOG_IS_ON(4)) {
        mnl_nlmsg_fprintf(stderr, hdr, hdr->nlmsg_len, sizeof(struct ifinfomsg));
    }

    if(mnl_socket_sendto(nlsock, hdr, hdr->nlmsg_len) < 0) {
        PLOG(ERROR) << "Failed to send netlink message";
        return -1;
    }

    char recv_buf[MNL_SOCKET_BUFFER_SIZE];
    int ret = mnl_socket_recvfrom(nlsock, recv_buf, sizeof(recv_buf));
    while(ret > 0) {
        ret = mnl_cb_run(recv_buf, ret, msg.seq(), portid, nullptr, nullptr);
        if(ret <= MNL_CB_STOP) {
            break;
        }
        ret = mnl_socket_recvfrom(nlsock, recv_buf, sizeof(recv_buf));
    }
    if(ret < 0) {
        PLOG(ERROR) << "Failed to receive netlink message";
    }
    return ret;
}

int BaseBpfAdapter:: textXdpProg(
            const int prog_fd,
            const int repeat,
            void* data,
            uint32_t data_size,
            void* data_out,
            uint32_t* size_out,
            uint32_t* retval,
            uint32_t* duration,
            void* ctx_in,
            uint32_t ctx_in_size,
            void* ctx_out,
            uint32_t* ctx_out_size
        )
{
    LIBBPF_OPTS(
        bpf_test_run_opts,
        attr,
        .data_in = data,
        .data_out = data_out,
        .data_size_in = data_size,
        .ctx_in = ctx_in,
        .ctx_out = ctx_out,
        .ctx_size_in = ctx_in_size,
        .repeat = repeat
        );

    auto ret = bpf_prog_test_run_opts(prog_fd, &attr);

    if(size_out) {
        *size_out = attr.data_size_out;
    }

    if(retval) {
        *retval = attr.retval;
    }

    if(duration) {
        *duration = attr.duration;
    }

    if(ctx_out_size) {
        *ctx_out_size = attr.ctx_size_out;
    }

    return ret;
}



BaseBpfAdapter:: BaseBpfAdapter(bool set_limits, 
                                bool enableBatchOpsIfSupported) {
    libbpf_set_print(libbpf_print);
    if(set_limits) {
        //参考EBpf中的一些项目，这里提升系统的资源限制
        struct rlimit rlim = {};
        rlim.rlim_cur = RLIM_INFINITY;
        rlim.rlim_max = RLIM_INFINITY;
        if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
            LOG(ERROR) << "Failed to set rlimit for memlock";
            throw std::runtime_error("error while setting rlimit for locked memory");
        }
    }
}

BaseBpfAdapter::~BaseBpfAdapter() {

}

int BaseBpfAdapter:: modifyXdpProg(const int prog_fd,
                                   const unsigned int ifindex,
                                   const uint32_t flags) {

    unsigned int seq = static_cast<unsigned int>(std::time(nullptr));
    auto msg = NetlinkMessage::XDP(seq, prog_fd, ifindex, flags);
    return NetlinkRoudtrip(msg);
}





int BaseBpfAdapter:: getInterfaceIndexByName(const std::string& interface_name) {
    int ifindex = if_nametoindex(interface_name.c_str());
    if(!ifindex) {
        VLOG(1) << " can not get ifindex for interface: " << interface_name;
        return 0;
    }
    return ifindex;
}

int BaseBpfAdapter:: getInterfaceIndex(const std::string& interface_name) {
    auto ifindex = if_nametoindex(interface_name.c_str());
    if(!ifindex) {
        VLOG(1) << " can not get ifindex for interface: " << interface_name;
        return 0;
    }
    return ifindex;
}

int BaseBpfAdapter:: detachXdpProgram(const std::string& interface_name, uint32_t flags) {
    auto ifindex = if_nametoindex(interface_name.c_str());
    if(!ifindex) {
        VLOG(1) << " can not get ifindex for interface: " << interface_name;
        return 1;
    }
    return modifyXdpProg(-1, ifindex, flags);

}

int BaseBpfAdapter:: detachXdpProgram(const int ifindex, uint32_t flags) {
    return modifyXdpProg(-1, ifindex, flags);
}

int BaseBpfAdapter:: getPinnedBpfObject(const std::string& path) {
    return bpf_obj_get(path.c_str());
}

int BaseBpfAdapter:: bpfMapDeleteElement(int map_fd, void *key) {
    auto bpferror = bpf_map_delete_elem(map_fd, key);
    if(bpferror) {
        VLOG(4) << " bpf_map_delete_elem failed with error: " << folly::errnoStr(errno);
        return 1;
    }
    return bpferror; //!= 0
}

int BaseBpfAdapter:: attachXdpProgram(const int prog_fd, 
                                    const std::string& interface_name, 
                                    const uint32_t flags) {
    auto ifindex = if_nametoindex(interface_name.c_str());
    if(!ifindex) {
        VLOG(4) << " bpf_map_delete_elem failed with error: " << folly::errnoStr(errno);
        return 1;
    }
    return modifyXdpProg(prog_fd, ifindex, flags);
}

int BaseBpfAdapter:: bpfUpdateMap(int map_fd, void *key, void *value, uint64_t flags) {
    auto bpferror = bpf_map_update_elem(map_fd, key, value, (unsigned long long)flags);
    if(bpferror) {
        VLOG(4) << " bpf_map_update_elem failed with error: " << folly::errnoStr(errno);
    }
    return bpferror; //!= 0
}

int BaseBpfAdapter:: getPossibleCpus() {
    return libbpf_num_possible_cpus(); // returns the number of possible CPUs on the system
}

int BaseBpfAdapter:: bpfMapLookUpElement(int map_fd, void* key, void *value, unsigned long long flags) {
    auto bpferror = bpf_map_lookup_elem_flags(map_fd, key, value, flags);
    if(bpferror) {
        VLOG(4) << " bpf_map_lookup_elem failed with error: " << folly::errnoStr(errno);
    }
    return bpferror; // != 0
}

int BaseBpfAdapter:: deleteTcBpfFilter(
            const int prog_fd,
            const unsigned int ifindex,
            const std::string& bpf_name,
            const uint32_t priority,
            const int direction,
            const uint32_t handle
        )
{
    int cmd = RTM_DELTFILTER;
    unsigned int flags = 0;
    return modifyTcBpfFilter(cmd, flags, priority, prog_fd, ifindex, bpf_name, direction, handle);
}

int BaseBpfAdapter:: modifyTcBpfFilter(
            const int cmd,
            const unsigned int flags,
            const uint32_t priority,
            const int prog_fd,
            const unsigned int ifindex,
            const std::string& bpf_name,
            const int direction,
            const uint32_t handle
        )
{
    unsigned int seq = static_cast<unsigned int>(std::time(nullptr));
    auto msg = NetlinkMessage::TC(seq, cmd, flags, priority, prog_fd, ifindex, bpf_name, direction, handle);
    return NetlinkRoudtrip(msg);
}

//------------------------------------2025-2-14-------------------------------
int BaseBpfAdapter:: getBpfMapInfo(int fd, struct bpf_map_info* info)//--------------------------√
{
    uint32_t info_size = sizeof(struct bpf_map_info);
    memset(info, 0, info_size);
    return bpf_obj_get_info_by_fd(fd, info, &info_size);
}

int BaseBpfAdapter:: bpfUpdateMapBatch(//--------------------------√
    int map_fd, 
    void* keys, 
    void* values, 
    uint32_t count) 
{
    if(batchOpsEnabled_) {
        uint32_t numUpdated = count;
        DECLARE_LIBBPF_OPTS(
            bpf_map_batch_opts, opts, .elem_flags = 0, .flags = 0,
        );
        if(auto bpferror = 
            bpf_map_update_batch(map_fd, keys, values, &numUpdated, &opts)) {
                LOG(ERROR) << "Falied to perform batch update, errno = " << errno;
                return -1;
        }
        if(count != numUpdated) {
            LOG(ERROR) << "Failed to perform batch update, count = " << count << ", numUpdated = " << numUpdated;
            return -1;
        }
    } else {
        struct bpf_map_info mapInfo;
        auto err = getBpfMapInfo(map_fd, &mapInfo);

        if(err) {
            LOG(ERROR) << "Failed to get map info for map-fd " << map_fd 
            << " err is " << folly::errnoStr(errno);
            return -1;
        }

        for(uint32_t i = 0; i < count; i++) {
            auto res = bpfUpdateMap(
                map_fd,
                (char*)keys + (i * mapInfo.key_size), //key_size: 单个key的大小
                (char*)values + (i * mapInfo.value_size) //value_size: 单个value的大小
            );
            if(res != 0) {
                LOG(ERROR) << "bpfUpdateMap (bpfUpdateMapBatch) failed, errno = " << folly::errnoStr(errno);
                return -1;
            }
        }
    }
    return 0;
}
//------------------------------------2025-2-14-------------------------------

}