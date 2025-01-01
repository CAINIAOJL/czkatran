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
        return 1;
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

int BaseBpfAdapter:: bpfMapLookUpElement(int map_fd, void* key, void *value) {
    auto bpferror = bpf_map_lookup_elem(map_fd, key, value);
    if(bpferror) {
        VLOG(4) << " bpf_map_lookup_elem failed with error: " << folly::errnoStr(errno);
    }
    return bpferror; // != 0
}

}