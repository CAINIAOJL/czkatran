#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace czkatran {

class NetlinkMessage {

public:

    /**
     * @brief 创造一条netlink message 用来与控制bpf程序（TC）
     * @param unsigned seq ---message序列号
     * @param int cmd ---message命令
     * @param unsigned flags ---message标志
     * @param uint32_t priority ---message 优先级
     * @param int prog_fd ---bpf程序文件描述符
     * @param unsigned ifindex ---网络接口索引
     * @param string bpf_name ---bpf程序名称
     * @param int dirction ---方向 ingress/egress
     * @param uint32_t handle ---句柄 tc-filter handle
     * @return NetlinkMessage
     */
    static NetlinkMessage TC(unsigned seq,
                            int cmd,
                            unsigned flags,
                            uint32_t priority,
                            int prog_fd,
                            unsigned ifindex,
                            const std::string& bpf_name,
                            int dirction,
                            const uint32_t handle = 0);

    /**
     * @brief 创造一条netlink message 用来与控制bpf程序（Qdisc）
     */
    static NetlinkMessage QD(unsigned ifindex);

    /**
     * @brief 创造一条netlink message 用来与控制xdp程序
     * @param unsigned seq ---message序列号
     * @param int prog_fd ---bpf程序文件描述符
     * @param unsigned ifindex ---网络接口索引
     * @param unsigned flags ---message标志
     * @return NetlinkMessage
     */
    static NetlinkMessage XDP(unsigned seq,
                             int prog_fd,
                             unsigned ifindex,
                             uint32_t flags);

    size_t size() const {
        return data_.size();
    }

    const uint8_t* data() const {
        return data_.data();
    }

    unsigned seq() const;

    private:
    NetlinkMessage();
    std::vector<uint8_t> data_;

};


}