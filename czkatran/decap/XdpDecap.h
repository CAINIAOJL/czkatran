#pragma once

#include "/home/jianglei/czkatran/czkatran/decap/XdpDecapStrcuts.h"
#include "/home/jianglei/czkatran/czkatran/lib/BpfAdapter.h"

namespace czkatran {

class XdpDecap {
    public:
        XdpDecap() = delete;

        //由XdpDecapConfig构造
        explicit XdpDecap(const XdpDecapConfig& config);

        ~XdpDecap();

        //加载XDP程序
        void loadXdpDecap();

        //attach XDP程序
        void attachXdpDecap();

        //获取XdpDecap的状态
        decap_stats getXdpDecapStats();

        int getXdpDecapFd();

        void setServerId(int id);
    
    private:
        //XdpDecap的配置
        XdpDecapConfig config_;

        //bpf程序加载器
        BpfAdapter bpfAdapter_;


        //一个标志，表示XdpDecap是否独立运行，
        //在独立运行下，Xdp程序安装到物理接口下
        //不在独立运行下，Xdp程序会放入提供的 BPF 的程序数组中的指定位置
        bool isStandalone {true};

        //是否加载了Xdp程序
        bool isLoaded_ {false};

        //是否附加了Xdp程序
        bool isAttached_ {false};
};

}