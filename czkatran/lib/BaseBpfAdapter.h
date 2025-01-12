#pragma once

#include <folly/Function.h>



extern "C" {
    #include <bpf/bpf.h>
    #include <bpf/libbpf.h>
    #include <linux/perf_event.h>
}

namespace czkatran {

//constexpr 编译期可见的常量
constexpr int TC_INGRESS = 0xfffffff2;
constexpr int TC_EGRESS = 0xfffffff3;

constexpr unsigned int kBpfMapTypeUnspec = 0;
constexpr unsigned int kBpfMapTypeHash = 1;
constexpr unsigned int kBpfMapTypeArray = 2;
constexpr unsigned int kBpfMapTypeProgArray = 3;
constexpr unsigned int kBpfMapTypePerfEventArray = 4;
constexpr unsigned int kBpfMapTypePercpuHash = 5;
constexpr unsigned int kBpfMapTypePercpuArray = 6;
constexpr unsigned int kBpfMapTypeStackTrace = 7;
constexpr unsigned int kBpfMapTypeCgroupArray = 8;
constexpr unsigned int kBpfMapTypeLruHash = 9;
constexpr unsigned int kBpfMapTypeLruPercpuHash = 10;
constexpr unsigned int kBpfMapTypeLpmTrie = 11;
constexpr unsigned int kBpfMapTypeArrayOfMaps = 12;
constexpr unsigned int kBpfMapTypeHashOfMaps = 13;

class BaseBpfAdapter {
    public:
        BaseBpfAdapter(bool set_limits, bool enableBatchOpsIfSupported);

        virtual ~BaseBpfAdapter();

        /**
         * @brief loadBpfProg 加载BPF程序
         * @param string bpf_prog ---要加载的BPF程序
         * @param bpf_prog_type type ---程序类型，默认为BPF_PROG_TYPE_UNSPEC
         * @param bool use_names ---是否使用名称，默认为false
         * @return int ---0表示成功，其他表示失败
         */
        virtual int loadBpfProg(
            const std::string& bpf_prog,
            const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC,
            bool use_names = false) = 0;
        
        virtual int loadBpfProg(
            const char *buf,
            int buf_size,
            const ::bpf_prog_type type = BPF_PROG_TYPE_UNSPEC,
            bool use_names = false,
            const char * objname = "buffer") = 0;

        /**
         * @brief reloadBpfProg 重新加载BPF程序
         * @param string bpf_prog ---要加载的BPF程序
         * @param bpf_prog_type type ---程序类型，默认为BPF_PROG_TYPE_UNSPEC
         * @return int ---0表示成功，其他表示失败
         */
        virtual int reloadBpfProg(
            const std::string& bpf_prog,
            const bpf_prog_type type = BPF_PROG_TYPE_UNSPEC) = 0;
        
        /**
         * @brief 通过map的name找到fd套接字
         * @param string name ---map的名称
         * @return int ---fd套接字
         */
        virtual int getMapFdByName(const std::string& name) = 0;

        /**
         * @brief 查找map是否存在在program中
         * @param string progName ---program名称
         * @param string mapName ---map名称
         * @return bool ---true表示存在，false表示不存在
         */
        virtual bool isMapInProg(
            const std::string& progName, 
            const std::string& mapName) = 0;

        /**
         * @brief 设置map到inner_Map_prototypes_中
         * @param string name ---map的名称
         * @param int fd ---map的fd
         * @return int ---0表示成功，其他表示失败
         */
        virtual int setInnerMapProtoType(
            const std::string& name, 
            int fd) = 0;
        
        /**
         * @brief 通过program的name找到fd套接字
         * @param string name ---program的名称
         * @return int ---fd套接字
         */
        virtual int getProgFdByName(const std::string& name) = 0;

        /**
         * @brief 更新共享map
         * @param string name ---map的名称
         * @param int fd ---map的fd
         * @return int ---0表示成功，其他表示失败
         */
        virtual int updateSharedMap(
            const std::string& name, 
            int fd) = 0;

        /**
         * @brief 通过interface（ifname）寻找ifindex
         * @param string interface ---interface名称
         * @return 0 ---失败，int ---ifindex
         */
        static int getInterfaceIndexByName(const std::string& interface_name);

        /**
         * @brief 终止xdp程序，通过interface（ifname）
         * @param string interface ---interface名称
         * @return int ---0表示成功，其他表示失败
         */
        static int detachXdpProgram(
            const std::string& interface_name, 
            uint32_t flags = 0);

        static int detachXdpProgram(
            const int ifindex, 
            uint32_t flags = 0);

        /**
         * @brief 通过path获得obj的fd
         * @param string path ---obj的路径
         * @return int ---fd
         */
        static int getPinnedBpfObject(const std::string& path);

        /**
         * @brief 删除map中的元素
         * @param int map_fd ---map的fd
         * @param void *key ---要删除的元素的key
         * @return int ---0表示成功，其他表示失败
         */
        static int bpfMapDeleteElement(
            int map_fd, 
            void *key);

        /**
         * @brief 附加xdp程序，通过interface（ifname）
         * @param int prog_fd ---program的fd
         * @param string interface ---interface名称
         * @param uint32_t flags ---附加标志
         * @return int ---0表示成功，其他表示失败
         */
        static int attachXdpProgram(
            const int prog_fd, 
            const std::string& interface_name, 
            const uint32_t flags = 0);

        /**
         * @brief update map element
         * @param int map_fd ---map的fd
         * @param void *key ---要更新的元素的key    
         * @param void *value ---要更新的元素的value
         * @param uint64_t flags ---更新标志
         * @return int ---0表示成功，其他表示失败
         */
        static int bpfUpdateMap(
            int map_fd, 
            void *key, 
            void *value, 
            uint64_t flags = 0);

        /**
         * @brief 获取当前系统的cpu数量
         */
        static int getPossibleCpus();

        /**
         * @brief bpf map 中寻找元素
         * @param int map_fd ---map的fd
         * @param void *key ---要查找的元素的key
         * @param void *value ---要查找的元素的value
         * @return int ---0表示成功，其他表示失败
         */
        static int bpfMapLookUpElement(
            int map_fd, 
            void* key, 
            void *value);

        /**
         * @brief 修改xdp程序，通过interface（ifname）
         * @param int prog_fd ---program的fd
         * @param string interface ---interface名称
         * @param uint32_t flags ---修改标志
         * @return int ---0表示成功，其他表示失败
         */
        static int modifyXdpProg(
            const int prog_fd,
            const unsigned int ifindex,
            const uint32_t flags = 0);

                /**
         * @param const int prog_fd: the file descriptor of the eBPF program
         * @param const int repeat: the number of times to repeat the program
         * @param void* data: the input data to the program
         * @param uint32_t data_size: the size of the input data
         * @param void* data_out: the output data from the program
         * @param uint32_t* size_out: the size of the output data
         * @param uint32_t* retval: the return value of the program
         * @param uint32_t* duration: the duration of the program execution in microseconds
         * @param void* ctx_in: the input context data to the program
         * @param uint32_t ctx_in_size: the size of the input context data
         * @param void* ctx_out: the output context data from the program
         * @param uint32_t ctx_out_size: the size of the output context data
         * @return int: the return value of the program
         */
        static int textXdpProg(
            const int prog_fd,
            const int repeat,
            void* data,
            uint32_t data_size,
            void* data_out,
            uint32_t* size_out = nullptr,
            uint32_t* retval = nullptr,
            uint32_t* duration = nullptr,
            void* ctx_in = nullptr,
            uint32_t ctx_in_size = 0,
            void* ctx_out = nullptr,
            uint32_t* ctx_out_size = nullptr
        );
        
        /**
         * @brief 获取interface的ifindex
         * @param string interface_name ---interface名称
         * @return int ---ifindex
         */
        static int getInterfaceIndex(const std::string& interface_name);

        /**
         * @brief 删除tc中的bpf filter
         * @param int prog_fd ---program的fd
         * @param unsigned int ifindex ---interface的ifindex
         * @param string bpf_name ---bpf filter的名称
         * @param uint32_t priority ---bpf filter的优先级
         * @param int direction ---方向，默认为TC_INGRESS
         * @param uint32_t handle ---bpf filter的handle
         * @return int ---0表示成功，其他表示失败
         */
        static int deleteTcBpfFilter(
            const int prog_fd,
            const unsigned int ifindex,
            const std::string& bpf_name,
            const uint32_t priority,
            const int direction = TC_INGRESS,
            const uint32_t handle = 0
        );

        /**
         * @brief 修改tc中的bpf filter
         * @param int cmd ---命令，RTM_NEWTFILTER或RTM_DELTFILTER
         * @param unsigned int flags ---修改标志
         * @param uint32_t priority ---bpf filter的优先级
         * @param int prog_fd ---program的fd
         * @param unsigned int ifindex ---interface的ifindex
         * @param string bpf_name ---bpf filter的名称
         * @param int direction ---方向，默认为TC_INGRESS
         * @param uint32_t handle ---bpf filter的handle
         * @return int ---0表示成功，其他表示失败
         */
        static int modifyTcBpfFilter(
            const int cmd,
            const unsigned int flags,
            const uint32_t priority,
            const int prog_fd,
            const unsigned int ifindex,
            const std::string& bpf_name,
            const int direction = TC_INGRESS,
            const uint32_t handle = 0
        );

};

}