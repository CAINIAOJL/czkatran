#pragma once
//------------------------------------2025-2-15-------------------------------
//--------------------------√
#include <folly/io/IOBuf.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include <memory>
#include <string>

namespace czkatran {

struct czkatranFlow {
    std::string src;
    std::string dst;

    uint16_t srcport;
    uint16_t dstport;
    uint8_t proto;
};



/*
* KatranSimulator 允许最终用户模拟指定数据包在被 Katran 负载均衡器处理后将发生的情况。
* 例如，这个数据包将被发送到（真实地址）哪里。
*/
class czkatranSimulator final {
    public:
        explicit czkatranSimulator(int rpogfd);
        
        ~czkatranSimulator();

        const std::string getRealForFlow(const czkatranFlow& flow);

        std::unique_ptr<folly::IOBuf> runSimulation(
            std::unique_ptr<folly::IOBuf> pckt
        );

    private:
        /*
        runSimulation 接受 packet （在 iobuf 表示中） 和
        通过 Katran BPF 程序运行它。它返回修改后的 pckt，如果
        result 为 XDP_TX 或 nullptr。
        */
        std::unique_ptr<folly::IOBuf> runSimulationInternal(
            std::unique_ptr<folly::IOBuf> pckt
        );

        /*
        将模拟器 evb 线程关联到 CPU 0。
        这可确保后续模拟在相同的 CPU 上运行并命中
        相同的每 CPU 映射。
        */
        void affinitizeSimulatorThread();

        int prog_fd;

        //thread
        folly::ScopedEventBaseThread simulatorEvn_ {"czkatranSimulator"};


};
}
//------------------------------------2025-2-15-------------------------------
//--------------------------√