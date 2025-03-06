#pragma once

#include <memory>
//用于接收有关 POSIX 信号的通知的处理程序。
#include <folly/io/async/AsyncSignalHandler.h>
#include <grpc++/grpc++.h>

namespace folly {
    class EventBase;
}

namespace lb {
namespace czkatran {

class GrpcSignalHandler : public folly::AsyncSignalHandler {
    public:
        GrpcSignalHandler(std::shared_ptr<folly::EventBase>eb, 
                            grpc::Server* server, 
                            int32_t delay);

        ~GrpcSignalHandler() override {}


        void signalReceived(int signum) noexcept override;

    private:
        grpc::Server* server_;
        std::shared_ptr<folly::EventBase> evb_;
        int32_t delay_;
        bool shutdownScheduled_ {false};
    
};
}
}

