#include "GrpcSingalHandler.h"

#include <folly/io/async/EventBase.h>

namespace lb {
namespace czkatran {


GrpcSignalHandler::GrpcSignalHandler(
        std::shared_ptr<folly::EventBase>evb, 
        grpc::Server* server, 
        int32_t delay): folly::AsyncSignalHandler(evb.get()), delay_(delay)
{
    server_ = server;
    evb_ = evb;
}

void GrpcSignalHandler:: signalReceived(int signum) noexcept
{
    if(shutdownScheduled_) {
        LOG(INFO) << "Ignoring signal: " << signum << "as we alreay shutdown scheduled signalhandler to run. ";
        return;
    }  
    
    evb_->runInEventBaseThread([this]() {
        evb_->runAfterDelay([this]() {
            LOG(INFO) << "Shutting down server";
            server_->Shutdown();
        }, delay_);
    });
    shutdownScheduled_ = true;
}

}
}