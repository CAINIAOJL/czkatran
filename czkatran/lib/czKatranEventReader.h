#pragma once

#include <folly/MPMCQueue.h>
#include "PcapMsgMeta.h"
#include "PerfBufferEventReader.h"

namespace folly {
    class EventBase;
}

namespace czkatran {

class czkatranEventReader : public PerfBufferEventReader {
    public:
        explicit czkatranEventReader(std::shared_ptr<folly::MPMCQueue<PcapMsgMeta>> queue): queue_(queue) {}

        void handlePerfBufferEvent(int cpu, const char* data, size_t size) noexcept override;



    private:
        std::shared_ptr<folly::MPMCQueue<PcapMsgMeta>> queue_;
};



}