#pragma once

#include <folly/MPMCQueue.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/AsyncPipe.h>

#include "/home/jianglei/czkatran/czkatran/lib/MonitoringStructs.h"
#include "/home/jianglei/czkatran/czkatran/lib/czkatranLbStructs.h"
#include "/home/jianglei/czkatran/czkatran/lib/PcapWriter.h"
#include "/home/jianglei/czkatran/czkatran/lib/PcapMsgMeta.h"

namespace folly {
    class ScopedEventBaseThread;
}

namespace czkatran {

class czkatranEventReader;
class PcapWriter;

class czkatranMonitor {
    public:
        czkatranMonitor() = delete;

        explicit czkatranMonitor(const struct czKatranMonitorConfig& config);

        ~czkatranMonitor();

        void stopMonitor();

        void restartMonitor(uint32_t limit, std::optional<PcapStorageFormat> storage);

        PcapWritesStats getPcapWriterStats();

        std::unique_ptr<folly::IOBuf> getEventBuffer(monitoring::EventId event);

        std::set<monitoring::EventId> getEnabledEvents();

        bool enableWriterEvent(monitoring::EventId event);

        bool disabledWriterEvent(monitoring::EventId event);

        PcapStorageFormat getStorageFormat() {
            return config_.storage;
        }        

        void setAsyncPipeWriter(monitoring::EventId event, std::shared_ptr<folly::AsyncPipeWriter> writer);

        void unsetAsyncPipeWriter(monitoring::EventId event);

    private:
        std::unordered_map<monitoring::EventId, std::shared_ptr<DataWriter>> createWriters(); 
        
        //main config 
        struct czKatranMonitorConfig config_;

        std::unordered_map<monitoring::EventId, std::shared_ptr<folly::AsyncPipeWriter>> pipeWriters_;

        std::shared_ptr<PcapWriter> writer_; //写端是共享指针

        std::unique_ptr<czkatranEventReader> reader_; //读端是unique指针

        std::shared_ptr<folly::MPMCQueue<PcapMsgMeta>> queue_; //队列是共享指针

        std::unique_ptr<folly::ScopedEventBaseThread> scopedEvb_;

        std::thread writerThread_;

        std::unordered_map<monitoring::EventId, std::unique_ptr<folly::IOBuf>> buffers_;

};

}