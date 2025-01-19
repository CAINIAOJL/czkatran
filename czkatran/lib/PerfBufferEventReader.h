#pragma once

#include <bpf/libbpf.h>
#include <vector>
#include <memory>
#include <folly/io/async/EventHandler.h>

namespace czkatran {

class PerfBufferEventReader {
    public:
        PerfBufferEventReader() = default;
        virtual ~PerfBufferEventReader();

        /**
         * @brief Opens the perf buffer and starts reading events.
         * @param bpfPerfMap The BPF perf map to read from.
         * @param evb The event base to run the reader on.
         * @param pageCount The number of pages to allocate for the perf buffer.
         */
        bool open(int bpfPerfMap, folly::EventBase* evb, size_t pageCpount);

        /**
         * @brief Callback when a perf buffer event is received.
         * @param cpu The CPU the event was received on.
         * @param data The event data.
         * @param size The size of the event data.
         */
        virtual void handlePerfBufferEvent(int cpu, const char* data, size_t size) noexcept;

        virtual void handlePerfBufferLoss(int cpu, uint64_t losscount) {}


    private:
    
    class CpuPerfBufferHandler : public folly::EventHandler {
        public:
            CpuPerfBufferHandler(folly::EventBase* evb,
                                struct perf_buffer* pb,
                                int bufFd,
                                size_t index);
                
            void handlerReady(uint16_t events) noexcept override;
        private:
            struct perf_buffer* pb_ {nullptr};
            int bufFd_;
            size_t bufIndex_;

    };

    struct perf_buffer* pb { nullptr};
    std::vector<std::unique_ptr<CpuPerfBufferHandler>> cpuBufferHandlers_;
        
};

}