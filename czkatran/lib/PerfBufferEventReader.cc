#include "PerfBufferEventReader.h"

namespace {

static void handle_sample_cb(void* ctx, int cpu, void* RawData, __u32 DataSize) {
    auto perfBufferReader = reinterpret_cast<::czkatran::PerfBufferEventReader*>(ctx);
    perfBufferReader->handlePerfBufferEvent(cpu, reinterpret_cast<const char*>(RawData), DataSize);
}

static void handle_lost_cb(void* ctx, int cpu, __u64 lost) {
    LOG(ERROR) << "cpu :" << cpu << " lost samples: " << lost;
    auto perfBufferReader = reinterpret_cast<::czkatran::PerfBufferEventReader*>(ctx);
    perfBufferReader->handlePerfBufferLoss(cpu, lost);
}

//检查是否是2的幂
bool isPowerOfTwo(uint64_t x) {
    return (x & (x - 1)) == 0;
}

}


namespace czkatran {

PerfBufferEventReader:: ~PerfBufferEventReader() {
    perf_buffer__free(pb); //释放perf_buffer
}

bool PerfBufferEventReader:: open(int bpfPerfMap, 
                                  folly::EventBase* evb, 
                                  size_t pageCpount)
{
    CHECK(evb != nullptr) << "Null EventBase";
    //初始化perf_buffer时，注意pagecnt参数必须是2的幂
    if(pageCpount == 0 || !isPowerOfTwo(pageCpount)) {
        LOG(ERROR) << "Invalid page count: " << pageCpount;
        return false;
    }
    //perf_buffer初始化需要回调函数，一个是样本处理函数，一个是样本丢失函数
    pb = perf_buffer__new(bpfPerfMap, pageCpount, handle_sample_cb, handle_lost_cb, this, nullptr);

    auto err = libbpf_get_error(pb);
    if(err != 0) {
        LOG(ERROR) << "Failed to create perf buffer: " << err;
        return false;
    }

    size_t bufcnt = perf_buffer__buffer_cnt(pb);
    if(bufcnt == 0) {
        LOG(ERROR) << "Failed to create perf buffer: no buffers";
        return false;
    }
    for(auto i = 0; i < bufcnt; i++) {
        int bufFd = perf_buffer__buffer_fd(pb, i);
        cpuBufferHandlers_.push_back(std::make_unique<PerfBufferEventReader::CpuPerfBufferHandler>(evb, pb,bufFd, i)); 
    }

    return true;
}

PerfBufferEventReader::CpuPerfBufferHandler::CpuPerfBufferHandler(
                                folly::EventBase* evb,
                                struct perf_buffer* pb,
                                int bufFd,
                                size_t index): pb_(pb), bufFd_(bufFd), bufIndex_(index)
{
    initHandler(evb, folly::NetworkSocket::fromFd(bufFd_));
    if(!registerHandler(READ | PERSIST)) {
        LOG(ERROR) << "Failed to register perf buffer handler";
    }    

}

void PerfBufferEventReader::CpuPerfBufferHandler::handlerReady(uint16_t events) noexcept{
    int res = perf_buffer__consume_buffer(pb_, bufIndex_);
    if(res < 0) {
        LOG(ERROR) << "Failed to consume perf buffer: " << res;
    }
}   


}