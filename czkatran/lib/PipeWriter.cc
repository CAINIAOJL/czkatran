#include "PipeWriter.h"
#include <folly/io/IOBuf.h>
#include <unistd.h>
#include <cstring>

namespace czkatran {

PipeWriter::PipeWriter() {}

void PipeWriter::writeData(const void* ptr, std::size_t size) {
    //每隔十秒打印一次日志
    VLOG_EVERY_N(4, 10) << __func__ << "write" << size << "bytes";

    if(size == 0) {
        LOG(ERROR) << "size is 0";
        return;
    } 

    if(!enabled_) {
        VLOG_EVERY_N(4, 10) << "PipeWriter is not enabled";
        return;
    }

    pipe_->write(&callback_, ptr, size);
}

void PipeWriter::writeHeader(const void* ptr, std::size_t size) {
    headerBuf_ = folly::IOBuf::copyBuffer(ptr, size);
}

bool PipeWriter:: available(std::size_t size) {
    return true;
}

bool PipeWriter:: restart() {
    VLOG(4) << "Restarting PipeWriter";
    enabled_ = true;
    return true;
}

bool PipeWriter:: stop() {
    VLOG(4) << "Stopping PipeWriter";
    enabled_ = false;
    return true;
}

void PipeWriter:: setWriterDestination(std::shared_ptr<folly::AsyncPipeWriter> pipewriter) {
    CHECK(pipewriter) << "PipeWriter destination is not set";
    pipe_ = pipewriter;
}

void PipeWriter:: unsetWriterDestination() {
    pipe_.reset();
}

}