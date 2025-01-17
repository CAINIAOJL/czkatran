#pragma once

#include "DataWriter.h"
#include <cstdint>
#include <folly/io/async/AsyncPipe.h> //从管道中读取数据，异步方式进行
#include <folly/io/async/AsyncSocketException.h> //异步socket异常


namespace czkatran {

class PipeWriterCallback : public folly::AsyncWriter::WriteCallback {
    public:
        void writeSuccess() noexcept override {
            event_writes_++;
        }

        void writeErr(size_t, const folly::AsyncSocketException& e) noexcept override {
            LOG(ERROR) << "PipeWriter error" << e.what();
            event_errors_++;
        }

        void reset() {
            event_writes_ = 0;
            event_errors_ = 0;
        }
        uint32_t event_writes_ {0}; 
        uint32_t event_errors_ {0};
};

//write pcap_data into pipe
class PipeWriter : public DataWriter {
    public:
        explicit PipeWriter();

        void writeData(const void* ptr, std::size_t size) override;

        void writeHeader(const void* ptr, std::size_t size) override;

        bool available(std::size_t size) override;

        bool restart() override;

        bool stop() override;

        void setWriterDestination(std::shared_ptr<folly::AsyncPipeWriter> pipewriter);

        void unsetWriterDestination();

        uint32_t getWrites() {
            return callback_.event_writes_;
        }

        uint32_t getErrors() {
            return callback_.event_errors_;
        }


    private:
        //pipe 管道的写端
        std::shared_ptr<folly::AsyncPipeWriter> pipe_;

        //是否可用
        bool enabled_ {true}; //开始是可用状态

        //回调函数
        PipeWriterCallback callback_;

        //header buffer
        std::unique_ptr<folly::IOBuf> headerBuf_ {nullptr};

};
}