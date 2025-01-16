#pragma once

#include <memory>

#include <folly/io/IOBuf.h>


namespace czkatran {

class PcapMsg {
    public:
        PcapMsg(); //构造函数

        ~PcapMsg(); //析构函数

        /**
         * @brief 构造函数
         * @param pckt 原始数据包
         * @param origlen 原始数据包长度
         * @param capturedLen 捕获数据包长度
         */
        PcapMsg(const char* pckt, uint32_t origlen, uint32_t capturedLen);
        PcapMsg(PcapMsg&& msg) noexcept; //移动构造函数
        PcapMsg(const PcapMsg& msg) = delete; //拷贝构造函数
        PcapMsg& operator=(PcapMsg&& msg) noexcept; //移动赋值运算符
        PcapMsg& operator=(const PcapMsg& msg) = delete; //拷贝赋值运算符

        uint32_t getOrigLen() const {
            return origLen_;
        }

        uint32_t getOrigLen() {
            return origLen_;
        }

        uint32_t getCaptruedLen() const {
            return capturedLen_;
        }

        uint32_t getCaptruedLen() {
            return capturedLen_;
        }

        const uint8_t* getRawData() {
            return pckt_->data();
        }

        const uint8_t* getRawData() const {
            return pckt_->data();
        }

        bool empty() const {
            return (pckt_ == nullptr);
        }

        uint32_t trim(uint32_t snaplen) {
            return capturedLen_ = std::min(capturedLen_, snaplen);
        }

    private:
        std::unique_ptr<folly::IOBuf> pckt_; //原始数据包
        uint32_t origLen_ {0}; //原始数据包长度
        uint32_t capturedLen_ {0}; //捕获数据包长度
};





}