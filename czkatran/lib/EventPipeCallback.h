#pragma once

#include <fmt/core.h>
#include <folly/Utility.h>
#include <folly/io/Cursor.h>
#include <folly/io/async/AsyncPipe.h>
#include <folly/Synchronized.h>
#include <folly/io/async/AsyncSocketException.h>

#include "czkatran/lib/czkatranLbStructs.h"
#include "czkatran/lib/MonitoringStructs.h"

namespace czkatran {
namespace monitoring {

namespace {
constexpr uint32_t KReadBufSize = 4000;
constexpr uint32_t KReadBufAllocsize = 4096;
}

class EventPipeCallback : public folly::AsyncPipeReader::ReadCallback {
    public:
           EventPipeCallback() = delete;

           explicit EventPipeCallback(EventId event_id): event_id_(event_id) {}

            explicit EventPipeCallback(EventId event_id,
                                       folly::Synchronized<ClientSubscriptionMap>&& subsmap):
                                           event_id_(event_id),
                                           cb_submap_(std::move(subsmap)) {}


            bool isBufferMovable() noexcept override {
                return false;
            }

            void readBuffer(std::unique_ptr<folly::IOBuf>&& buf) noexcept;

            void logerror(std::string msg) {
                LOG(ERROR) << fmt::format(
                    "EventPipeCallback({}): {}", toString(event_id_), msg);
            }

            void readBufferAvailable(std::unique_ptr<folly::IOBuf> readBuf) noexcept override {
                logerror("getBufferAvailable called while buffer is not movable");
                readBuffer(std::move(readBuf));
            }

            void getReadBuffer(void** bufReturn, size_t* lenReturn) noexcept override {
                auto res = readBuffer_.preallocate(KReadBufSize, KReadBufAllocsize);
                *bufReturn = res.first; //指向IOBUF可写的位置 
                *lenReturn = res.second;//IOBUF可写的长度 tailroom()

                VLOG(4) << "Preallocated " << lenReturn << " bytes";
            } 

            void readDataAvailable(size_t len) noexcept override {
                VLOG(4) << __func__ << len << " bytes";
                readBuffer_.postallocate(len);
                auto buf = readBuffer_.move();
                buf->coalesce();
                readBuffer(std::move(buf));
            }


            void enable() {
                *(event_enabled_.wlock()) = true; //设置event_enabled 为true
            }

            bool enabled() {
                return *(event_enabled_.rlock());
            }

            void disable() {
                *(event_enabled_.wlock()) = false; //设置event_enabled 为false
            }

            void addClientSubscription(std::pair<ClientId, std::shared_ptr<ClientSubscriptionIf>> && new_sub);

            void removeClientSubscription(ClientId client_id);

            void readErr(const folly::AsyncSocketException& e) noexcept override {
                logerror(e.what());
            }

            void readEOF() noexcept override {
                if(enabled()) {
                    logerror("EOF read while event is enabled");
                }
            }

    private:
        //
        folly::IOBufQueue readBuffer_;

        //Synchronized实现了数据和锁的绑定，使得数据和锁的操作原子化，保证线程安全
        //实现了锁的操作
        folly::Synchronized<ClientSubscriptionMap> cb_submap_;

        //实现了锁的操作
        folly::Synchronized<bool> event_enabled_ {false};

        EventId event_id_;
};
}
}

