#include <fcntl.h>
#include <folly/io/async/EventBase.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <vector>
#include "/home/jianglei/czkatran/czkatran/lib/EventPipeCallback.h"
#include "/home/jianglei/czkatran/czkatran/lib/PcapStructs.h"

using namespace ::testing;
using namespace ::czkatran;
using namespace ::czkatran::monitoring;


namespace {
// 100 bytes
std::string kDefaultRaw =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Cras at sem nec tortor aliquet ullamcorper.";
std::string kLargeRaw =
    "ySWfbHcqMziTj7jJKnQX0HA7EMNJQGA2R2Tl5KgFs3txYcUSzXkbgm738rwCjLRePYxY9nBoaQKBcxSl442Ag19QXzSU105t5s9QdZga9HosZQLEXMYZmQ1jl2CNZWNssCBVY89h1petGhfBlqWlbb1iHX3mi5Tjr1ldC4hFLE9gOp2JXsE70tKfyhxNjv8JqWUKys1AXCesTBuxh2hMRwcLsOFNmWn1o94HBLMQfIA5oqDSPgHK58xOmHyySC6GhW6UaK3RL0bNwGGBaR9iqAwUVOzDser2Jk3aT5qLTiwNElvIkkL30rBw7n3CrVw0ol6N7zMjmSW204aYiQ6Sd99OVyS09eThHkJjfWRsE2yYU2ZgDcRoknTmUuAGzfpsvVL3hThm9B7HvAsWnuB5cG5yfw727kqQtx0DyHZ3euePWKTJGc58WFzx93dqLr8aywlibftndt1rz3E1Hk6yCBbLUiJCrBiV4rET0bAdaCdcVPFJGhoP8LWhyfSvI0drVKqB3Rf5cgjmXUqeqtz3UeeQR7Rxv3yhSOdoT0MrlNUblmYNsr8KVBkl8GHaqtOqrdsKgG8bQOXMXnbDjA6OXxMaERYtazWYRgIiWAdx6u7VLoxleGqSAhkRBhWS6PzXNYjaJ9ZkPnIzSWDpE4mhAo682fWveSMN2kd9CCN6DtnyZOh1iPPFuA2B7yV0NmdeWJFQjjZ95W0KnIIQAPzCzDP8Wt8HTZV3ZyUjX1Qf0abTejkdC5Tws9hsbbOICFTAIclilsu055oV0y055kQpMUsLuWnxUCgc4SbUeUTZraZnhHdcLaubbdz3Q4gfkQDdBzJwUmGVbdWut5VqMyX2yTfF4NH3T2TQ2oLT5eF25zfBq2yi1GLntbHanTo9C6DgAHs3zzodZ0wJakzNEDTgtovBFj1dUEao7H6kF0KT7fV4XcWY3ELRVxqS8CJKJEQNMLeIL6G9lYmlKuVImsm7xRWk6v0ZdXauwHG9RqVdeZSCwvPWn3mdFANkFuXYWcR0AaBxt3n2gZMEn8MgpWICfQ42C1ny2J3Nw5Gxzw584GilqnKUrPjFJVEjEdaLuQC0oY4Nuo3lUvs2a6kqVF0UTsj7HnIiz9TXK9h3CSYlWhjyCxcc59J4JOzIFl3P4pEVsCIdo5ZClU5lLrhfCGx6RV5HW2uyVF6z8znIQ1iBzocjnjQGZfuqFX9Bs3Zy5NXNytcWdezjbECwB57QD1HzTyr5t37A1yLPqJ9hEQ8aynpAd45DGI5WGUHVwECFaeEWkuZivHsH5WqvvXczE3K3g1oke9o0DLGgDeo1lwf952GqRIKJ1t5H4Drog9Fp2QseIyXYaWZ1HldgzBTdqJsxf853huDLW72C6dl2yYpJeq3Kj38KejSb9g3sN8NzXE27cA3fSRgXGoH8ZCsBsEYbvLN8WEiJCH4wDf27JJHURjZnJxeTbPzALZ21YHYPdYbsGMbC17SyJAYHZfQV8Tj2LjIcznBSxTV8bLe7EfKcDq";
}

// Mock class for ClientSubscriptionIf(基类)
class mockClientSubsrciption : public ClientSubscriptionIf {
    public:
        explicit mockClientSubsrciption() {}
        
        void sendEvent(const Event& event) override {
            sent_events.push_back(event);
        }

        bool hasEvent(const EventId& eventid) override {
            for(auto &event : sent_events) {
                if(event.id == eventid) {
                    return true;
                }
            }
            return false;
        }
        std::vector<Event> sent_events; //模拟已经发送的事件
};

class MockAsyncWriteCallback : public folly::AsyncWriter::WriteCallback {
    public:
        MockAsyncWriteCallback() = default;
        ~MockAsyncWriteCallback() override = default;

        MOCK_METHOD0(writeSuccessImpl, void());
        void writeSuccess() noexcept override {
            writeSuccessImpl();
        }

        MOCK_METHOD2(writeErrImpl, void(size_t bytes_written, const folly::AsyncSocketException& ex));
        void writeErr(size_t bytes_written, const folly::AsyncSocketException& ex) noexcept override {
            writeErrImpl(bytes_written, ex);
        } 
};

class EventPipeCallBackTest : public Test {
    public:
        void SetUp() override {
            int rc = pipe2(pipe_fd, O_NONBLOCK);
            EXPECT_EQ(rc, 0);

            reader_ = 
                folly::AsyncPipeReader::newReader(&evb_, folly::NetworkSocket::fromFd(pipe_fd[0]));
            writer_ = 
                folly::AsyncPipeWriter::newWriter(&evb_, folly::NetworkSocket::fromFd(pipe_fd[1]));
        }

        pcaprec_hdr_s getDefaultPcapRecordHeader(uint32_t incl_len, uint32_t orig_len) {
                auto unix_ts = std::chrono::duration_cast<std::chrono::microseconds>
                                                (std::chrono::high_resolution_clock::now().time_since_epoch()).count();
                const uint32_t now_sec = unix_ts / 1000000;
                const uint32_t now_usec = unix_ts - now_sec * 1000000;
                pcaprec_hdr_s header = {
                    .ts_sec = now_sec,
                    .ts_usec = now_usec,
                    .incl_len = incl_len,
                    .orig_len = orig_len
                };
                return header;
        }

        std::string getDefaultEventData(pcaprec_hdr_s rec_hdr, const std::string& raw) {
            auto hdr_buf = folly::IOBuf::copyBuffer(&rec_hdr, sizeof(rec_hdr));
            auto data_buf = folly::IOBuf::copyBuffer(raw.c_str(), raw.size());
            hdr_buf->appendChain(std::move(data_buf));
            hdr_buf->coalesce();
            return std::string(reinterpret_cast<const char*>(hdr_buf->data()), hdr_buf->length());
        }

        Event getEvent(uint32_t orig_len, const std::string& raw) {
            EXPECT_GE(orig_len, raw.size()); //greater

            auto header = getDefaultPcapRecordHeader(raw.size(), orig_len);
            std::string event = getDefaultEventData(header, raw);
            Event e {
                .id = EventId::TCP_NONSYN_LRUMISS,
                .pcksize = orig_len,
                .data = event
            };
            return e;
        }

        folly::EventBase evb_;
        int pipe_fd[2];
        folly::AsyncPipeReader::UniquePtr reader_ {nullptr};
        folly::AsyncPipeWriter::UniquePtr writer_ {nullptr};
        std::unique_ptr<EventPipeCallback> eventPipeCb_ {nullptr};
};

TEST_F(EventPipeCallBackTest, SimpleCallbacktest) {
    auto mock_sub = std::make_shared<mockClientSubsrciption>();
    Event expect_event = getEvent(200, kDefaultRaw);

    ClientSubscriptionMap submap;
    for(int i = 1; i <= 10; i++) {
        submap.insert({i, mock_sub});
    }
    eventPipeCb_ = std::make_unique<EventPipeCallback>(
        EventId::TCP_NONSYN_LRUMISS,
        folly::Synchronized<ClientSubscriptionMap>(std::move(submap))
    );
    eventPipeCb_->enable();
    reader_->setReadCB(eventPipeCb_.get());

    writer_->write(nullptr, expect_event.data.c_str(), expect_event.data.size());
    writer_->closeOnEmpty();

    evb_.loop();
    evb_.loop();

    EXPECT_EQ(mock_sub->sent_events.size(), 10);//10个订阅者，这些订阅者共享一个指针，所以在mock类中，sent_events的size等于10
    for(int i = 0; i < 10; i++) {
        auto event = mock_sub->sent_events[i];
        EXPECT_EQ(event.id, expect_event.id);
        EXPECT_EQ(event.pcksize, expect_event.pcksize);
        EXPECT_EQ(event.data, expect_event.data);
    }
}

TEST_F(EventPipeCallBackTest, LargeWritetest) {
    auto mock_sub = std::make_shared<mockClientSubsrciption>();
    Event expect_event = getEvent(1514, kLargeRaw);
    EXPECT_EQ(
        expect_event.data.size(),
        kLargeRaw.size() + sizeof(struct pcaprec_hdr_s)
    );
    int numBatch = 10;

    ClientSubscriptionMap submap;
    submap.insert({1, mock_sub});
    eventPipeCb_ = std::make_unique<EventPipeCallback>(
        EventId::TCP_NONSYN_LRUMISS,
        folly::Synchronized<ClientSubscriptionMap>(std::move(submap))
    );
    eventPipeCb_->enable();
    reader_->setReadCB(eventPipeCb_.get());

    MockAsyncWriteCallback mock_write_cb;
    EXPECT_CALL(mock_write_cb, writeSuccessImpl())
    .WillRepeatedly(Invoke([&]{
        LOG(INFO) << "write success! ";
    }));

    EXPECT_CALL(mock_write_cb, writeErrImpl(_, _))
    .WillRepeatedly(Invoke([&](size_t bytes_written, const folly::AsyncSocketException& ex){
        EXPECT_TRUE(false) 
            << "writer error, has written bytes: " << bytes_written << "\n"
            << "Socket exception: " << ex.what();
    }));
    //写10000个相同的包
    for(int i = 0; i < numBatch; i++) {
        writer_->write(&mock_write_cb, expect_event.data.c_str(), expect_event.data.size());
    }

    for(int i = 0; i < numBatch; i++) {
        evb_.loopOnce(EVLOOP_NONBLOCK);
    }

    EXPECT_EQ(mock_sub->sent_events.size(), numBatch); //一个客户端订阅者，写入10000个包
    for(int i = 0; i < numBatch; i++) {
        auto event = mock_sub->sent_events[i];
        EXPECT_EQ(expect_event.id, event.id);
        EXPECT_EQ(expect_event.pcksize, event.pcksize);
        EXPECT_EQ(expect_event.data, event.data);
    }
}

int main(int argc, char** argv) {
    InitGoogleMock(&argc, argv);
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
