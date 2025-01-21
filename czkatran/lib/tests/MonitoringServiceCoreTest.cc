#include "/home/jianglei/czkatran/czkatran/lib/MonitoringServiceCore.h"
#include <fcntl.h>
#include <folly/Random.h>
#include <gtest/gtest.h>
#include <algorithm>
#include <functional>
#include <mutex>

using namespace ::testing;
using namespace ::czkatran;
using namespace ::czkatran::monitoring;

namespace {
const std::set<EventId> kEventIds = {
    EventId::TCP_NONSYN_LRUMISS,
    EventId::PACKET_TOOBIG
};
}

class MockMonitoringServiceCore : public MonitoringServiceCore {
    public:
        MockMonitoringServiceCore() {}

        static std::shared_ptr<MockMonitoringServiceCore> make() {
            return std::make_shared<MockMonitoringServiceCore>();
        }

        bool initialize(std::shared_ptr<czkatranMonitor> monitor) {
            for(const auto& event : kEventIds) {
                int pipefd[2];
                int res = pipe2(pipefd, O_NONBLOCK);
                EXPECT_EQ(res, 0);
                auto reader = 
                    folly::AsyncPipeReader::newReader(reader_thread_.getEventBase(), folly::NetworkSocket::fromFd(pipefd[0]));
                auto writer = 
                    folly::AsyncPipeWriter::newWriter(reader_thread_.getEventBase(), folly::NetworkSocket::fromFd(pipefd[1]));
                //为每个event创造回调函数
                auto cb = std::make_unique<EventPipeCallback>(event);
                cb->enable();
                reader->setReadCB(cb.get());
                readers_.insert({event, std::move(reader)});
                Events_to_cbs_.insert({event, std::move(cb)});
                my_writers_.insert({event, std::move(writer)});
                enabled_events_.insert(event);
            }
            initialized_ = true;
            return true;
        }


        private:
            std::unordered_map<EventId, std::unique_ptr<folly::AsyncPipeWriter, folly::DelayedDestruction::Destructor>> my_writers_;
};

class MockClientSubscription : public ClientSubscriptionIf {
    public:
        void sendEvent(const Event& event) override{
            sent_events_.push_back(event);
        }

        bool hasEvent(const EventId& eventid) override {
            return std::find_if(sent_events_.begin(),
                                    sent_events_.end(),
                                    [&](const auto& it)-> bool {
                                        return it.id == eventid;
                                    }) != sent_events_.end();
        }
        std::vector<Event> sent_events_;
};

class TestMonitoringServiceCore : public Test {
    public:
        void SetUp() override {
            core = MockMonitoringServiceCore::make();
            EXPECT_TRUE(core->initialize(nullptr));
        }
        std::shared_ptr<MockMonitoringServiceCore> core { nullptr };
};

TEST_F(TestMonitoringServiceCore, simpleAcceptSubscription) {
    EventIds eventids = {
        EventId::TCP_NONSYN_LRUMISS
    };
    auto res = core->acceptSubscription(eventids);
    EXPECT_EQ(res.status, ResponseStatus::OK);
}

TEST_F(TestMonitoringServiceCore, simpleErrors) {
    EventIds eventids = {
        EventId::UNKNOWN
    };

    auto res1 = core->acceptSubscription(eventids);
    EXPECT_EQ(res1.status, ResponseStatus::NOT_SUPPORTED);

    EventIds emptyEventids = {
    };

    auto res2 = core->acceptSubscription(emptyEventids);
    EXPECT_EQ(res2.status, ResponseStatus::OK);
    EXPECT_FALSE(res2.events.has_value());

    core->set_limit(0);
    EventIds gooadEventids = {
        EventId::PACKET_TOOBIG
    };

    auto res3 = core->acceptSubscription(gooadEventids);
    EXPECT_EQ(res3.status, ResponseStatus::TOOMANY_CLIENTS);
}

//测试交集功能
TEST_F(TestMonitoringServiceCore, EventIntersection) {
    EventIds eventids = {
        EventId::UNKNOWN,
        EventId::TCP_NONSYN_LRUMISS
    };

    EventIds ExpectEventids = {
        EventId::TCP_NONSYN_LRUMISS
    };

    auto res = core->acceptSubscription(eventids);
    EXPECT_EQ(res.status, ResponseStatus::OK);
    EXPECT_TRUE(res.events.has_value());
    EXPECT_EQ(res.events.value(), ExpectEventids);
}

//测试客户id计数功能
TEST_F(TestMonitoringServiceCore, ThreadsClients) {
    EventIds group1Eventids = {
        EventId::TCP_NONSYN_LRUMISS
    };

    EventIds group2Eventids = {
        EventId::PACKET_TOOBIG
    };

    std::vector<std::thread> threads_;
    folly::Synchronized<std::vector<uint32_t>>cids_;

    for(int i = 0; i < 30; i++) {
        threads_.push_back(std::thread([&]() mutable {
            ClientId cid;
            if(folly::Random::rand32() % 2 == 0) {
                auto res = core->acceptSubscription(group1Eventids);
                EXPECT_EQ(res.status, ResponseStatus::OK);
                EXPECT_TRUE(res.events.has_value());
                EXPECT_EQ(res.events.value(), group1Eventids);
                EXPECT_TRUE(res.cid.has_value());
                cid = *res.cid;
            } else {
                auto res = core->acceptSubscription(group2Eventids);
                EXPECT_EQ(res.status, ResponseStatus::OK);
                EXPECT_TRUE(res.events.has_value());
                EXPECT_EQ(res.events.value(), group2Eventids);
                EXPECT_TRUE(res.cid.has_value());
                cid = *res.cid;
            }
            //先设置锁
            auto cids = cids_.wlock();
            cids->push_back(cid);
        }));
    }

    for(int i = 0; i < 30; i++) {
        threads_[i].join();
    }

    //再拉不大函数中一直保有锁
    cids_.withWLock([](auto& client_ids) {
        EXPECT_EQ(client_ids.size(), 30);
        std::sort(client_ids.begin(), client_ids.end(), std::less<uint32_t>());
        for(int i = 0; i < 30; i++) {
            EXPECT_EQ(client_ids[i], i);
        }
    });
}
TEST_F(TestMonitoringServiceCore, SubscribeAndCancel) {
    EventIds eventids = {
        EventId::TCP_NONSYN_LRUMISS
    };

    auto submock = std::make_shared<MockClientSubscription>();
    auto res = core->acceptSubscription(eventids);
    EXPECT_EQ(res.status, ResponseStatus::OK);
    EXPECT_TRUE(res.events.has_value());
    EXPECT_TRUE(res.sub_cb_.has_value());
    EXPECT_TRUE(res.cid.has_value());
    EXPECT_EQ(res.events.value().size(), 1);

    auto cid = *res.cid;
    EXPECT_TRUE(res.sub_cb_.value()->onClientSubscribed(
        *res.cid,
        submock,
        *res.events
    ));
    EXPECT_TRUE(core->has_Client(cid));
    res.sub_cb_.value()->onClientCanceled(cid);
    EXPECT_FALSE(core->has_Client(cid));
}

int main(int argc, char** argv) {
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
