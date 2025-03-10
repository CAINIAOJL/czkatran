#include "/home/jianglei/czkatran/czkatran/lib/PcapWriter.h"
#include <folly/MPMCQueue.h> //多生产者，多消费者队列
#include <folly/portability/GMock.h>
#include <gtest/gtest.h>
#include <cstring>
#include <thread> //多线程
#include "/home/jianglei/czkatran/czkatran/lib/DataWriter.h"
#include "/home/jianglei/czkatran/czkatran/lib/PcapStructs.h"

using namespace ::testing;

namespace czkatran {

namespace {
using EventId = monitoring::EventId;

const struct pcap_hdr_s kPcapInvariant24 {
    .magic_number = 0xa1b2c3d4, .version_major = 2, .version_minor = 4,
    .thiszone = 0, // Gmt
    .sigfigs = 0, // Accuracy
    .snaplen = 2000, // No use
    .network = 1 // Ethernet
};
}

//继承基类，测试纯虚函数
class MockDataWriter : public DataWriter {
    public:
        MockDataWriter() = default;

        MOCK_METHOD2(writeData, void(const void*, std::size_t));
        MOCK_METHOD2(writeHeader, void(const void*, std::size_t));
        MOCK_METHOD1(available, bool(std::size_t));
        MOCK_METHOD0(restart, bool());
        MOCK_METHOD0(stop, bool());
        MOCK_METHOD0(writtenBytes, std::size_t());
};

class PcapWriterTest : public Test {
    public:
        PcapWriterTest() = default;

        void expectPcapHeader(MockDataWriter& writer) {
            EXPECT_CALL(writer, available(_)).WillRepeatedly(Return(true));
            EXPECT_CALL(writer, writeHeader(_, _))
                .Times(1)
                .WillOnce(Invoke([&](const void* ptr, std::size_t size) {
                    EXPECT_EQ(size, sizeof(struct pcap_hdr_s));
                    auto hdr = reinterpret_cast<const struct pcap_hdr_s*>(ptr);
                    EXPECT_EQ(hdr->magic_number, kPcapInvariant24.magic_number);
                    EXPECT_EQ(hdr->version_major, kPcapInvariant24.version_major);
                    EXPECT_EQ(hdr->version_minor, kPcapInvariant24.version_minor);
                    EXPECT_EQ(hdr->thiszone, kPcapInvariant24.thiszone);
                    EXPECT_EQ(hdr->sigfigs, kPcapInvariant24.sigfigs);
                    EXPECT_EQ(hdr->snaplen, 100);
                    EXPECT_EQ(hdr->network, kPcapInvariant24.network);
            }));
        }
};

//单个写入者
TEST_F(PcapWriterTest, singleWriter) {
    auto queue = std::make_shared<folly::MPMCQueue<PcapMsg>>(10);
    auto mockwriter = std::make_shared<MockDataWriter>();
    auto  pcapwriter = std::make_unique<PcapWriter>(mockwriter, 10, 100);

    const char* msg1 = "summer is better than spring";
    const char* msg2 = "birds fly south in winter";
    
    //第二步
    expectPcapHeader(*mockwriter);
    //第三步
    EXPECT_CALL(*mockwriter, writeData(_, _))
    .Times(4)
    //Pcap record header
    .WillOnce(Invoke([&](const void* ptr, std::size_t size) {
        EXPECT_EQ(size, sizeof(pcaprec_hdr_s));
        auto hdr = reinterpret_cast<const pcaprec_hdr_s*>(ptr);
        EXPECT_EQ(hdr->incl_len, 20);
        EXPECT_EQ(hdr->orig_len, 28);
    }))
    //Pcap record data
    .WillOnce(Invoke([&](const void* ptr, std::size_t size) {
        EXPECT_EQ(size, 20);
        auto msg = reinterpret_cast<const char*>(ptr);
        EXPECT_EQ(std::strncmp(msg, msg1, 20), 0);
    }))
    //Pcap record header
    .WillOnce(Invoke([&](const void* ptr, std::size_t size) {
        EXPECT_EQ(size, sizeof(pcaprec_hdr_s));
        auto rechdr = reinterpret_cast<const pcaprec_hdr_s*>(ptr);
        EXPECT_EQ(rechdr->incl_len, 24);
        EXPECT_EQ(rechdr->orig_len, 25);
    }))
    //Pcap record data
    .WillOnce(Invoke([&](const void* ptr, std::size_t size){
        EXPECT_EQ(size, 24);
        auto msg = reinterpret_cast<const char*>(ptr);
        EXPECT_EQ(std::strncmp(msg, msg2, 24), 0);
    }));

    auto readerThread = std::thread(
        [&]{
            pcapwriter->run(queue);
        }
    );

    //这是第一步
    PcapMsg pcapmsg1(msg1, 28, 20);
    PcapMsg pcapmsg2(msg2, 25, 24);
    PcapMsg emptymsg(nullptr, 0, 0);
    queue->blockingWrite(std::move(pcapmsg1));
    queue->blockingWrite(std::move(pcapmsg2));
    queue->blockingWrite(std::move(emptymsg));

    readerThread.join();
}


TEST_F(PcapWriterTest, multipleWriters) {
    auto queue = std::make_shared<folly::MPMCQueue<PcapMsgMeta>>(10);
    auto writer1 = std::make_shared<MockDataWriter>();
    auto writer2 = std::make_shared<MockDataWriter>();
    std::unordered_map<EventId, std::shared_ptr<DataWriter>> writers {
        {EventId::TCP_NONSYN_LRUMISS, writer1},
        {EventId::PACKET_TOOBIG, writer2}
    };

    auto pcapwriter = std::make_unique<PcapWriter>(writers, 10, 100);
    pcapwriter->enableEvent(EventId::TCP_NONSYN_LRUMISS);
    pcapwriter->enableEvent(EventId::PACKET_TOOBIG);

    const char* msg1 = "kiwi fruit not the bird";
    const char* msg2 = "chocolate beats coffee";

    expectPcapHeader(*writer1);
    expectPcapHeader(*writer2);

    EXPECT_CALL(*writer1, writeData(_, _))
    .Times(2)
    //Pcap record header
    .WillOnce(Invoke([&](const void* ptr, std::size_t size) {
        EXPECT_EQ(size, sizeof(pcaprec_hdr_s));
        auto hdr = reinterpret_cast<const pcaprec_hdr_s*>(ptr);
        EXPECT_EQ(hdr->incl_len, 20);
        EXPECT_EQ(hdr->orig_len, 23);
    }))
    //Pcap record data
    .WillOnce(Invoke([&](const void* ptr, std::size_t size) {
        EXPECT_EQ(size, 20);
        auto msg = reinterpret_cast<const char*>(ptr);
        EXPECT_EQ(std::strncmp(msg, msg1, 20), 0);
    }));

    EXPECT_CALL(*writer2, writeData(_, _))
    .Times(2)
    //Pcap record header
    .WillOnce(Invoke([&](const void* ptr, std::size_t size) {
        EXPECT_EQ(size, sizeof(pcaprec_hdr_s));
        auto rechdr = reinterpret_cast<const pcaprec_hdr_s*>(ptr);
        EXPECT_EQ(rechdr->incl_len, 19);
        EXPECT_EQ(rechdr->orig_len, 22);
    }))
    //Pcap record data
    .WillOnce(Invoke([&](const void* ptr, std::size_t size){
        EXPECT_EQ(size, 19);
        auto msg = reinterpret_cast<const char*>(ptr);
        EXPECT_EQ(std::strncmp(msg, msg2, 19), 0);  
    }));

    auto readerThread = std::thread(
        [&]{
            pcapwriter->runMutil(queue);
        }
    );


    PcapMsg pcapMsg1(msg1, 23, 20);
    PcapMsg pcapMsg2(msg2, 22, 19);
    PcapMsg emptyMsg(nullptr, 0, 0);
    PcapMsgMeta meta1 (std::move(pcapMsg1), static_cast<uint32_t>(EventId::TCP_NONSYN_LRUMISS));
    PcapMsgMeta meta2 (std::move(pcapMsg2), static_cast<uint32_t>(EventId::PACKET_TOOBIG));
    PcapMsgMeta emptymeta (std::move(emptyMsg), 0);

    emptymeta.setControl(true);
    emptymeta.setShutdown(true);

    queue->blockingWrite(std::move(meta1));
    queue->blockingWrite(std::move(meta2));
    queue->blockingWrite(std::move(emptymeta));

    readerThread.join();

}

}

int main(int argc, char* argv[]) {
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}