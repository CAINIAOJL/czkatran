#include "/home/jianglei/czkatran/czkatran/lib/PipeWriter.h"
#include <gtest/gtest.h>
#include <fcntl.h>

//我们写了pipe写端的代码，那么我们测试需要读端进行配合
using namespace ::testing;

namespace {
class PipeReadCallback : public folly::AsyncReader::ReadCallback {
    public:
        bool isBufferMovable() noexcept override {
            return true;
        }

        void readBufferAvailable(std::unique_ptr<folly::IOBuf> readBuf) noexcept override {
            readBuffer_.append(std::move(readBuf));  
        }

        void readDataAvailable(size_t len) noexcept override {
            readBuffer_.postallocate(len);
        }

        void getReadBuffer(void** bufReturn, size_t* lenReturn) noexcept override {
            auto res = readBuffer_.preallocate(4000, 65000);
            *bufReturn = res.first;
            *lenReturn = res.second;
        }

        void readEOF() noexcept override {

        }

        void readErr(const folly::AsyncSocketException&) noexcept override {
            error_ = true;
        }

        std::string getData() {
            auto res = readBuffer_.move();
            res->coalesce();
            return std::string((char*)res->data(), res->length());
        }

        folly::IOBufQueue readBuffer_{folly::IOBufQueue::cacheChainLength()};
        bool error_ {false};
};

class PipeWriterTest : public Test {
    public:
        //测试启动前的初始化工作
        void SetUp() override {
            auto res = pipe2(pipefd_, O_NONBLOCK);
            EXPECT_EQ(0, res); //创建管道成功
            /*
            static UniquePtr newReader(
                folly::EventBase* eventBase, NetworkSocket pipeFd) {
                return UniquePtr(new AsyncPipeReader(eventBase, pipeFd));
            }
            */
            reader_ = folly::AsyncPipeReader::newReader(&evb_, folly::NetworkSocket::fromFd(pipefd_[0]));
            auto writer = folly::AsyncPipeWriter::newWriter(&evb_, folly::NetworkSocket::fromFd(pipefd_[1]));
            writer_ = std::move(writer);
        }

    protected:
        folly::EventBase evb_; //联系到reader_的初始化
        int pipefd_[2];
        folly::AsyncPipeReader::UniquePtr reader_ {nullptr};
        std::shared_ptr<folly::AsyncPipeWriter> writer_ {nullptr};
        PipeReadCallback readCallback_;
};

TEST_F(PipeWriterTest, SimpleWrite) {
    czkatran::PipeWriter pipeWriter;
    std::string buf = "ramen";
    reader_->setReadCB(&readCallback_);
    pipeWriter.setWriterDestination(writer_);
    pipeWriter.writeData(buf.c_str(), buf.size());
    evb_.loopOnce();
    pipeWriter.stop();
    EXPECT_EQ(readCallback_.getData(), "ramen");
    EXPECT_FALSE(readCallback_.error_);
    EXPECT_EQ(pipeWriter.getWrites(), 1);//写入成功，会触发回调函数，计数器加一
    EXPECT_EQ(pipeWriter.getErrors(), 0);//没有错误发生，计数器为0
}

//测试：stop暂停后，还能不能写入，期望是不能写入，计数器只会加一
TEST_F(PipeWriterTest, WriteAfterStop) {
    czkatran::PipeWriter pipeWriter;
    std::string buf = "ramen";
    reader_->setReadCB(&readCallback_);
    pipeWriter.setWriterDestination(writer_);
    pipeWriter.writeData(buf.c_str(), buf.size());
    pipeWriter.stop();
    pipeWriter.writeData(buf.c_str(), buf.size());
    evb_.loopOnce();
    EXPECT_EQ(readCallback_.getData(), "ramen"); //读者读到的数据是否一致
    EXPECT_FALSE(readCallback_.error_);//读者是否有错误
    EXPECT_EQ(pipeWriter.getWrites(), 1);
    EXPECT_EQ(pipeWriter.getErrors(), 0);
}
}

int main(int argc, char* argv[]) {
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}