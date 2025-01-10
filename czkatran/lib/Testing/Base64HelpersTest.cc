#include "Base64Helpers.h"

#include <folly/io/IOBuf.h>
#include <gtest/gtest.h>

//测试，往错的地方测试 
namespace czkatran {
    TEST(Base64Tests, testEncode) {
        auto input = "Test Data";
        auto iobuf = folly::IOBuf::copyBuffer(input);
        ASSERT_STREQ(Base64Helpers::base64Encode(iobuf.get()).c_str(), "VGVzdCBEYXRhIQ=="); //Test Data！
    };

    TEST(Base64Tests, testDecode) {
        auto input = "VGVzdCBEYXRhIQ==";
        ASSERT_STREQ(Base64Helpers::base64Decode(input).c_str(), "Test Data");
    }
}

int main(int argc, char** argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}