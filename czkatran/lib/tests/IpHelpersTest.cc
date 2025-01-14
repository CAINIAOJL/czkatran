#include <gtest/gtest.h>

#include "/home/jianglei/czkatran/czkatran/lib/IpHelpers.h"


namespace czkatran {


TEST(IpHelpersTest, testV4ParseBe) {
    auto addr = IpHelpers::parseAddrToBe("1.1.1.2");
    ASSERT_EQ(addr.flags, 0);
    ASSERT_EQ(addr.daddr, 33620225);
}

TEST(IpHelpersTest, testV6ParseBe) {
    auto addr = IpHelpers::parseAddrToBe("2401:db00:f01c:2002:face:0:d:0");
    ASSERT_EQ(addr.flags, 1);
    ASSERT_EQ(addr.v6daddr[0], 14352676);
    ASSERT_EQ(addr.v6daddr[1], 35658992);
    ASSERT_EQ(addr.v6daddr[2], 52986);
    ASSERT_EQ(addr.v6daddr[3], 3328);
}

TEST(IpHelpersTest, testV4ParseInt) {
    auto addr = IpHelpers::parseAddrToInt("1.1.1.2");
    ASSERT_EQ(addr.flags, 0);
    ASSERT_EQ(addr.daddr, 16843010); //大端序和小端序的问题
}

TEST(IpHelpersTests, testV6ParsingInt) {
    auto addr = IpHelpers::parseAddrToInt("2401:db00:f01c:2002:face:0:d:0");
    ASSERT_EQ(addr.flags, 1);
    ASSERT_EQ(addr.v6daddr[0], 604101376);
    ASSERT_EQ(addr.v6daddr[1], 4028375042);
    ASSERT_EQ(addr.v6daddr[2], 4207804416);
    ASSERT_EQ(addr.v6daddr[3], 851968);
}

TEST(IpHelpersTest, testIncorrectAddr) {
    int i = 1;
    try {
        IpHelpers::parseAddrToBe("woshicainiao");
        i = 2;
    } catch (...) {
        i = 1;
    }
    ASSERT_EQ(i, 1);
}

}

int main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}