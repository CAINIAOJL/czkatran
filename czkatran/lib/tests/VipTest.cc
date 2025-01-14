#include "/home/jianglei/czkatran/czkatran/lib/Vip.h"

#include <folly/init/Init.h>
#include <folly/Portability.h>
#include <folly/portability/GFlags.h>
#include <folly/portability/GTest.h>

#include <gtest/gtest.h>
#include <algorithm>
#include <iostream>


namespace czkatran {

class VipTestF : public ::testing::Test {
 protected:
    VipTestF() :
        vip1(1),
        vip2(2, 0, kDefaultChRingSize, HashFunction::Maglev2),
        real(100) {}

    void SetUp() override {
        UpdateReal ureal;
        ureal.action = ModifyAction::ADD;

        for(int i = 0; i < 100; i++) {
            ureal.updateReal.num = i;
            ureal.updateReal.weight = 10;
            ureal.updateReal.hash = i;
            real[i] = ureal;
        }
    }

    Vip vip1;
    Vip vip2;
    std::vector<UpdateReal> real;
};

TEST_F(VipTestF, testBatchUpdateReals) {
    auto dalta = vip1.batchRealsupdate(real);
    auto dalta2 = vip2.batchRealsupdate(real);
    //比较hashring的大小是否一致
    ASSERT_EQ(dalta.size(), vip1.getRingSize());
    ASSERT_EQ(dalta2.size(), vip2.getRingSize());

    dalta = vip1.batchRealsupdate(real);
    dalta2 = vip2.batchRealsupdate(real);
    ASSERT_EQ(dalta.size(), 0);
    ASSERT_EQ(dalta2.size(), 0);

    dalta = vip1.delReal(0);
    dalta2 = vip2.delReal(0);
    ASSERT_EQ(dalta.size(), 1009);
    ASSERT_EQ(dalta2.size(), 1020);
}

TEST_F(VipTestF, testBatchUpdateRealsWeight) {
    auto dalta = vip1.batchRealsupdate(real);
    auto dalta2 = vip2.batchRealsupdate(real);
    //比较hashring的大小是否一致
    ASSERT_EQ(dalta.size(), vip1.getRingSize());
    ASSERT_EQ(dalta2.size(), vip2.getRingSize());

    
    dalta = vip1.batchRealsupdate(real);
    dalta2 = vip2.batchRealsupdate(real);
    ASSERT_EQ(dalta.size(), 0);
    ASSERT_EQ(dalta2.size(), 0);

    for(auto& real : real) {
        real.updateReal.weight = 13;
    }

    dalta = vip1.batchRealsupdate(real);
    dalta2 = vip2.batchRealsupdate(real);

    ASSERT_EQ(dalta.size(), 17);
    ASSERT_EQ(dalta2.size(), 0);

    real[0] = UpdateReal{ModifyAction::ADD, {0, 26, 0}};
    dalta = vip1.batchRealsupdate(real);
    dalta2 = vip2.batchRealsupdate(real);
    ASSERT_EQ(dalta.size(), 109);
    ASSERT_EQ(dalta2.size(), 1013);
}

TEST(VipTest, testAddRemoveReal) {
    Vip vip(1);
    Endpoint real;
    real.num = 0;
    real.weight = 1;
    real.hash = 0;
    auto dalta = vip.addReal(real);
    ASSERT_EQ(dalta.size(), vip.getRingSize());
    real.num = 1;
    real.hash = 1;
    dalta = vip.addReal(real);
    ASSERT_EQ(dalta.size(), 32768);
    dalta = vip.delReal(1);
    ASSERT_EQ(dalta.size(), 32768);
    dalta = vip.delReal(1); //删除不存在的real
    ASSERT_EQ(dalta.size(), 0);   
}

TEST_F(VipTestF, testGetRealAndWeight) {
    vip1.batchRealsupdate(real);
    auto endpoints = vip1.getRealsAndWeights();
    ASSERT_EQ(endpoints.size(), 100);
    for(auto &real : endpoints) {
        ASSERT_EQ(real.weight, 10);
    }
}

TEST_F(VipTestF, testGetReals) {
    auto dalta = vip1.batchRealsupdate(real);
    auto vip_reals = vip1.getReals();
    ASSERT_EQ(vip_reals.size(), 100);
    ASSERT_EQ(dalta.size(), kDefaultChRingSize);
    dalta = vip1.batchRealsupdate(real);
    ASSERT_EQ(dalta.size(), 0);
    dalta = vip1.recalculateHashRing();
    ASSERT_EQ(dalta.size(), 0);
}
}

/*
 * This is the recommended main function for all tests.
 * The Makefile links it into all of the test programs so that tests do not need
 * to - and indeed should typically not - define their own main() functions
 */
FOLLY_ATTR_WEAK int main(int argc, char** argv);

int main(int argc, char** argv) {
#if FOLLY_HAVE_LIBGFLAGS
  // Enable glog logging to stderr by default.
  gflags::SetCommandLineOptionWithMode(
      "logtostderr", "1", gflags::SET_FLAGS_DEFAULT);
#endif

  ::testing::InitGoogleTest(&argc, argv);
  folly::Init init(&argc, &argv);

  return RUN_ALL_TESTS();
}