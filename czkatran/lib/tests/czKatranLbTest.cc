#include <fmt/core.h>
#include <gtest/gtest.h>

#include "../czkatranLb.h"
/*
struct czKatranConfig {
  std::string mainInterface;
  std::string v4TunInterface = kDefaultHcInterface;
  std::string v6TunInterface = kDefaultHcInterface;
  std::string balancerProgPath;
  std::string healthcheckingProgPath;
  std::vector<uint8_t> defaultMac;
  uint32_t priority = kDefaultPriority;
  std::string rootMapPath = kNoExternalMap;
  uint32_t rootMapPos = kDefaultKatranPos;
  bool enableHc = true;
  bool tunnelBasedHCEncap = true;
  uint32_t maxVips = kDefaultMaxVips;
  uint32_t maxReals = kDefaultMaxReals;
  uint32_t chRingSize = kLbDefaultChRingSize;
  bool testing = false;
  uint64_t LruSize = kDefaultLruSize;
  std::vector<int32_t> forwardingCores;
  std::vector<int32_t> numaNodes;
  uint32_t maxLpmSrcSize = kDefaultMaxLpmSrcSize;
  uint32_t maxDecapDst = kDefaultMaxDecapDstSize;
  std::string hcInterface = kDefaultHcInterface;
  uint32_t xdpAttachFlags = kNoFlags;
  struct czKatranMonitorConfig monitorConfig;
  bool memlockUnlimited = true;
  std::string katranSrcV4 = kAddressNotSpecified;
  std::string katranSrcV6 = kAddressNotSpecified;
  std::vector<uint8_t> localMac;
  HashFunction hashFunction = HashFunction::Maglev;
  bool flowDebug = false;
  uint32_t globalLruSize = kDefaultGlobalLruSize;
  bool useRootMap = true;
  bool enableCidV3 = false;
  uint32_t mainInterfaceIndex = kUnspecifiedInterfaceIndex;
  uint32_t hcInterfaceIndex = kUnspecifiedInterfaceIndex;
  bool cleanupOnShutdown = true;
};
*/


namespace czkatran {
constexpr int kMaxRealTest = 4096;
constexpr int kMaxNumOfReals = kMaxRealTest - 1;

class czKatranLbTest : public ::testing::Test {
    protected:
        //czKantranLb构造函数需要czKatranConfig&设置
        czKatranLbTest() {
            czKatranConfig czKatranconfig_ {
                "eth0", //mainInterface
                //数据包：【【Ethhdr】【【iphdr】【iphdr】】
                "ipip0", //v4TunInterface
                //数据包： 【Ethhdr】【iphdr】【iphdr/ipv6hdr】【payload】
                //数据包： 【Ethhdr】【ipv6hdr】【iphdr/ipv6hdr】【payload】
                "ipip60", //v6TunInterface
                "./balancer.o", //balancerProgPath
                "./healthchecking.o", //healthcheckingProgPath
                {0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E}, //defaultMac
                1, //priority
                "", //rootMapPath
                1, //rootMapPos
                true, //enableHc
                false, //tunnelBasedEncap
                512, //maxVips
                kMaxRealTest, //maxReals
                65537, //chRingSize
                true, //testing
                1, //LruSize
                {}, //forwardingCores
                {}, //numaNodes,
                10, //maxLpmSrcSize,
                4,//maxDecapDst,
                "eth0", //hcInterface
                0, //xdpAttachFlags
                {}, //monitorConfig
                false, //memlockUnlimited
                {}, //localMac
            };
            lb = 
                std::make_unique<czKatranLb>(czKatranconfig_, 
                                                    std::make_unique<czkatran::BpfAdapter>(czKatranconfig_.memlockUnlimited));
        }
        
        void SetUp() override {
            v1.address = "fc01::1"; //ipv6地址
            v1.port = 443; //端口
            v1.proto = 6; //协议

            v2.address = "fc01::2";
            v2.port = 443;
            v2.proto = 6;

            r1.address = "192.168.1.1";
            r1.weight = 10; //权重
            r2.address = "fc00::1";
            r2.weight = 12;
            
            //增加了4096个后端服务器
            NewReal real1, real2;
            QuicReal qreal1, qreal2;

            for(int i = 0; i < 16; i++) {
                for(int j = 0; j < 256; j++) {
                    auto k = 256 * i + j;
                    if (k < kMaxNumOfReals) {
                        real1.address = fmt::format("10.0.{}.{}", i, j);
                        newReals1.push_back(real1);
                        real2.address = fmt::format("10.1.{}.{}", i, j);
                        newReals2.push_back(real2);
                        qreal1.address = real1.address;
                        qreal2.address = real2.address;
                        qreal1.id = k;
                        qreal2.id = k;
                        qReals1.push_back(qreal1);
                        qReals2.push_back(qreal2);
                    }
                }
            } 
        }

    std::unique_ptr<czKatranLb> lb;
    //两个虚拟IP
    VipKey v1;
    VipKey v2;
    //两个后端服务器
    NewReal r1;
    NewReal r2;

    std::vector<NewReal> newReals1; //10.0.{}.{}
    std::vector<NewReal> newReals2; //10.1.{}.{}

    std::vector<QuicReal> qReals1;
    std::vector<QuicReal> qReals2;
};

TEST_F(czKatranLbTest, testChangeMac) {
    std::vector<uint8_t> newMac = {0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0F};
    ASSERT_EQ(lb->changeMac(newMac), true);
    auto default_mac = lb->getMac();
    ASSERT_EQ(default_mac.size(), 6);
    ASSERT_EQ(default_mac, newMac);
    for(int i = 0; i < 6; i++) {
        default_mac[i] = newMac[i];
    }
}

TEST_F(czKatranLbTest, testIfindex) {
    auto ifindexs = lb->getIndexOfNetworkInterfaces();
    ASSERT_EQ(ifindexs.size(), 2);
    auto it = ifindexs.find(kHcIntfPos);
    ASSERT_FALSE(it == ifindexs.end());
    it = ifindexs.find(kMainIntfPos);
    ASSERT_FALSE(it == ifindexs.end());
    it = ifindexs.find(kIpv4TunPos);
    ASSERT_TRUE(it == ifindexs.end());
    it = ifindexs.find(kIpv6TunPos);
    ASSERT_TRUE(it == ifindexs.end());
}

TEST_F(czKatranLbTest, testVipHelpers) {
    VipKey v3;
    v3.address = "fc00::3";
    v3.port = 0;
    v3.proto = 6;
    ASSERT_FALSE(lb->delVip(v1));

    ASSERT_TRUE(lb->addVip(v2));
    ASSERT_TRUE(lb->delVip(v2));

    for(int i = 0; i < 512; i++) {
        v3.port = i;
        ASSERT_TRUE(lb->addVip(v3));
    }
    v3.port = 1000; //大于maxVips
    ASSERT_FALSE(lb->addVip(v3));
}

TEST_F(czKatranLbTest, testAddingInvalidVip) {
    VipKey v;
    v.address = "fc00::/64"; //无效的IP地址,网络地址，不是主机ip地址
    v.port = 0;
    v.proto = 6;
    ASSERT_FALSE(lb->addVip(v));
}

TEST_F(czKatranLbTest, testRealHelpers) {
    lb->addVip(v1);
    ASSERT_TRUE(lb->deleteRealForVip(r1, v1));
    ASSERT_FALSE(lb->addRealForVip(r1, v2));//删除不存在的后端服务器
    ASSERT_TRUE(lb->addRealForVip(r1, v1));
}

TEST_F(czKatranLbTest, testRealFlags) {
    lb->addVip(v1);
    lb->addRealForVip(r1, v1);

    ASSERT_TRUE(lb->modifyReal(r1.address, 0xf0, true));
    ASSERT_FALSE(lb->modifyReal("1.2.3.4", 0xff, true));

    lb->modifyReal(r1.address, 0xff, true);
    auto reals = lb->getRealsForVip(v1);
    ASSERT_EQ(reals[0].flags, 0xfe);

    lb->modifyReal(r1.address, 0x10, false);
    reals = lb->getRealsForVip(v1);
    ASSERT_EQ(reals[0].flags, 0xee);
}   

TEST_F(czKatranLbTest, testVipStatsHelper) {
    lb->addVip(v1);
    auto stats = lb->getStatsForVip(v1);
    ASSERT_EQ(stats.v1, 0);
    ASSERT_EQ(stats.v2, 0);
}

TEST_F(czKatranLbTest, testLruMissStatsHelper) {
    auto stats = lb->getLruMissStats();
    ASSERT_EQ(stats.v1, 0);
    ASSERT_EQ(stats.v2, 0);
}

TEST_F(czKatranLbTest, testHcHelper) {
    //不存在这个somark
    ASSERT_FALSE(lb->delHealthcheckerDst(1000));
    ASSERT_TRUE(lb->addHealthcheckerDst(1000, "192.168.1.1"));
    ASSERT_TRUE(lb->delHealthcheckerDst(1000));
}

TEST_F(czKatranLbTest, getVipFlags) {
    lb->addVip(v1, 2307);
    ASSERT_EQ(lb->getVipFlags(v1), 2307);
}

TEST_F(czKatranLbTest, getAllVips) {
    lb->addVip(v1);
    lb->addVip(v2);
    ASSERT_EQ(lb->getAllVips().size(), 2);
}

TEST_F(czKatranLbTest, testUpdateRealHelper) {
    lb->addVip(v1);
    lb->addVip(v2);
    ModifyAction action = ModifyAction::ADD;
    ASSERT_TRUE(lb->modifyRealsForVip(action, newReals1, v1));
    ASSERT_TRUE(lb->modifyRealsForVip(action, newReals2, v2));

    ASSERT_EQ(lb->getRealsForVip(v1).size(), kMaxNumOfReals);
    //理解为什么v2的后端服务器群的数量为0，在初始化v1时，已经将队列中的事先准备的4096个后端服务器序号（也就是说在初始化v1时，消耗完了我们定义的maxReals数量）分配给了v1
    ASSERT_EQ(lb->getRealsForVip(v2).size(), 0);

    ASSERT_TRUE(lb->modifyRealsForVip(action, newReals1, v2));
    ASSERT_EQ(lb->getRealsForVip(v2).size(), kMaxNumOfReals);

    action = ModifyAction::DEL;
    ASSERT_TRUE(lb->modifyRealsForVip(action, newReals1, v1));
    ASSERT_TRUE(lb->modifyRealsForVip(action, newReals1, v2));

    action = ModifyAction::ADD;
    ASSERT_TRUE(lb->modifyRealsForVip(action, newReals2, v2));
    ASSERT_EQ(lb->getRealsForVip(v2).size(), kMaxNumOfReals);
    ASSERT_EQ(lb->getNumToRealMap().size(), kMaxNumOfReals);
}

TEST_F(czKatranLbTest, testUpdateQuicRealsHelper) {
    lb->addVip(v1);
    lb->addVip(v2);
    ModifyAction action = ModifyAction::ADD;
    lb->modifyQuicRealsMapping(action, qReals2);
    ASSERT_TRUE(lb->modifyRealsForVip(action, newReals1, v1));
    ASSERT_TRUE(lb->modifyRealsForVip(action, newReals2, v2));

    ASSERT_EQ(lb->getRealsForVip(v1).size(), 0);
    ASSERT_EQ(lb->getRealsForVip(v2).size(), kMaxNumOfReals);
    ASSERT_EQ(lb->getQuicRealsMapping().size(), kMaxNumOfReals);

    action = ModifyAction::DEL;
    ASSERT_TRUE(lb->modifyRealsForVip(action, newReals2, v2));
    lb->modifyQuicRealsMapping(action, qReals2);
    ASSERT_EQ(lb->getQuicRealsMapping().size(), 0);

    action = ModifyAction::ADD;
    ASSERT_TRUE(lb->modifyRealsForVip(action, newReals1, v1));
    ASSERT_EQ(lb->getRealsForVip(v1).size(), kMaxNumOfReals);
}

TEST_F(czKatranLbTest, testUpdateQuicVip) {
    QuicReal real;
    std::vector<QuicReal> reals;
    real.address = "10.0.0.1";
    real.id = 1;
    reals.push_back(real);
    //reals 【{1，10.0.0.1}】
    ModifyAction action = ModifyAction::ADD;
    lb->modifyQuicRealsMapping(action, reals);
    ASSERT_EQ(lb->getQuicRealsMapping().size(), 1);

    lb->modifyQuicRealsMapping(action, reals);//相同的映射
    ASSERT_EQ(lb->getQuicRealsMapping().size(), 1);

    reals[0].address = "2.0.0.1";
    //reals 【{1，2.0.0.1}】
    lb->modifyQuicRealsMapping(action, reals);
    auto real_mapping = lb->getQuicRealsMapping();
    ASSERT_EQ(real_mapping.size(), 1);
    ASSERT_EQ(real_mapping[0].address, "2.0.0.1");
    //【{1，2.0.0.1}】

    reals[0].id = 2;
    //【{2，2.0.0.1}】
    lb->modifyQuicRealsMapping(action, reals);
    real_mapping = lb->getQuicRealsMapping();
    ASSERT_EQ(real_mapping.size(), 2);
    ASSERT_EQ(real_mapping[0].address, "2.0.0.1");
    ASSERT_EQ(real_mapping[1].address, "2.0.0.1");

    //mapping 【{1，2.0.0.1}】【{2.2.0.0.1}】
    action = ModifyAction::DEL;
    reals[0].id = 100;
    lb->modifyQuicRealsMapping(action, reals); //删除不存在的id映射
    ASSERT_EQ(lb->getQuicRealsMapping().size(), 2);

    reals[0].id = 1;
    reals[0].address = "9.9.9.9";
    lb->modifyQuicRealsMapping(action, reals);
    ASSERT_EQ(lb->getQuicRealsMapping().size(), 2);

    reals[0].id = 1;
    reals[0].address = "2.0.0.1";
    //【{1，2.0.0.1}】
    QuicReal real2;
    real2.id = 2;
    real2.address = "2.0.0.1";
    reals.emplace_back(real2);
    /*std::vector<QuicReal> newReals;
    QuicReal nr;
    nr.address = "2.0.0.1";
    nr.id = 1;
    newReals.push_back(nr);
    nr.address = "2.0.0.1";
    nr.id = 2;
    newReals.push_back(nr);*/

    //【{1，2.0.0.1}】【{2，2.0.0.1}】
    ASSERT_EQ(reals.size(), 2);
    ASSERT_EQ(reals[0].id, 1);
    ASSERT_EQ(reals[0].address, "2.0.0.1");
    ASSERT_EQ(reals[1].id, 2);
    ASSERT_EQ(reals[1].address, "2.0.0.1");
    lb->modifyQuicRealsMapping(action, reals);
    ASSERT_EQ(lb->getQuicRealsMapping().size(), 0);
    /*lb->modifyQuicRealsMapping(action, reals);
    ASSERT_EQ(lb->getQuicRealsMapping().size(), 1);
    reals[0].id = 2;
    lb->modifyQuicRealsMapping(action, reals);
    ASSERT_EQ(lb->getQuicRealsMapping().size(), 0);*/

}

TEST_F(czKatranLbTest, getRealsForVip) {
    lb->addVip(v1);
    lb->addRealForVip(r1, v1);
    lb->addRealForVip(r2, v1);
    ASSERT_EQ(lb->getRealsForVip(v1).size(), 2);
}

TEST_F(czKatranLbTest, getHealthcheckersDst) {
    lb->addHealthcheckerDst(1, "192.168.1.1");
    lb->addHealthcheckerDst(2, "198.168.1.1");
    auto hcs = lb->getHealthcheckersDst();
    ASSERT_EQ(hcs.size(), 2);
}

TEST_F(czKatranLbTest, invalidAddressHanding) {
    VipKey v;
    v.address = "aaa";
    v.port = 0;
    v.proto = 6;
    NewReal r;
    r.address = "bbb";
    r.weight = 1;

    auto res = lb->addVip(v);
    ASSERT_FALSE(res);
    res = lb->addVip(v1);
    ASSERT_TRUE(res);
    res = lb->addRealForVip(r, v1);
    //ASSERT_FALSE(res);自己加上的，错误的代码
    auto rnum = lb->getRealsForVip(v1);
    ASSERT_EQ(rnum.size(), 0);
    res = lb->addHealthcheckerDst(1, "ccc");
    ASSERT_FALSE(res);
    //ASSERT_EQ(lb->getHealthcheckersDst().size(), 0);
    auto stats = lb->getczKatranLbStats();
    ASSERT_EQ(stats.addrValidationFailed, 3);
}

TEST_F(czKatranLbTest, addInvalidSrcRoutingRule) {
    std::vector<std::string> srcsv4 = {"10.0.0.0/24", "10.0.1.0/24"};
    auto res = lb->addSrcRoutingRule(srcsv4, "abc");
    ASSERT_EQ(res, -1);
    res = lb->addSrcRoutingRule(srcsv4, "fc00::/64");
    ASSERT_EQ(res, -1);
}

TEST_F(czKatranLbTest, addValidSrcRoutingRuleV4) {
    std::vector<std::string> srcsv4 = {"10.0.0.0/24", "10.0.1.0/24"};
    auto res = lb->addSrcRoutingRule(srcsv4, "fc00::1");
    ASSERT_EQ(res, 0);
}

TEST_F(czKatranLbTest, addValidSrcRoutingRuleV6) {
    std::vector<std::string> srcsv6 = {"fc00:1::/64", "fc00:2::/64"};
    auto res = lb->addSrcRoutingRule(srcsv6, "fc00::1");
    ASSERT_EQ(res, 0);
}

TEST_F(czKatranLbTest, addMaxSrcRules) {
    std::vector<std::string> srcs;
    for(int i = 0; i < 10; i++) {
        auto ip_prefix = fmt::format("10.0.{}.0/24", i);
        srcs.push_back(ip_prefix);
    }
    auto res = lb->addSrcRoutingRule(srcs, "fc00::1");
    ASSERT_EQ(res, 0);
    auto src_rules = lb->getSrcRoutingRule();
    ASSERT_EQ(src_rules.size(), 10);
    ASSERT_EQ(lb->getSrcRoutingRuleCidr().size(), 10);
    ASSERT_EQ(lb->getSrcRoutingMap().size(), 10);
    ASSERT_EQ(lb->getNumToRealMap().size(), 1);
    auto src_iter = src_rules.find("10.0.0.0/24");
    ASSERT_TRUE(src_iter != src_rules.end());
    ASSERT_EQ(src_iter->second, "fc00::1");
}

TEST_F(czKatranLbTest, delSrcRules) {
    std::vector<std::string> srcs;
    for(int i = 0; i < 10; i++) {
        auto ip_prefix = fmt::format("10.0.{}.0/24", i);
        srcs.push_back(ip_prefix);
    }

    ASSERT_EQ(lb->addSrcRoutingRule(srcs, "fc00::1"), 0);
    ASSERT_EQ(lb->getSrcRoutingMap().size(), 10);
    ASSERT_TRUE(lb->delSrcRoutingRule(srcs));
    ASSERT_EQ(lb->getSrcRoutingMap().size(), 0);
}

TEST_F(czKatranLbTest, clearAllSrcRoutingRules) {
    std::vector<std::string> srcs;
    for(int i = 0; i < 10; i++) {
        auto ip_prefix = fmt::format("10.0.{}.0/24", i);
        srcs.push_back(ip_prefix);
    }
    ASSERT_EQ(lb->addSrcRoutingRule(srcs, "fc00::1"), 0);
    ASSERT_EQ(lb->getSrcRoutingMap().size(), 10);
    ASSERT_TRUE(lb->clearAllSrcRoutingRules());
    ASSERT_EQ(lb->getSrcRoutingMap().size(), 0);
}

TEST_F(czKatranLbTest, addFewInvalidNets) {
    std::vector<std::string> srcs;
    for(int i = 0; i < 10; i++) {
        auto ip_prefix = fmt::format("10.0.{}.0/24", i);
        srcs.push_back(ip_prefix);
    }
    srcs.push_back("aaaa");
    srcs.push_back("bbbb");

    auto res = lb->addSrcRoutingRule(srcs, "fc00::1");
    ASSERT_EQ(res, 2);
    ASSERT_EQ(lb->getSrcRoutingMap().size(), 10);
}

TEST_F(czKatranLbTest, addInvalidDecapDst) {
    ASSERT_FALSE(lb->addInlineDecapDst("aaa"));
}

TEST_F(czKatranLbTest, addInvalidDecapDstNet) {
    ASSERT_FALSE(lb->addInlineDecapDst("fc00::1/64"));
}

TEST_F(czKatranLbTest, addValidDecapDst) {
    ASSERT_TRUE(lb->addInlineDecapDst("fc00::1"));
}

TEST_F(czKatranLbTest, deleteValidDecapDst) {
    ASSERT_TRUE(lb->addInlineDecapDst("fc00::1"));
    ASSERT_TRUE(lb->delInlineDecapDst("fc00::1"));
}

TEST_F(czKatranLbTest, deleteInvalidDecapDst) {
    ASSERT_FALSE(lb->delInlineDecapDst("fc00::2"));
}

TEST_F(czKatranLbTest, addMaxDecapDst) {
    ASSERT_TRUE(lb->addInlineDecapDst("fc00::1"));
    ASSERT_TRUE(lb->addInlineDecapDst("fc00::2"));
    ASSERT_TRUE(lb->addInlineDecapDst("fc00::3"));
    ASSERT_TRUE(lb->addInlineDecapDst("fc00::4"));
    ASSERT_FALSE(lb->addInlineDecapDst("fc00::5"));
    ASSERT_EQ(lb->getInlineDecapDst().size(), 4);
}
};

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}