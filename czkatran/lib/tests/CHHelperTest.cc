#include <gtest/gtest.h>
#include <algorithm>
#include <vector>

#include "/home/jianglei/czkatran/czkatran/lib/CHHelper.h"

namespace czkatran {

constexpr uint32_t nreals = 400; //400个真实的样本
constexpr uint32_t nreals_diff_weight = 3; //3个不同的权重

TEST(CHHelperTest, testMaglevCHSameWeight) {
    std::vector<Endpoint> Endpoints;
    std::vector<uint32_t> freq(nreals, 0);
    Endpoint Endpoint;

    for(int i =0; i < nreals; i++) {
        Endpoint.num = i;
        Endpoint.weight = 1;
        Endpoint.hash = i;
        Endpoints.push_back(Endpoint);
    }

    auto maglev_hashing = CHFactory::make(HashFunction::Maglev);
    auto maglev_ch = maglev_hashing->generateHashRing(Endpoints);

    for(int i = 0; i < maglev_ch.size(); i++) {
        ASSERT_NE(maglev_ch[i], -1);
        freq[maglev_ch[i]]++;
    }

    std::sort(freq.begin(), freq.end());

    auto diff = freq[freq.size() - 1] - freq[0];

    ASSERT_EQ(diff, 1); // 差距为1，说明权重相同的CH均匀分布
}

TEST(CHHelpersTest, testMaglevV2CHSameWeight) {
    std::vector<Endpoint> Endpoints;
    std::vector<uint32_t> freq(nreals, 0);
    Endpoint Endpoint;

    for(int i =0; i < nreals; i++) {
        Endpoint.num = i;
        Endpoint.weight = 1;
        Endpoint.hash = i;
        Endpoints.push_back(Endpoint);
    }

    auto maglev_hashing = CHFactory::make(HashFunction::Maglev2);
    auto maglev_ch = maglev_hashing->generateHashRing(Endpoints);

    for(int i = 0; i < maglev_ch.size(); i++) {
        ASSERT_NE(maglev_ch[i], -1);
        freq[maglev_ch[i]]++;
    }

    std::sort(freq.begin(), freq.end());

    auto diff = freq[freq.size() - 1] - freq[0];

    ASSERT_EQ(diff, 1); // 差距为1，说明权重相同的CH均匀分布
}

TEST(CHHelpersTest, testMaglevCHDiffWeight) {
    std::vector<Endpoint> Endpoints;
    Endpoint Endpoint;
    std::vector<uint32_t> freq(nreals_diff_weight, 0);

    for(int i = 0; i < nreals_diff_weight; i++) {
        Endpoint.num = i;
        Endpoint.weight = 1;
        Endpoint.hash = i;
        Endpoints.push_back(Endpoint);
    }
    //假设这个后端节点的权重为2，和另外两个权重不一致
    Endpoints[0].weight = 2;

    auto maglev_hashing = CHFactory::make(HashFunction::Maglev);
    auto maglev_ch = maglev_hashing->generateHashRing(Endpoints);

    for(int i = 0; i < maglev_ch.size(); i++) {
        ASSERT_NE(maglev_ch[i], -1);
        freq[maglev_ch[i]]++;
    }

    std::sort(freq.begin(), freq.end());

    auto diff = freq[freq.size() - 1] - freq[0];

    ASSERT_EQ(diff, 2); // 差距为2，说明权重不同的CH均匀分布
}

TEST(CHHelpersTest, testMaglevV2CHDiffWeight) {
    std::vector<Endpoint> Endpoints;
    Endpoint Endpoint;
    std::vector<uint32_t> freq(nreals_diff_weight, 0);

    for(int i = 0; i < nreals_diff_weight; i++) {
        Endpoint.num = i;
        Endpoint.weight = 1;
        Endpoint.hash = i;
        Endpoints.push_back(Endpoint);
    }
    //假设这个后端节点的权重为2，和另外两个权重不一致
    Endpoints[0].weight = 2;

    auto maglev_hashing = CHFactory::make(HashFunction::Maglev2);
    auto maglev_ch = maglev_hashing->generateHashRing(Endpoints);

    for(int i = 0; i < maglev_ch.size(); i++) {
        ASSERT_NE(maglev_ch[i], -1);
        freq[maglev_ch[i]]++;
    }

    std::sort(freq.begin(), freq.end());

    auto diff = freq[freq.size() - 1] - freq[0];

    ASSERT_EQ(diff, 16385); // 差距为16385，说明权重不同的CH均匀分布
}

TEST(CHHelpersTest, testMaglevWeightsSumLargerThanRing) {
    std::vector<Endpoint> endpoints;
    std::vector<uint32_t> freq(nreals, 0);
    Endpoint endpoint;
    uint32_t weight = (kDefaultChRingSize * 2) / nreals;
    for (int i = 0; i < nreals; i++) {
        endpoint.num = i;
        endpoint.weight = weight;
        endpoint.hash = i;
        endpoints.push_back(endpoint);
    }

    auto maglev_hashing = CHFactory::make(HashFunction::Maglev);

    auto maglev_ch = maglev_hashing->generateHashRing(endpoints);

    for (int i = 0; i < maglev_ch.size(); i++) {
        // test that we have changed all points inside ch ring
        ASSERT_NE(maglev_ch[i], -1);
        freq[maglev_ch[i]]++;
    }

    int realWithFullSlots = (nreals / 2);
    int realsWithPartialSlots = 1;
    for(int i = 0; i < freq.size(); i++) {
        if(i < realWithFullSlots) {
            EXPECT_EQ(freq[i], weight);
        } else if (i < realWithFullSlots + realsWithPartialSlots) {
            EXPECT_GT(freq[i], 0);
        } else {
            EXPECT_EQ(freq[i], 0);
        }
    }
}

TEST(CHHelpersTest, testMaglevWeightsSumBelowRingSize) {
    std::vector<Endpoint> endpoints;
    std::vector<uint32_t> freq(nreals, 0);
    Endpoint endpoint;

    uint32_t weight = (kDefaultChRingSize / nreals) - 1;
    for (int i = 0; i < nreals; i++) {
        endpoint.num = i;
        endpoint.weight = weight;
        endpoint.hash = i;
        endpoints.push_back(endpoint);
    }

    auto maglev_hashing = CHFactory::make(HashFunction::Maglev2);

    auto maglev_ch = maglev_hashing->generateHashRing(endpoints);

    for(int i = 0; i < maglev_ch.size(); i++) {
        ASSERT_NE(maglev_ch[i], -1);
        freq[maglev_ch[i]]++;
    }

    std::sort(freq.begin(), freq.end());

    auto diff = freq[freq.size() - 1] - freq[0];

    EXPECT_EQ(diff, 1); // equal to 1
    EXPECT_GT(freq[0], 0); //greater than 0
}

}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}