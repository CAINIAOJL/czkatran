#include <gflags/gflags.h>
#include <algorithm>
#include <iostream>
#include <vector>


#include "CHHelper.h"

DEFINE_int64(weight, 100, "weight per real");
DEFINE_int64(freq, 1, "how often real would have diff weight");
DEFINE_int64(diffweight, 1, "number of different weights");
DEFINE_int64(nreals, 400, "number of reals");
DEFINE_int64(npos, -1, "position of real to be moved");
DEFINE_bool(v2, false, "use v2");


int main(int argc, char** argv) {
    gflags::ParseCommandLineFlags(&argc, &argv, true);
    std::vector<czkatran::Endpoint> endpoints;
    std::vector<uint32_t> freq(FLAGS_nreals, 0);
    czkatran::Endpoint endpoint;

    double n1 = 0;
    double n2 = 0;


    for(int i = 0; i < FLAGS_nreals; i++) {
        endpoint.num = i;
        endpoint.hash = 10 * i;
        if(i & FLAGS_freq == 0) { //是否是第一个序号
            endpoint.weight = FLAGS_weight;
        } else {
            endpoint.weight = FLAGS_diffweight;
        }
        endpoints.push_back(endpoint);
    }

    auto ch = czkatran::HashFunction::Maglev;
    if(FLAGS_v2) {
        ch = czkatran::HashFunction::Maglev2;
    }

    auto maglev_hashing = czkatran::CHFactory::make(ch); //创建工厂
    auto ch1 = maglev_hashing->generateHashRing(endpoints);

    int deleted_real_num{0};
    if(FLAGS_npos >= 0 && FLAGS_npos < FLAGS_nreals) {
        endpoints.erase(endpoints.begin() + FLAGS_npos);
        deleted_real_num = FLAGS_npos;
    } else {
        deleted_real_num = FLAGS_nreals - 1;
        endpoints.pop_back();
    }
    //调整过后的endpoints
    auto ch2 = maglev_hashing->generateHashRing(endpoints);


    for(int i = 0; i < ch1.size(); i++) {
        freq[ch1[i]]++;
    }

    std::vector<uint32_t> sort_freq(freq);

    std::sort(sort_freq.begin(), sort_freq.end());

    std::cout << "min freq is " << sort_freq[0]
              << " max freq is " << sort_freq[sort_freq.size() - 1] << std::endl;

    
    std::cout << "p95 w: " << sort_freq[(sort_freq.size() / 20) * 19]
              << "\np75 w: " << sort_freq[(sort_freq.size() / 20) * 15]
              << "\np50 w: " << sort_freq[sort_freq.size() / 2]
              << "\np25 w: " << sort_freq[sort_freq.size() / 4]
              << "\np5 w: " << sort_freq[sort_freq.size() / 20] << std::endl;

    for(int i = 0; i < ch1.size(); i++) {
        if (ch1[i] != ch2[i]) {
            if(ch1[i] == deleted_real_num) {
                n1++;
                continue;
            }
            n2++;
        }
    }
    std::cout << "changes for affected real: " << n1 << "; and for not affected "
            << n2 << " this is: " << n2 / ch1.size() * 100 << "%\n";
    return 0;
    //2025-1-7-22:00
}


/*#include <gflags/gflags.h>
#include <algorithm>
#include <iostream>
#include <vector>

#include "CHHelper.h"

DEFINE_int64(weight, 100, "weights per real");
DEFINE_int64(freq, 1, "how often real would have diff weight");
DEFINE_int64(diffweight, 1, "diff weight for test");
DEFINE_int64(nreals, 400, "number of reals");
DEFINE_int64(npos, -1, "position to delete");
DEFINE_bool(v2, false, "use v2 of maglev hash");
int main(int argc, char** argv) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);

  std::vector<czkatran::Endpoint> endpoints;
  std::vector<uint32_t> freq(FLAGS_nreals, 0);
  czkatran::Endpoint endpoint;
  double n1 = 0;
  double n2 = 0;

  for (int i = 0; i < FLAGS_nreals; i++) {
    endpoint.num = i;
    endpoint.hash = 10 * i;
    if (i % FLAGS_freq == 0) {
      endpoint.weight = FLAGS_weight;
    } else {
      endpoint.weight = FLAGS_diffweight;
    }
    endpoints.push_back(endpoint);
  }
  auto hash_func = czkatran::HashFunction::Maglev;
  if (FLAGS_v2) {
    hash_func = czkatran::HashFunction::Maglev2;
  }
  auto maglev_hashing = czkatran::CHFactory::make(hash_func);
  auto ch1 = maglev_hashing->generateHashRing(endpoints);

  int deleted_real_num{0};
  if (FLAGS_npos >= 0 && FLAGS_npos < FLAGS_nreals) {
    endpoints.erase(endpoints.begin() + FLAGS_npos);
    deleted_real_num = FLAGS_npos;
  } else {
    deleted_real_num = FLAGS_nreals - 1;
    endpoints.pop_back();
  }
  auto ch2 = maglev_hashing->generateHashRing(endpoints);

  for (int i = 0; i < ch1.size(); i++) {
    freq[ch1[i]]++;
  }

  std::vector<uint32_t> sorted_freq(freq);

  std::sort(sorted_freq.begin(), sorted_freq.end());

  std::cout << "min freq is " << sorted_freq[0] << " max freq is "
            << sorted_freq[sorted_freq.size() - 1] << std::endl;

  std::cout << "p95 w: " << sorted_freq[(sorted_freq.size() / 20) * 19]
            << "\np75 w: " << sorted_freq[(sorted_freq.size() / 20) * 15]
            << "\np50 w: " << sorted_freq[sorted_freq.size() / 2]
            << "\np25 w: " << sorted_freq[sorted_freq.size() / 4]
            << "\np5 w: " << sorted_freq[sorted_freq.size() / 20] << std::endl;

  for (int i = 0; i < ch1.size(); i++) {
    if (ch1[i] != ch2[i]) {
      if (ch1[i] == deleted_real_num) {
        n1++;
        continue;
      }
      n2++;
    }
  }

  std::cout << "changes for affected real: " << n1 << "; and for not affected "
            << n2 << " this is: " << n2 / ch1.size() * 100 << "%\n";

  return 0;
}*/