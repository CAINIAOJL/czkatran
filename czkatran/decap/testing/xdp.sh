#g++ -Wall -frtti -Wsign-compare -o xdp \
#    /home/jianglei/czkatran/czkatran/lib/BaseBpfAdapter.cc\
#    /home/jianglei/czkatran/czkatran/lib/BpfAdapter.cc\
#    /home/jianglei/czkatran/czkatran/lib/BpfLoader.cc\
#    /home/jianglei/czkatran/czkatran/lib/Testing/Base64Helpers.cc\
#    /home/jianglei/czkatran/czkatran/lib/MaglevBase.cc\
#    /home/jianglei/czkatran/czkatran/decap/testing/xdpdecap_tester.cc\
#    /home/jianglei/czkatran/czkatran/decap/XdpDecap.cc\
#    /home/jianglei/czkatran/czkatran/lib/CHHelper.cc\
#    /home/jianglei/czkatran/czkatran/lib/czkatranLb.cc\
#    /home/jianglei/czkatran/czkatran/lib/MaglevHash.cc\
#    /home/jianglei/czkatran/czkatran/lib/MaglevHashV2.cc\
#    /home/jianglei/czkatran/czkatran/lib/MurmurHash3.cc\
#    /home/jianglei/czkatran/czkatran/lib/Netlink.cc\
#    /home/jianglei/czkatran/czkatran/lib/Testing/BpfTester.cc\
#    /home/jianglei/czkatran/czkatran/lib/Testing/PcapParser.cc\
#    -lgflags -lpthread -lfolly -lglog -lfmt -lbpf -lmnl


#g++ -Wall -o xdp \
#    /home/jianglei/czkatran/czkatran/decap/testing/xdpdecap_tester.cc\
#    /home/jianglei/czkatran/czkatran/lib/Testing/Base64Helpers.cc\
#    /home/jianglei/czkatran/czkatran/lib/MaglevBase.cc\
#    /home/jianglei/czkatran/czkatran/decap/XdpDecap.cc\
#    /home/jianglei/czkatran/czkatran/lib/BpfLoader.cc\
#    /home/jianglei/czkatran/czkatran/lib/CHHelper.cc\
#    /home/jianglei/czkatran/czkatran/lib/czkatranLb.cc\
#    /home/jianglei/czkatran/czkatran/lib/MaglevHash.cc\
#    /home/jianglei/czkatran/czkatran/lib/MaglevHashV2.cc\
#    /home/jianglei/czkatran/czkatran/lib/MurmurHash3.cc\
#    /home/jianglei/czkatran/czkatran/lib/Netlink.cc\
#    /home/jianglei/czkatran/czkatran/lib/Testing/BpfTester.cc\
#    /home/jianglei/czkatran/czkatran/lib/Testing/PcapParser.cc\
#    /home/jianglei/czkatran/czkatran/lib/BaseBpfAdapter.cc\
#    /home/jianglei/czkatran/czkatran/lib/BpfAdapter.cc\
#    -lgflags -lpthread -lfolly -lglog -lfmt -lbpf -lmnl

g++ -g -Wall -o xdp \
    /home/cainiao/czkatran/czkatran/decap/testing/xdpdecap_tester.cc\
    /home/cainiao/czkatran/czkatran/lib/Testing/Base64Helpers.cc\
    /home/cainiao/czkatran/czkatran/lib/MaglevBase.cc\
    /home/cainiao/czkatran/czkatran/decap/XdpDecap.cc\
    /home/cainiao/czkatran/czkatran/lib/BpfLoader2.cc\
    /home/cainiao/czkatran/czkatran/lib/CHHelper.cc\
    /home/cainiao/czkatran/czkatran/lib/czkatranLb.cc\
    /home/cainiao/czkatran/czkatran/lib/MaglevHash.cc\
    /home/cainiao/czkatran/czkatran/lib/MaglevHashV2.cc\
    /home/cainiao/czkatran/czkatran/lib/MurmurHash3.cc\
    /home/cainiao/czkatran/czkatran/lib/Netlink.cc\
    /home/cainiao/czkatran/czkatran/lib/Testing/BpfTester.cc\
    /home/cainiao/czkatran/czkatran/lib/Testing/PcapParser.cc\
    /home/cainiao/czkatran/czkatran/lib/BaseBpfAdapter.cc\
    /home/cainiao/czkatran/czkatran/lib/BpfAdapter.cc\
    -lgflags -lpthread -lfolly -lglog -lfmt -lbpf -lmnl


g++ -Wall -g -std=c++17 -o xdp \
    /home/jianglei/czkatran/czkatran/decap/testing/xdpdecap_tester.cc\
    /home/jianglei/czkatran/czkatran/lib/Testing/Base64Helpers.cc\
    /home/jianglei/czkatran/czkatran/lib/MaglevBase.cc\
    /home/jianglei/czkatran/czkatran/decap/XdpDecap.cc\
    /home/jianglei/czkatran/czkatran/lib/BpfLoader2.cc\
    /home/jianglei/czkatran/czkatran/lib/CHHelper.cc\
    /home/jianglei/czkatran/czkatran/lib/czkatranLb.cc\
    /home/jianglei/czkatran/czkatran/lib/MaglevHash.cc\
    /home/jianglei/czkatran/czkatran/lib/MaglevHashV2.cc\
    /home/jianglei/czkatran/czkatran/lib/MurmurHash3.cc\
    /home/jianglei/czkatran/czkatran/lib/Netlink.cc\
    /home/jianglei/czkatran/czkatran/lib/Testing/BpfTester.cc\
    /home/jianglei/czkatran/czkatran/lib/Testing/PcapParser.cc\
    /home/jianglei/czkatran/czkatran/lib/BaseBpfAdapter.cc\
    /home/jianglei/czkatran/czkatran/lib/BpfAdapter.cc\
    -lgflags -lpthread -lfolly -lglog -lfmt -lbpf -lmnl
