g++ -Wall -g -std=c++17 -I/include/ -o grpc \
    /home/jianglei/czkatran/czkatran/example_grpc/czkatran_server.cc\
    /home/jianglei/czkatran/czkatran/example_grpc/GrpcSingalHandler.cc\
    /home/jianglei/czkatran/czkatran/example_grpc/czKatranGrpcSerice.cc\
    /home/jianglei/czkatran/czkatran/lib/BaseBpfAdapter.cc\
    /home/jianglei/czkatran/czkatran/lib/BpfAdapter.cc\
    /home/jianglei/czkatran/czkatran/lib/Testing/Base64Helpers.cc\
    /home/jianglei/czkatran/czkatran/lib/Vip.cc\
    /home/jianglei/czkatran/czkatran/lib/czkatranSimulator.cc\
    /home/jianglei/czkatran/czkatran/lib/MaglevBase.cc\
    /home/jianglei/czkatran/czkatran/lib/FileWriter.cc\
    /home/jianglei/czkatran/czkatran/lib/IOBuffWriter.cc\
    /home/jianglei/czkatran/czkatran/lib/IpHelpers.cc\
    /home/jianglei/czkatran/czkatran/lib/MacHelpers.cc\
    /home/jianglei/czkatran/czkatran/lib/PerfBufferEventReader.cc\
    /home/jianglei/czkatran/czkatran/lib/czKatranEventReader.cc\
    /home/jianglei/czkatran/czkatran/lib/EventPipeCallback.cc\
    /home/jianglei/czkatran/czkatran/lib/MonitoringServiceCore.cc\
    /home/jianglei/czkatran/czkatran/lib/BpfLoader2.cc\
    /home/jianglei/czkatran/czkatran/lib/CHHelper.cc\
    /home/jianglei/czkatran/czkatran/lib/czKatanMonitor.cc\
    /home/jianglei/czkatran/czkatran/lib/czkatranLb.cc\
    /home/jianglei/czkatran/czkatran/lib/MaglevHash.cc\
    /home/jianglei/czkatran/czkatran/lib/MaglevHashV2.cc\
    /home/jianglei/czkatran/czkatran/lib/MurmurHash3.cc\
    /home/jianglei/czkatran/czkatran/lib/Netlink.cc\
    /home/jianglei/czkatran/czkatran/lib/MonitoringStructs.cc\
    /home/jianglei/czkatran/czkatran/lib/Testing/BpfTester.cc\
    /home/jianglei/czkatran/czkatran/lib/Testing/PcapParser.cc\
    /home/jianglei/czkatran/czkatran/lib/PipeWriter.cc\
    /home/jianglei/czkatran/czkatran/lib/PcapWriter.cc\
    /home/jianglei/czkatran/czkatran/lib/PcapMsgMeta.cc\
    /home/jianglei/czkatran/czkatran/lib/PcapMsg.cc\
    -lpthread \
    -lfolly \
    -lglog \
    -lfmt \
    -lbpf \
    -lmnl \
    -ldouble-conversion \
    -levent \
    -liberty \
    -lgflags \
    -lgrpc++ \
    -lgpr \
    -lgrpc_unsecure \
    -labsl_base \
    -labsl_cord \
    -labsl_node_hash_set \
    -labsl_random_random \
    -labsl_statusor \
    -lprotobuf \
    -ldl \
    -lz 

