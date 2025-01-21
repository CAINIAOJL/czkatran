g++ -Wall -o MonitoringServiceCoreTest \
    /home/jianglei/czkatran/czkatran/lib/tests/MonitoringServiceCoreTest.cc \
    /home/jianglei/czkatran/czkatran/lib/MonitoringServiceCore.cc \
    /home/jianglei/czkatran/czkatran/lib/czKatanMonitor.cc \
    /home/jianglei/czkatran/czkatran/lib/BaseBpfAdapter.cc \
    /home/jianglei/czkatran/czkatran/lib/BpfAdapter.cc \
    /home/jianglei/czkatran/czkatran/lib/BpfLoader.cc \
    /home/jianglei/czkatran/czkatran/lib/MonitoringStructs.cc \
    /home/jianglei/czkatran/czkatran/lib/PerfBufferEventReader.cc\
    /home/jianglei/czkatran/czkatran/lib/czKatranEventReader.cc\
    /home/jianglei/czkatran/czkatran/lib/EventPipeCallback.cc \
    /home/jianglei/czkatran/czkatran/lib/czkatranLb.cc \
    /home/jianglei/czkatran/czkatran/lib/PipeWriter.cc \
    /home/jianglei/czkatran/czkatran/lib/FileWriter.cc \
    /home/jianglei/czkatran/czkatran/lib/IOBuffWriter.cc \
    /home/jianglei/czkatran/czkatran/lib/PcapWriter.cc \
    /home/jianglei/czkatran/czkatran/lib/PcapMsg.cc \
    /home/jianglei/czkatran/czkatran/lib/PcapMsgMeta.cc \
    /home/jianglei/czkatran/czkatran/lib/Netlink.cc \
    -std=c++17 \
    -g \
    -Wall \
    -lpthread \
    -lgtest \
    -lfolly \
    -levent \
    -lboost_filesystem \
    -liberty \
    -ldouble-conversion \
    -lglog \
    -lfmt \
    -lgflags \
    -lgmock \
    -lmnl \
    -lbpf