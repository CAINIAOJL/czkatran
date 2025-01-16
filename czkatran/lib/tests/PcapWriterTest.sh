g++ -Wall -o PcapWriterTest\
    /home/jianglei/czkatran/czkatran/lib/tests/PcapWriterTest.cc\
    /home/jianglei/czkatran/czkatran/lib/MonitoringStructs.cc\
    /home/jianglei/czkatran/czkatran/lib/PcapMsg.cc\
    /home/jianglei/czkatran/czkatran/lib/PcapMsgMeta.cc\
    /home/jianglei/czkatran/czkatran/lib/PcapWriter.cc\
    -std=c++17 -g -Wall -lpthread -lgtest -lfolly -ldouble-conversion -lglog -lfmt -lgflags -lgmock