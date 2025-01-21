g++ -Wall -o EventPipeCallBackTest \
    /home/jianglei/czkatran/czkatran/lib/tests/EventPipeCallBackTest.cc \
    /home/jianglei/czkatran/czkatran/lib/MonitoringServiceCore.cc \
    /home/jianglei/czkatran/czkatran/lib/EventPipeCallback.cc \
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
    -lgmock