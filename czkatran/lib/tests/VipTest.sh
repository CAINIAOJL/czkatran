g++ -Wall -o VipTest \
    /home/jianglei/czkatran/czkatran/lib/tests/VipTest.cc \
    /home/jianglei/czkatran/czkatran/lib/CHHelper.cc \
    /home/jianglei/czkatran/czkatran/lib/MurmurHash3.cc \
    /home/jianglei/czkatran/czkatran/lib/MaglevBase.cc \
    /home/jianglei/czkatran/czkatran/lib/MaglevHash.cc \
    /home/jianglei/czkatran/czkatran/lib/MaglevHashV2.cc \
    /home/jianglei/czkatran/czkatran/lib/Vip.cc \
    -std=c++17 \
    -g \
    -Wall \
    -lpthread \
    -lgtest \
    -lfolly \
    -ldouble-conversion \
    -liberty \
    -lunwind \
    -lglog \
    -lfmt \
    -lgflags