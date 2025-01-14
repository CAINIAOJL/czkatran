g++ -Wall -o CHHelperTest \
    /home/jianglei/czkatran/czkatran/lib/tests/CHHelperTest.cc \
    /home/jianglei/czkatran/czkatran/lib/CHHelper.cc \
    /home/jianglei/czkatran/czkatran/lib/MurmurHash3.cc \
    /home/jianglei/czkatran/czkatran/lib/MaglevBase.cc \
    /home/jianglei/czkatran/czkatran/lib/MaglevHash.cc \
    /home/jianglei/czkatran/czkatran/lib/MaglevHashV2.cc \
    -std=c++17 -g -Wall -lpthread -lgtest -lfolly -lglog -lfmt -lgflags