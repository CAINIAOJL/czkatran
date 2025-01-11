g++ -o MaglevTest -std=c++17 \
    Maglev_test.cc \
    MurmurHash3.cc \
    CHHelper.cc \
    MaglevBase.cc \
    MaglevHash.cc \
    MaglevHashV2.cc \
    -g -Wall -lglog -lpthread -lfolly -lfmt -lgflags
#MaglevTest.sh