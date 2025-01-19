#g++ -Wall -o PipeWriterTest\
#    /home/jianglei/czkatran/czkatran/lib/tests/PipeWriterTest.cc\
#    /home/jianglei/czkatran/czkatran/lib/PipeWriter.cc\
#    -std=c++17 -g -v -Wall -lpthread -lgtest -levent -lfolly -ldouble-conversion -lglog -lfmt -lgflags

#g++ -v -Wall -o PipeWriterTest \
#    /home/jianglei/czkatran/czkatran/lib/tests/PipeWriterTest.cc \
#    /home/jianglei/czkatran/czkatran/lib/PipeWriter.cc \
#    -std=c++17 -g -Wall -lpthread -lgtest -lfolly -levent -lboost_filesystemt -ldouble-conversion -lglog -lfmt -lgflags


g++ -v -Wall -o PipeWriterTest \
    /home/jianglei/czkatran/czkatran/lib/tests/PipeWriterTest.cc \
    /home/jianglei/czkatran/czkatran/lib/PipeWriter.cc \
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
    -lgflags  # 如果需要连接 gflags 库的话