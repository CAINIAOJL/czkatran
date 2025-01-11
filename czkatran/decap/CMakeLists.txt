cmake_minimum_required(VERSION 3.2)
#CZKATRAN_INCLUDE_DIR 是/home/jianglei/czkatran/czkatran的路径
set(CZKATRAN_INCLUDE_DIR "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../../>")

#find_package(Glog REQUIRED)
#find_package(folly CONFIG REQUIRED)
#find_package(Threads)

add_library(decap STATIC
    XdpDecap.cc
    XdpDecap.h
    XdpDecapStrcuts.h
)
#连接库目标
target_link_libraries(decap
    bpfadapter
    "Folly"
    ${GLOG}
)

#寻找头文件
target_include_directories(
    decap PUBLIC
    ${GFLAGS_INCLUDE_DIR}
    ${CZKATRAN_INCLUDE_DIR}
)

install(TARGETS decap
    EXPORT czkatran-exports
    DESTINATION decap
)

if (BUILD_TESTS)
    add_subdirectory(testing)
endif()