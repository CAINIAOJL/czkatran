if(NOT BUILD_TESTS)
    return ()
endif()

#include(czkatranTest)

add_library(base64_helpers STATIC
    Base64Helpers.h
    Base64Helpers.cc
)

target_link_libraries(base64_helpers
    glog
    "${GFLAGS}"
    Folly
    "${BOOST_SYSTEM}"
    "czkatranlb"
)

target_include_directories(
    base64_helpers PUBLIC
    "${GTEST_INCLUDE_DIR}"
    "${CZKATRAN_INCLUDE_DIR}"
)

add_library(pcap_parser STATIC
    PcapParser.h
    PcapParser.cc
)

target_link_libraries(pcap_parser
    base64_helpers
    Folly
    glog
    "${BOOST_SYSTEM}"
)

add_library(bpftester STATIC
    BpfTester.h
    BpfTester.cc
)

target_link_libraries(bpftester
    Folly
    glog
    pcap_parser
    bpfadapter
)

install(
  TARGETS bpftester
  EXPORT czczkatran-exports
  DESTINATION lib
)