
#include(czkatranTest)

add_library(base64_helpers STATIC
    Base64Helpers.h
    Base64Helpers.cc
)

target_link_libraries(base64_helpers
    -lglog
    "${GFLAGS}"
    Folly::folly
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
    Folly::folly
    -lglog
    "${BOOST_SYSTEM}"
)

add_library(bpftester STATIC
    BpfTester.h
    BpfTester.cc
)

target_link_libraries(bpftester
    Folly::folly
    -lglog
    fmt::fmt
    pcap_parser
    bpfadapter
)

install(
  TARGETS bpftester
  EXPORT czczkatran-exports
  DESTINATION lib
)