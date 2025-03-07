#if(NOT BUILD_TESTS)
#    return()
#endif()

#include(czkatranTest)

add_library(base64_helpers STATIC
    Base64Helpers.h
    Base64Helpers.cc
)

target_link_libraries(base64_helpers
    #"glog::glog"
    #-lglog
    #-lfolly
    ${FOLLY}
    ${GLOG}
    #-lgflags
    "${GFLAGS}"
    #"Folly::folly"
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
    pcapwriter
    #"Folly::folly"
    #"glog::glog"
    #-lglog
    #-lfolly
    #-lgflags
    ${FLOLLY}
    ${GLOG}
    ${GFLAGS}
    "${BOOST_SYSTEM}"
)

add_library(bpftester STATIC
    BpfTester.h
    BpfTester.cc
)

target_link_libraries(bpftester
    #"Folly::folly"
    #"glog::glog"
    #-lglog
    #-lfolly
    #-lgflags
    ${FLOLLY}
    ${GLOG}
    ${GFLAGS}
    pcap_parser
    bpfadapter
)

add_test(TARGET base64_helpers-tests
    SOURCES
    Base64Helpers.cc
    DEPENDS
    base64_helpers
    czkatranlb
    ${FOLLY}
    ${GTEST}
    #"glog::glog"
    ${GFLAGS}
    #"Folly::folly"
    #-lglog
    #-lfolly
    #-lgflags
    ${LIBUNWIND}
    INCLUDES
    base64_helpers
)

add_library(czkatran_test_provision STATIC
    czkatranTestProvision.cc
)

target_link_libraries(czkatran_test_provision
    czkatranlb
)

add_library(czkatran_test_util STATIC
    czkatranTestUtil.cc
)

target_link_libraries(czkatran_test_util
    czkatran_test_provision
    czkatranlb
    bpftester
)

add_executable(czkatran_tester
    czkatran_testing.cc
)

target_link_libraries(czkatran_tester
    czkatranlb
    bpftester
    czkatran_test_provision
    czkatran_test_util
    ${FOLLY}
    ${GFLAGS}
    ${GTEST}
)

target_include_directories(czkatran_tester PRIVATE
    ${BPF_INCLUDE_DIRS}
    ${GTEST_INCLUDE_DIR}
    ${FOLLY_INCLUDE_DIR}
    ${CZKATRAN_INCLUDE_DIR}
)