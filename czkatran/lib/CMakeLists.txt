find_library(LIBELF libelf.a elf)
# To support build for katran with user-supplied libbpf path
set(LIB_BPF_PREFIX "" CACHE STRING "USER Supplied Prefix for libppf path")
if ( LIB_BPF_PREFIX )
  set(ENV{PKG_CONFIG_PATH} "$ENV{PKG_CONFIG_PATH}:${LIB_BPF_PREFIX}/lib/pkgconfig")
endif()

# Look for libbpf.  It is important to use its pkg-config file as that is
# responsible for locating its libelf dependency.
find_package(PkgConfig REQUIRED)
pkg_check_modules(BPF REQUIRED libbpf)
add_library(Bpf INTERFACE IMPORTED)
set_property(TARGET Bpf PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${BPF_INCLUDEDIR})
if ( LIB_BPF_PREFIX )
  set(BPF_LINK_LIBRARIES "${LIB_BPF_PREFIX}/lib/libbpf.a")
endif()
set_property(TARGET Bpf PROPERTY INTERFACE_LINK_LIBRARIES ${BPF_LINK_LIBRARIES})
set_property(TARGET Bpf PROPERTY INTERFACE_LINK_OPTIONS ${BPF_STATIC_LDFLAGS})
set_property(TARGET Bpf PROPERTY INTERFACE_COMPILE_OPTIONS ${BPF_STATIC_CFLAGS_OTHER})

find_library(LIBMNL_LIBRARY mnl)
find_path(LIBMNL_INCLUDE_DIR libmnl)
find_library(LIBZ_LIBRARY z)
find_library(LIBZ z)

#先有这个库，
add_library(murmur3 STATIC
    MurmurHash3.h
    MurmurHash3.cc
)

#这个库依赖于上面的那个
add_library(chhelpers STATIC
    CHHelper.h
    CHHelper.cc
    MaglevBase.h
    MaglevBase.cc
    MaglevHash.h
    MaglevHash.cc
    MaglevHashV2.h
    MaglevHashV2.cc
)

target_link_libraries(chhelpers murmur3)

#头文件搜索位置
target_include_directories(
  chhelpers PUBLIC
  ${CZKATRAN_INCLUDE_DIR}
)

add_library(bpfadapter STATIC
    BaseBpfAdapter.h
    BaseBpfAdapter.cc
    BpfAdapter.h
    BpfAdapter.cc
    BpfLoater.h
    BpfLoader.cc
    Netlink.h
    Netlink.cc
)

target_link_libraries(bpfadapter 
  PUBLIC
    ${BPF_LINK_LIBRARIES}
    ${LIBELF}
    glog
    ${GLOG}
    ${PTHREAD}
    ${LIBZ}
    ${FOLLY}
    Folly
    ${LIBMNL_LIBRARY}
)

target_include_directories(
  bpfadapter PUBLIC
  ${BPF_INCLUDE_DIRS}
  ${FOLLY_INCLUDE_DIR}
  ${CZKATRAN_INCLUDE_DIR}
  ${LIBMNL_INCLUDE_DIR}
)

add_library(czkatranlb STATIC
    czkatranLb.h
    czkatranLb.cc
    czkatranLbStructs.h
    Balancer_structs.h
    #暂且只用到这么些
)

target_link_libraries(czkatranlb
    "-Wl,--start-group"
    bpfadapter
    chhelpers
    ${GFLAGS}
    ${PTHREAD}
    "-Wl,--end-group"
)

target_include_directories(
  czkatranlb PUBLIC
  ${BPF_INCLUDE_DIRS}
  ${FOLLY_INCLUDE_DIR}
  ${CZKATRAN_INCLUDE_DIR}
)


#add_executable(Maglev_test
#    Maglev_test.cc
#)

#target_link_libraries(Maglev_test
#    ${GFLAGS}    
#    chhelpers
#    "${PTHREAD}"
#)

#target_include_directories(
#     Maglev_test PUBLIC
#     ${GFLAGS_INCLUDE_DIR}
#     ${CZKATRAN_INCLUDE_DIR}
#)

install(
  TARGETS murmur3
  EXPORT czkatran-exports
  DESTINATION lib
)

install(
  TARGETS chhelpers
  EXPORT czkatran-exports
  DESTINATION lib
)

install(
  TARGETS bpfadapter
  EXPORT czkatran-exports
  DESTINATION lib
)

install(
  TARGETS czkatranlb
  EXPORT czkatran-exports
  DESTINATION lib
)

if(BUILD_TESTS)
  add_subdirectory(testing)
endif()