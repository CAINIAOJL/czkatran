cmake_minimum_required(VERSION 3.0)

project(czkatran)


#find_package(fmt CONFIG REQUIRED)
#find_package(folly CONFIG REQUIRED)
#find_package(Glog REQUIRED)
#find_package(Gflags REQUIRED)

include_directories(".")
add_subdirectory(czkatran)

if(BUILD_TESTS)
    enable_testing()
    #include(czkatranTest)
endif()