set(COMMON_INCLUDE_DIR.)

add_library(testa STATIC
    a.h
    a.cc
)
target_include_directories(testa PUBLIC ${COMMON_INCLUDE_DIR})

add_library(testb STATIC
    b.h
    b.cc
)
target_include_directories(testb PUBLIC ${COMMON_INCLUDE_DIR})

add_library(testc STATIC
    c.h
    c.cc
)
target_include_directories(testc PUBLIC ${COMMON_INCLUDE_DIR})

add_executable(test
    test.cc
)
target_include_directories(test PUBLIC ${COMMON_INCLUDE_DIR})

# 将testa、testb和testc库链接到test可执行文件
target_link_libraries(test testa testb testc)


install(
  TARGETS testa
  EXPORT test-exports
  DESTINATION lib
)