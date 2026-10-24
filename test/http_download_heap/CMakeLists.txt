add_executable(HttpDownloadHeapTest HttpDownloadHeapTest.cpp)

target_include_directories(HttpDownloadHeapTest PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/stubs
  ${REPO_ROOT}/src
)

target_link_libraries(HttpDownloadHeapTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(HttpDownloadHeapTest)

add_executable(HttpDownloadAttemptTest
  HttpDownloadAttemptTest.cpp
  ${REPO_ROOT}/src/network/HttpDownloader.cpp
)

target_include_directories(HttpDownloadAttemptTest PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/mocks
  ${REPO_ROOT}/src/network
)

target_compile_definitions(HttpDownloadAttemptTest PRIVATE CROSSPOINT_VERSION="test")

target_link_libraries(HttpDownloadAttemptTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(HttpDownloadAttemptTest)
