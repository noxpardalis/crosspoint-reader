add_executable(WireGuardConfigTest
  WireGuardConfigTest.cpp
  ${REPO_ROOT}/lib/WireGuardTransport/WireGuardConfig.cpp
)

target_link_libraries(WireGuardConfigTest PRIVATE
  crosspoint_test_common
  GTest::gtest_main
)

gtest_discover_tests(WireGuardConfigTest)
