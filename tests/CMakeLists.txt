
include_directories(
    ${UNSAFESSL_DIR}
    ${QSSLCAUDIT_DIR}
    )

# this is required on Ubuntu
set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_executable(tests_SslTest02 tests_SslTest02.cpp test.h)
set_target_properties(tests_SslTest02 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTest02 qsslcaudit)

add_executable(tests_SslTest08 tests_SslTest08.cpp test.h)
set_target_properties(tests_SslTest08 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTest08 qsslcaudit)

add_executable(tests_SslTest12 tests_SslTest12.cpp test.h)
set_target_properties(tests_SslTest12 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTest12 qsslcaudit)
