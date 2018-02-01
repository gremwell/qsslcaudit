
include_directories(
    ${UNSAFESSL_DIR}
    ${QSSLCAUDIT_DIR}
    )

add_executable(tests_SslTest02 tests_SslTest02.cpp test.h)
set_target_properties(tests_SslTest02 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTest02 qsslcaudit)
