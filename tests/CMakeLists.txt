
include_directories(
    ${UNSAFESSL_DIR}
    ${QSSLCAUDIT_DIR}
    )

add_executable(tests02 tests02.cpp test.h)
set_target_properties(tests02 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests02 qsslcaudit)
