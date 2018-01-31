project(qsslcaudit.bin)

add_subdirectory(unsafessl)
add_subdirectory(qsslcaudit)

include_directories(
    ${QSSLCAUDIT_DIR}
    ${UNSAFESSL_DIR}
    )

add_executable(qsslcaudit.bin main.cpp)
set_target_properties(qsslcaudit.bin PROPERTIES AUTOMOC TRUE)

target_link_libraries(qsslcaudit.bin qsslcaudit)

install(TARGETS qsslcaudit.bin RUNTIME DESTINATION bin)
