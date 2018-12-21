project(qsslcaudit.bin)

add_subdirectory(unsafessl)
add_subdirectory(libqsslcaudit)

include_directories(
    ${LIBQSSLCAUDIT_DIR}
    ${UNSAFESSL_DIR}
    )

add_executable(qsslcaudit main.cpp)
set_target_properties(qsslcaudit PROPERTIES AUTOMOC TRUE)

target_link_libraries(qsslcaudit qsslcaudit_lib)

install(TARGETS qsslcaudit RUNTIME DESTINATION bin)
