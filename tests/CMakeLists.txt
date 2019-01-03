
include_directories(
    ${UNSAFESSL_DIR}
    ${LIBQSSLCAUDIT_DIR}
    )

# this is required on Ubuntu
set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_executable(tests_SslTest02 tests_SslTest02.cpp test.h)
set_target_properties(tests_SslTest02 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTest02 qsslcaudit_lib)

if(UNSAFE_MODE)
  add_executable(tests_SslTest08 tests_SslTest08.cpp test.h)
  set_target_properties(tests_SslTest08 PROPERTIES AUTOMOC TRUE)
  target_link_libraries(tests_SslTest08 qsslcaudit_lib)
endif()

if(UNSAFE_MODE)
  add_executable(tests_SslTest09 tests_SslTest09.cpp test.h)
  set_target_properties(tests_SslTest09 PROPERTIES AUTOMOC TRUE)
  target_link_libraries(tests_SslTest09 qsslcaudit_lib)
endif()

if(UNSAFE_MODE)
  add_executable(tests_SslTest12 tests_SslTest12.cpp test.h)
  set_target_properties(tests_SslTest12 PROPERTIES AUTOMOC TRUE)
  target_link_libraries(tests_SslTest12 qsslcaudit_lib)
endif()

add_executable(tests_SslTest13 tests_SslTest13.cpp test.h)
set_target_properties(tests_SslTest13 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTest13 qsslcaudit_lib)

add_executable(tests_SslTest16 tests_SslTest16.cpp test.h)
set_target_properties(tests_SslTest16 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTest16 qsslcaudit_lib)

add_executable(tests_SslTest19 tests_SslTest19.cpp test.h)
set_target_properties(tests_SslTest19 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTest19 qsslcaudit_lib)

add_executable(tests_SslTest22 tests_SslTest22.cpp test.h)
set_target_properties(tests_SslTest22 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTest22 qsslcaudit_lib)
