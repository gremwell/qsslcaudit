include_directories(
    ${UNSAFESSL_DIR}
    ${LIBQSSLCAUDIT_DIR}
    )

# this is required on Ubuntu
set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_executable(tests_SslTest02 tests_SslTest02.cpp test.h)
set_target_properties(tests_SslTest02 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTest02 qsslcaudit_lib)
add_test(tests_SslTest02 tests_SslTest02)

add_executable(tests_SslTest02dtls tests_SslTest02dtls.cpp test.h)
set_target_properties(tests_SslTest02dtls PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTest02dtls qsslcaudit_lib)
add_test(tests_SslTest02dtls tests_SslTest02dtls)

if(UNSAFE_MODE)
  add_executable(tests_SslTest08 tests_SslTest08.cpp test.h)
  set_target_properties(tests_SslTest08 PROPERTIES AUTOMOC TRUE)
  target_link_libraries(tests_SslTest08 qsslcaudit_lib)
  add_test(tests_SslTest08 tests_SslTest08)
endif()

if(UNSAFE_MODE)
  add_executable(tests_SslTest09 tests_SslTest09.cpp test.h)
  set_target_properties(tests_SslTest09 PROPERTIES AUTOMOC TRUE)
  target_link_libraries(tests_SslTest09 qsslcaudit_lib)
  add_test(tests_SslTest09 tests_SslTest09)
endif()

if(UNSAFE_MODE)
  add_executable(tests_SslTest12 tests_SslTest12.cpp test.h)
  set_target_properties(tests_SslTest12 PROPERTIES AUTOMOC TRUE)
  target_link_libraries(tests_SslTest12 qsslcaudit_lib)
  add_test(tests_SslTest12 tests_SslTest12)
endif()

add_executable(tests_SslTest13 tests_SslTest13.cpp test.h)
set_target_properties(tests_SslTest13 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTest13 qsslcaudit_lib)
add_test(tests_SslTest13 tests_SslTest13)

add_executable(tests_SslTest16 tests_SslTest16.cpp test.h)
set_target_properties(tests_SslTest16 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTest16 qsslcaudit_lib)
add_test(tests_SslTest16 tests_SslTest16)

add_executable(tests_SslTest19 tests_SslTest19.cpp test.h)
set_target_properties(tests_SslTest19 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTest19 qsslcaudit_lib)
add_test(tests_SslTest19 tests_SslTest19)

add_executable(tests_SslTest22 tests_SslTest22.cpp test.h)
set_target_properties(tests_SslTest22 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTest22 qsslcaudit_lib)
add_test(tests_SslTest22 tests_SslTest22)

if(UNSAFE_MODE)
  add_executable(tests_SslTest23 tests_SslTest23.cpp test.h)
  set_target_properties(tests_SslTest23 PROPERTIES AUTOMOC TRUE)
  target_link_libraries(tests_SslTest23 qsslcaudit_lib)
  add_test(tests_SslTest23 tests_SslTest23)

  add_executable(tests_SslTest26 tests_SslTest26.cpp test.h)
  set_target_properties(tests_SslTest26 PROPERTIES AUTOMOC TRUE)
  target_link_libraries(tests_SslTest26 qsslcaudit_lib)
  add_test(tests_SslTest26 tests_SslTest26)
endif()

add_executable(tests_RecurrentRequests tests_RecurrentRequests.cpp test.h)
set_target_properties(tests_RecurrentRequests PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_RecurrentRequests qsslcaudit_lib)
add_test(NAME tests_RecurrentRequests COMMAND tests_RecurrentRequests 100)

add_executable(tests_DifferentClientTypes tests_DifferentClientTypes.cpp test.h)
set_target_properties(tests_DifferentClientTypes PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_DifferentClientTypes qsslcaudit_lib)
add_test(tests_DifferentClientTypes tests_DifferentClientTypes)

add_executable(tests_MultipleClients tests_MultipleClients.cpp test.h)
set_target_properties(tests_MultipleClients PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_MultipleClients qsslcaudit_lib)
add_test(tests_MultipleClients tests_MultipleClients)
