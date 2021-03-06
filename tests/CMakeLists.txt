include_directories(
    ${UNSAFESSL_DIR}
    ${LIBQSSLCAUDIT_DIR}
    )

# this is required on Ubuntu
set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_executable(tests_SslTestCertSS1 tests_SslTestCertSS1.cpp test.h)
set_target_properties(tests_SslTestCertSS1 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTestCertSS1 qsslcaudit_lib)
add_test(tests_SslTestCertSS1 tests_SslTestCertSS1)

add_executable(tests_SslTestCertSS1dtls tests_SslTestCertSS1dtls.cpp test.h)
set_target_properties(tests_SslTestCertSS1dtls PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTestCertSS1dtls qsslcaudit_lib)
add_test(tests_SslTestCertSS1dtls tests_SslTestCertSS1dtls)

if(UNSAFE_MODE)
  add_executable(tests_SslTestProtoSsl2 tests_SslTestProtoSsl2.cpp test.h)
  set_target_properties(tests_SslTestProtoSsl2 PROPERTIES AUTOMOC TRUE)
  target_link_libraries(tests_SslTestProtoSsl2 qsslcaudit_lib)
  add_test(tests_SslTestProtoSsl2 tests_SslTestProtoSsl2)
endif()

if(UNSAFE_MODE)
  add_executable(tests_SslTestProtoSsl3 tests_SslTestProtoSsl3.cpp test.h)
  set_target_properties(tests_SslTestProtoSsl3 PROPERTIES AUTOMOC TRUE)
  target_link_libraries(tests_SslTestProtoSsl3 qsslcaudit_lib)
  add_test(tests_SslTestProtoSsl3 tests_SslTestProtoSsl3)
endif()

if(UNSAFE_MODE)
  add_executable(tests_SslTestCiphersSsl3Med tests_SslTestCiphersSsl3Med.cpp test.h)
  set_target_properties(tests_SslTestCiphersSsl3Med PROPERTIES AUTOMOC TRUE)
  target_link_libraries(tests_SslTestCiphersSsl3Med qsslcaudit_lib)
  add_test(tests_SslTestCiphersSsl3Med tests_SslTestCiphersSsl3Med)
endif()

add_executable(tests_SslTestProtoTls10 tests_SslTestProtoTls10.cpp test.h)
set_target_properties(tests_SslTestProtoTls10 PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTestProtoTls10 qsslcaudit_lib)
add_test(tests_SslTestProtoTls10 tests_SslTestProtoTls10)

add_executable(tests_SslTestCiphersTls10Med tests_SslTestCiphersTls10Med.cpp test.h)
set_target_properties(tests_SslTestCiphersTls10Med PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTestCiphersTls10Med qsslcaudit_lib)
add_test(tests_SslTestCiphersTls10Med tests_SslTestCiphersTls10Med)

add_executable(tests_SslTestCiphersTls11Med tests_SslTestCiphersTls11Med.cpp test.h)
set_target_properties(tests_SslTestCiphersTls11Med PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTestCiphersTls11Med qsslcaudit_lib)
add_test(tests_SslTestCiphersTls11Med tests_SslTestCiphersTls11Med)

add_executable(tests_SslTestCiphersTls12Med tests_SslTestCiphersTls12Med.cpp test.h)
set_target_properties(tests_SslTestCiphersTls12Med PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_SslTestCiphersTls12Med qsslcaudit_lib)
add_test(tests_SslTestCiphersTls12Med tests_SslTestCiphersTls12Med)

if(UNSAFE_MODE)
  add_executable(tests_SslTestCiphersDtls10Exp tests_SslTestCiphersDtls10Exp.cpp test.h)
  set_target_properties(tests_SslTestCiphersDtls10Exp PROPERTIES AUTOMOC TRUE)
  target_link_libraries(tests_SslTestCiphersDtls10Exp qsslcaudit_lib)
  add_test(tests_SslTestCiphersDtls10Exp tests_SslTestCiphersDtls10Exp)

  add_executable(tests_SslTestCiphersDtls12Exp tests_SslTestCiphersDtls12Exp.cpp test.h)
  set_target_properties(tests_SslTestCiphersDtls12Exp PROPERTIES AUTOMOC TRUE)
  target_link_libraries(tests_SslTestCiphersDtls12Exp qsslcaudit_lib)
  add_test(tests_SslTestCiphersDtls12Exp tests_SslTestCiphersDtls12Exp)
endif()

add_executable(tests_MultipleTests tests_MultipleTests.cpp test.h)
set_target_properties(tests_MultipleTests PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_MultipleTests qsslcaudit_lib)
add_test(NAME tests_MultipleTests COMMAND tests_MultipleTests 100)

add_executable(tests_DifferentClientTypes tests_DifferentClientTypes.cpp test.h)
set_target_properties(tests_DifferentClientTypes PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_DifferentClientTypes qsslcaudit_lib)
add_test(tests_DifferentClientTypes tests_DifferentClientTypes)

add_executable(tests_MultipleClients tests_MultipleClients.cpp test.h)
set_target_properties(tests_MultipleClients PROPERTIES AUTOMOC TRUE)
target_link_libraries(tests_MultipleClients qsslcaudit_lib)
add_test(tests_MultipleClients tests_MultipleClients)
