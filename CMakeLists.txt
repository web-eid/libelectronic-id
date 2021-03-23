cmake_minimum_required(VERSION 3.8.0)
if(POLICY CMP0092)
  cmake_policy(SET CMP0092 NEW)
endif()

project(electronic-id)

# The eid library itself.

add_library(${PROJECT_NAME}
  STATIC
  include/${PROJECT_NAME}/${PROJECT_NAME}.hpp
  include/${PROJECT_NAME}/enums.hpp
  src/autoSelectSupportedCard.cpp
  src/${PROJECT_NAME}.cpp
  src/electronic-ids/common.hpp
  src/electronic-ids/common.cpp
  src/electronic-ids/pcsc/EIDIDEMIA.cpp
  src/electronic-ids/pcsc/EIDIDEMIA.hpp
  src/electronic-ids/pcsc/EstEIDGemalto.cpp
  src/electronic-ids/pcsc/EstEIDGemalto.hpp
  src/electronic-ids/pcsc/EstEIDIDEMIA.cpp
  src/electronic-ids/pcsc/EstEIDIDEMIA.hpp
  src/electronic-ids/pcsc/FinEID.cpp
  src/electronic-ids/pcsc/FinEID.hpp
  src/electronic-ids/pcsc/LatEIDIDEMIACommon.hpp
  src/electronic-ids/pcsc/LatEIDIDEMIAv1.cpp
  src/electronic-ids/pcsc/LatEIDIDEMIAv1.hpp
  src/electronic-ids/pcsc/LatEIDIDEMIAv2.cpp
  src/electronic-ids/pcsc/LatEIDIDEMIAv2.hpp
  src/electronic-ids/pcsc/PcscElectronicID.hpp
  src/electronic-ids/pcsc/pcsc-common.hpp
  src/electronic-ids/pkcs11/PKCS11CardManager.hpp
  src/electronic-ids/pkcs11/pkcs11.h
  src/electronic-ids/pkcs11/Pkcs11ElectronicID.cpp
  src/electronic-ids/pkcs11/Pkcs11ElectronicID.hpp
)

target_include_directories(${PROJECT_NAME}
  PUBLIC
  include
)

find_package(OpenSSL REQUIRED)

target_link_libraries(${PROJECT_NAME}
  pcsc-cpp
  ${CMAKE_DL_LIBS}
  OpenSSL::Crypto
  $<$<C_COMPILER_ID:MSVC>:Shlwapi>
)

# Common compile options.

set(CMAKE_CXX_EXTENSIONS OFF)

# libpcsc-cpp dependency.

add_subdirectory(lib/libpcsc-cpp)

# Common testing options.

enable_testing()

find_package(GTest REQUIRED)

# Mock tests that use libpcsc-mock to mock PC/SC API calls.

set(MOCK_TEST_EXE lib${PROJECT_NAME}-test-mock)

add_executable(${MOCK_TEST_EXE}
  tests/common/verify.hpp
  tests/mock/atrs.hpp
  tests/mock/select-certificate-script.hpp
  tests/mock/select-certificate-script-EST-GEMALTO.hpp
  tests/mock/select-certificate-script-EST-IDEMIA.hpp
  tests/mock/select-certificate-script-FIN-V3.hpp
  tests/mock/select-certificate-script-LAT-V1.hpp
  tests/mock/select-certificate-script-LAT-V2.hpp
  tests/mock/test-autoselect-card.cpp
  tests/mock/test-get-certificate.cpp
  tests/mock/test-pkcs11-token.cpp
)

target_link_libraries(${MOCK_TEST_EXE}
  ${PROJECT_NAME}
  pcsc-mock # this is available via libpcsc-cpp
  GTest::Main
  OpenSSL::Crypto
)

add_test(${MOCK_TEST_EXE} ${MOCK_TEST_EXE})

# Integration tests that use the real operating system PC/SC service.

set(INTEGRATION_TEST_EXE lib${PROJECT_NAME}-test-integration)

add_executable(${INTEGRATION_TEST_EXE}
  tests/common/verify.hpp
  tests/integration/test-get-certificate.cpp
  tests/integration/test-authenticate.cpp
  tests/integration/test-signing.cpp
)

target_link_libraries(${INTEGRATION_TEST_EXE}
  ${PROJECT_NAME}
  pcsc
  GTest::Main
  OpenSSL::Crypto
)
