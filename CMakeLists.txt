cmake_minimum_required(VERSION 3.22)
if(POLICY CMP0092)
  cmake_policy(SET CMP0092 NEW)
endif()

project(electronic-id)

# The eid library itself.

add_library(${PROJECT_NAME}
  STATIC
  include/${PROJECT_NAME}/${PROJECT_NAME}.hpp
  include/${PROJECT_NAME}/enums.hpp
  src/availableSupportedCards.cpp
  src/${PROJECT_NAME}.cpp
  src/electronic-ids/common.hpp
  src/electronic-ids/common.cpp
  src/electronic-ids/scope.hpp
  src/electronic-ids/TLV.hpp
  src/electronic-ids/x509.hpp
  src/electronic-ids/pcsc/EIDIDEMIA.cpp
  src/electronic-ids/pcsc/EIDIDEMIA.hpp
  src/electronic-ids/pcsc/EstEIDIDEMIA.hpp
  src/electronic-ids/pcsc/FinEID.cpp
  src/electronic-ids/pcsc/FinEID.hpp
  src/electronic-ids/pcsc/LatEIDIDEMIAv2.cpp
  src/electronic-ids/pcsc/LatEIDIDEMIAv2.hpp
  src/electronic-ids/pcsc/PcscElectronicID.hpp
  src/electronic-ids/pcsc/pcsc-common.hpp
  src/electronic-ids/pkcs11/PKCS11CardManager.hpp
  src/electronic-ids/pkcs11/pkcs11.h
  src/electronic-ids/pkcs11/Pkcs11ElectronicID.cpp
  src/electronic-ids/pkcs11/Pkcs11ElectronicID.hpp
  $<$<PLATFORM_ID:Windows>:
    src/electronic-ids/ms-cryptoapi/listMsCryptoApiElectronicIDs.cpp
    src/electronic-ids/ms-cryptoapi/listMsCryptoApiElectronicIDs.hpp
    src/electronic-ids/ms-cryptoapi/MsCryptoApiElectronicID.cpp
    src/electronic-ids/ms-cryptoapi/MsCryptoApiElectronicID.hpp
  >
)

target_include_directories(${PROJECT_NAME}
  PUBLIC
  include
)

find_package(OpenSSL 3.0.0 REQUIRED)

target_link_libraries(${PROJECT_NAME}
  pcsc-cpp
  ${CMAKE_DL_LIBS}
  OpenSSL::Crypto
  $<$<PLATFORM_ID:Windows>: Shlwapi Crypt32 Ncrypt>
)

# libpcsc-cpp dependency.

add_subdirectory(lib/libpcsc-cpp)

# Common testing options.

enable_testing()

find_package(GTest REQUIRED)

# Mock tests that use libpcsc-mock to mock PC/SC API calls.

set(MOCK_TEST_EXE lib${PROJECT_NAME}-test-mock)

add_executable(${MOCK_TEST_EXE}
  tests/common/selectcard.hpp
  tests/common/verify.hpp
  tests/mock/atrs.hpp
  tests/mock/select-certificate-script.hpp
  tests/mock/select-certificate-script-EST-IDEMIA.hpp
  tests/mock/select-certificate-script-FIN-V3.hpp
  tests/mock/select-certificate-script-FIN-V4.hpp
  tests/mock/select-certificate-script-LAT-V2.hpp
  tests/mock/test-autoselect-card.cpp
  tests/mock/test-find-masked-atr.cpp
  tests/mock/test-is-card-supported.cpp
  tests/mock/test-get-certificate.cpp
  tests/mock/test-pkcs11-token.cpp
)

target_link_libraries(${MOCK_TEST_EXE}
  ${PROJECT_NAME}
  pcsc-mock # this is available via libpcsc-cpp
  GTest::Main
)

add_test(${MOCK_TEST_EXE} ${MOCK_TEST_EXE})

# Integration tests that use the real operating system PC/SC service.

set(INTEGRATION_TEST_EXE lib${PROJECT_NAME}-test-integration)

add_executable(${INTEGRATION_TEST_EXE}
  tests/common/selectcard.hpp
  tests/common/verify.hpp
  tests/integration/test-get-certificate.cpp
  tests/integration/test-authenticate.cpp
  tests/integration/test-signing.cpp
)

target_link_libraries(${INTEGRATION_TEST_EXE}
  ${PROJECT_NAME}
  pcsc
  GTest::Main
)
