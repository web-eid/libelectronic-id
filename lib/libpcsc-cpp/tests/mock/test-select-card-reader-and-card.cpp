// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#include "pcsc-cpp/pcsc-cpp.hpp"

#include "pcsc-mock/pcsc-mock.hpp"
#include "pcsc-cpp/comp_winscard.hpp"

#include <gtest/gtest.h>

TEST(pcsc_cpp_test, listReadersSuccess)
{
    using namespace pcsc_cpp;

    auto readers = listReaders();
    EXPECT_EQ(readers.size(), 1U);
#ifdef _WIN32
    EXPECT_EQ(readers[0].name, L"PcscMock-reader");
#else
    EXPECT_EQ(readers[0].name, "PcscMock-reader");
#endif
    EXPECT_EQ(readers[0].isCardPresent, true);
}

TEST(pcsc_cpp_test, listReadersNoReaders)
{
    using namespace pcsc_cpp;

    PcscMock::addReturnValueForScardFunctionCall("SCardListReaders", SCARD_E_NO_READERS_AVAILABLE);

    auto readers = listReaders();
    EXPECT_EQ(readers.size(), 0U);

    PcscMock::reset();
}

TEST(pcsc_cpp_test, listReadersNoService)
{
    using namespace pcsc_cpp;

    PcscMock::addReturnValueForScardFunctionCall("SCardEstablishContext", SCARD_E_NO_SERVICE);

    EXPECT_THROW({ listReaders(); }, ScardServiceNotRunningError);

    PcscMock::reset();
}
