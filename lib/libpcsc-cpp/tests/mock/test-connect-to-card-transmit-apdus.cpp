// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#include "pcsc-cpp/pcsc-cpp.hpp"

#include "pcsc-mock/pcsc-mock.hpp"
#include "pcsc-cpp/comp_winscard.hpp"

#include <gtest/gtest.h>

using namespace pcsc_cpp;

namespace
{

SmartCard connectToCard()
{
    auto readers = listReaders();
    EXPECT_EQ(readers.size(), 1U);

    return readers[0].connectToCard();
}

} // namespace

TEST(pcsc_cpp_test, connectToCardSuccess)
{
    auto card = connectToCard();

    EXPECT_EQ(card.atr(), PcscMock::DEFAULT_CARD_ATR);
    EXPECT_EQ(card.protocol(), SmartCard::Protocol::T1);
}

TEST(pcsc_cpp_test, transmitApduSuccess)
{
    auto card = connectToCard();

    CommandApdu command {PcscMock::DEFAULT_COMMAND_APDU[0], PcscMock::DEFAULT_COMMAND_APDU[1],
                         PcscMock::DEFAULT_COMMAND_APDU[2], PcscMock::DEFAULT_COMMAND_APDU[3]};

    auto session = card.beginSession();
    auto response = session.transmit(command);

    EXPECT_TRUE(response.isOK());
}
