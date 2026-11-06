// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#include "pcsc-cpp/pcsc-cpp.hpp"

#include "pcsc-mock/pcsc-mock.hpp"
#include "pcsc-cpp/comp_winscard.hpp"

#include <gtest/gtest.h>

#include <limits>

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

TEST(pcsc_cpp_test, transmitStopsMoreDataAtSizeLimit)
{
    PcscMock::reset();

    const auto getResponse = CommandApdu::getResponse();
    byte_vector chunk(ResponseApdu::MAX_SIZE, 0x41);
    chunk[ResponseApdu::MAX_DATA_SIZE] = ResponseApdu::MORE_DATA_AVAILABLE;
    chunk[ResponseApdu::MAX_DATA_SIZE + 1] = 0x00;

    // The 256th chunk brings the total to 65 536 bytes, exceeding the 65 535-byte limit.
    const size_t chunkCount =
        (std::numeric_limits<uint16_t>::max)() / ResponseApdu::MAX_DATA_SIZE + 1;
    PcscMock::ApduScript script(chunkCount, {getResponse, chunk});

    // Put a READ BINARY command next in the script to detect any extra GET RESPONSE.
    // The size limit should stop the command chain before this point.
    // An extra GET RESPONSE instead throws PcscMockError, so the EXPECT_THROW fails below.
    const auto nextCommand = CommandApdu::readBinary(0, 1);
    script.emplace_back(nextCommand, byte_vector {0x42, ResponseApdu::OK, 0x00});
    PcscMock::setApduScript(script);

    auto card = connectToCard();
    auto session = card.beginSession();

    EXPECT_THROW(session.transmit(getResponse), Error);
    const auto response = session.transmit(nextCommand);
    EXPECT_TRUE(response.isOK());
    EXPECT_EQ(response.data, (byte_vector {0x42}));

    PcscMock::reset();
}
