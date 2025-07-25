/*
 * Copyright (c) 2020-2024 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

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
