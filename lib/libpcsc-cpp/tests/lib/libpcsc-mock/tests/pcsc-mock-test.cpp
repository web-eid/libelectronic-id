/*
 * Copyright (c) 2020-2023 Estonian Information System Authority
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

#include <pcsc-mock/pcsc-mock.hpp>

#include "gtest/gtest.h"

#ifdef __APPLE__
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif

#include <vector>
#include <string>

TEST(scard_mock_test, testScardCalls)
{
    using namespace std;

    SCARDCONTEXT _context;
    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &_context);
    EXPECT_FALSE(rv);
    EXPECT_TRUE(PcscMock::wasScardFunctionCalled("SCardEstablishContext"));

    vector<PcscMock::string_t::value_type> readerNames;
    readerNames.resize(25);
    DWORD readerNamesLen = DWORD(readerNames.size());
    rv = SCardListReaders(_context, nullptr, readerNames.data(), &readerNamesLen);
    EXPECT_FALSE(rv);
    EXPECT_TRUE(PcscMock::wasScardFunctionCalled("SCardListReaders"));
    PcscMock::string_t readerName(readerNames.data());
    EXPECT_EQ(readerName, PcscMock::DEFAULT_READER_NAME);

    std::vector<SCARD_READERSTATE> readerStates {{nullptr,
                                                  nullptr,
                                                  0,
                                                  0,
                                                  0,
                                                  {
                                                      0,
                                                  }}};
    rv = SCardGetStatusChange(_context, 0, readerStates.data(), DWORD(readerStates.size()));
    EXPECT_FALSE(rv);
    EXPECT_TRUE(PcscMock::wasScardFunctionCalled("SCardGetStatusChange"));
    readerName = readerStates[0].szReader;
    EXPECT_EQ(readerName, PcscMock::DEFAULT_READER_NAME);

    auto atrBuf = readerStates[0].rgbAtr;
    vector<unsigned char> atr(atrBuf, atrBuf + readerStates[0].cbAtr);
    EXPECT_EQ(atr, PcscMock::DEFAULT_CARD_ATR);

    auto protocol = SCARD_PROTOCOL_T0;
    DWORD protocolOut = SCARD_PROTOCOL_UNDEFINED;
    SCARDHANDLE _card;
    rv = SCardConnect(_context, nullptr, SCARD_SHARE_SHARED, protocol, &_card, &protocolOut);
    EXPECT_FALSE(rv);
    EXPECT_TRUE(PcscMock::wasScardFunctionCalled("SCardConnect"));

    rv = SCardBeginTransaction(_card);
    EXPECT_FALSE(rv);
    EXPECT_TRUE(PcscMock::wasScardFunctionCalled("SCardBeginTransaction"));

    auto commandBytes = PcscMock::byte_vector {2, 1, 3, 4};
    auto responseBytes = PcscMock::byte_vector(5, 0);
    DWORD responseLength = DWORD(responseBytes.size());
    SCARD_IO_REQUEST _protocol; // = *SCARD_PCI_T0; <-- non-trivial
    rv = SCardTransmit(_card, &_protocol, commandBytes.data(), DWORD(commandBytes.size()), nullptr,
                       responseBytes.data(), &responseLength);
    EXPECT_FALSE(rv);
    EXPECT_TRUE(PcscMock::wasScardFunctionCalled("SCardTransmit"));

    rv = SCardEndTransaction(_card, SCARD_LEAVE_CARD);
    EXPECT_FALSE(rv);
    EXPECT_TRUE(PcscMock::wasScardFunctionCalled("SCardEndTransaction"));

    rv = SCardDisconnect(_card, SCARD_LEAVE_CARD);
    EXPECT_FALSE(rv);
    EXPECT_TRUE(PcscMock::wasScardFunctionCalled("SCardDisconnect"));

    rv = SCardReleaseContext(_context);
    EXPECT_FALSE(rv);
    EXPECT_TRUE(PcscMock::wasScardFunctionCalled("SCardReleaseContext"));
}
