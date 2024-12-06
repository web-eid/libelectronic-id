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

#include "electronic-id/electronic-id.hpp"

#include <gtest/gtest.h>

using namespace electronic_id;

const pcsc_cpp::byte_vector BEL_EID_V1_7_ATR {0x3b, 0x98, 0x13, 0x40, 0x0a, 0xa5, 0x03,
                                              0x01, 0x01, 0x01, 0xad, 0x13, 0x11};
const pcsc_cpp::byte_vector INVALID_ATR {0xaa, 0xbb, 0xcc, 0x40, 0x0a, 0xa5, 0x03,
                                         0x01, 0x01, 0x01, 0xad, 0x13, 0x11};

TEST(electronic_id_test, findMaskedATRSuccessWithSupportedMaskedATR)
{
    EXPECT_TRUE(findMaskedATR(BEL_EID_V1_7_ATR).has_value());
}

TEST(electronic_id_test, findMaskedATRFailureWithUnSupportedATR)
{
    EXPECT_FALSE(findMaskedATR(INVALID_ATR).has_value());
}

TEST(electronic_id_test, isCardSupportedSuccessWithSupportedMaskedATR)
{
    EXPECT_TRUE(isCardSupported(BEL_EID_V1_7_ATR));
}
