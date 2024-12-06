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

const pcsc_cpp::byte_vector EstEIDIDEMIAV1_ATR {0x3b, 0xdb, 0x96, 0x00, 0x80, 0xb1, 0xfe, 0x45,
                                                0x1f, 0x83, 0x00, 0x12, 0x23, 0x3f, 0x53, 0x65,
                                                0x49, 0x44, 0x0f, 0x90, 0x00, 0xf1};
const pcsc_cpp::byte_vector INVALID_ATR {0xaa, 0xbb, 0xcc, 0x40, 0x0a, 0xa5, 0x03,
                                         0x01, 0x01, 0x01, 0xad, 0x13, 0x11};

TEST(electronic_id_test, isCardSupportedSuccessWithSupportedATR)
{
    EXPECT_TRUE(isCardSupported(EstEIDIDEMIAV1_ATR));
}

TEST(electronic_id_test, isCardSupportedFailureWithUnsupportedATR)
{
    EXPECT_FALSE(isCardSupported(INVALID_ATR));
}
