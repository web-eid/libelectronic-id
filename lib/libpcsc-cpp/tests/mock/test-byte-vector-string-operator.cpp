/*
 * Copyright (c) 2020-2025 Estonian Information System Authority
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

#include <gtest/gtest.h>

using namespace pcsc_cpp;

TEST(byte_vector_stringOperatorTest, appendsHexToNonEmptyString)
{
    byte_vector data = {0x12, 0x34, 0xAB, 0xFF};
    std::string prefix = "prefix-";

    std::string result = prefix + data;

    EXPECT_EQ(result, "prefix-1234abff");
}

TEST(byte_vector_stringOperatorTest, appendsHexToEmptyString)
{
    byte_vector data = {0x01, 0xA0, 0xFF};
    std::string prefix;

    std::string result = prefix + data;

    EXPECT_EQ(result, "01a0ff");
}

TEST(byte_vector_stringOperatorTest, handlesEmptyByteVector)
{
    byte_vector data;
    std::string prefix = "nothing-changes-";

    std::string result = prefix + data;

    EXPECT_EQ(result, "nothing-changes-");
}
