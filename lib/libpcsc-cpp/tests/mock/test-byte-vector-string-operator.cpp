// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#include "pcsc-cpp/pcsc-cpp.hpp"

#include <gtest/gtest.h>

using namespace pcsc_cpp;

TEST(byte_vector_stringOperatorTest, appendsHexToNonEmptyString)
{
    byte_vector data = {0x12, 0x34, 0xAB, 0xFF};
    std::string prefix = "prefix-";

    std::string result = std::move(prefix) + data;

    EXPECT_EQ(result, "prefix-1234abff");
}

TEST(byte_vector_stringOperatorTest, appendsHexToEmptyString)
{
    byte_vector data = {0x01, 0xA0, 0xFF};
    std::string prefix;

    std::string result = std::move(prefix) + data;

    EXPECT_EQ(result, "01a0ff");
}

TEST(byte_vector_stringOperatorTest, handlesEmptyByteVector)
{
    byte_vector data;
    std::string prefix = "nothing-changes-";

    std::string result = std::move(prefix) + data;

    EXPECT_EQ(result, "nothing-changes-");
}
