// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#include "electronic-id/electronic-id.hpp"

#include <gtest/gtest.h>

using namespace electronic_id;

const pcsc_cpp::Reader INVALID_ATR {
    nullptr,
    {},
    {0xaa, 0xbb, 0xcc, 0x40, 0x0a, 0xa5, 0x03, 0x01, 0x01, 0x01, 0xad, 0x13, 0x11},
    true};

TEST(electronic_id_test, getElectronicIDNullForUnsupportedATR)
{
    EXPECT_FALSE(getElectronicID(INVALID_ATR));
}
