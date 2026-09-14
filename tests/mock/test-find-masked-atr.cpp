// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
