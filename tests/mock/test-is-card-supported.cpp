// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

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
