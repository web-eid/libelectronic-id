// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#include "../common/selectcard.hpp"

#include "electronic-ids/pcsc/EstEIDIDEMIA.hpp"
#include "electronic-ids/pcsc/FinEID.hpp"
#include "electronic-ids/pcsc/LatEIDIDEMIAv2.hpp"

#include "pcsc-mock/pcsc-mock.hpp"

#include <gtest/gtest.h>

using namespace electronic_id;

TEST(electronic_id_test, autoSelectFailureWithUnsupportedCard)
{
    EXPECT_THROW({ autoSelectSupportedCard(); }, AutoSelectFailed);
}

TEST(electronic_id_test, autoSelectSuccessWithSupportedCardEstIDEMIA)
{
    PcscMock::setAtr(EstEIDIDEMIAV1::ATR_COSMO_8);
    auto result = autoSelectSupportedCard();
    EXPECT_TRUE(result);
    EXPECT_EQ(result->name(), "EstEID IDEMIA v1");
    PcscMock::reset();
}

TEST(electronic_id_test, autoSelectSuccessWithSupportedCardLatV2)
{
    PcscMock::setAtr(LatEIDIDEMIAV2::ATR_COSMO_8);
    auto result = autoSelectSupportedCard();
    EXPECT_TRUE(result);
    EXPECT_EQ(result->name(), "LatEID IDEMIA v2");
    PcscMock::reset();
}

TEST(electronic_id_test, autoSelectSuccessWithSupportedCardFinV3)
{
    PcscMock::setAtr(FinEIDv3::ATR);
    auto result = autoSelectSupportedCard();
    EXPECT_TRUE(result);
    EXPECT_EQ(result->name(), "FinEID v3");
    PcscMock::reset();
}

TEST(electronic_id_test, autoSelectSuccessWithSupportedCardFinV4)
{
    PcscMock::setAtr(FinEIDv4::ATR);
    auto result = autoSelectSupportedCard();
    EXPECT_TRUE(result);
    EXPECT_EQ(result->name(), "FinEID v4");
    PcscMock::reset();
}
