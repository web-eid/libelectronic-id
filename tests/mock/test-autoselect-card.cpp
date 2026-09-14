// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#include "../common/selectcard.hpp"

#include "atrs.hpp"

#include <gtest/gtest.h>

using namespace electronic_id;

TEST(electronic_id_test, autoSelectFailureWithUnsupportedCard)
{
    EXPECT_THROW({ autoSelectSupportedCard(); }, AutoSelectFailed);
}

TEST(electronic_id_test, autoSelectSuccessWithSupportedCardEstIDEMIA)
{
    PcscMock::setAtr(ESTEID_IDEMIA_V1_ATR);
    auto result = autoSelectSupportedCard();
    EXPECT_TRUE(result);
    EXPECT_EQ(result->name(), "EstEID IDEMIA v1");
    PcscMock::reset();
}

TEST(electronic_id_test, autoSelectSuccessWithSupportedCardLatV2)
{
    PcscMock::setAtr(LATEID_IDEMIA_V2_ATR);
    auto result = autoSelectSupportedCard();
    EXPECT_TRUE(result);
    EXPECT_EQ(result->name(), "LatEID IDEMIA v2");
    PcscMock::reset();
}

TEST(electronic_id_test, autoSelectSuccessWithSupportedCardFinV3)
{
    PcscMock::setAtr(FINEID_V3_ATR);
    auto result = autoSelectSupportedCard();
    EXPECT_TRUE(result);
    EXPECT_EQ(result->name(), "FinEID v3");
    PcscMock::reset();
}

TEST(electronic_id_test, autoSelectSuccessWithSupportedCardFinV4)
{
    PcscMock::setAtr(FINEID_V4_ATR);
    auto result = autoSelectSupportedCard();
    EXPECT_TRUE(result);
    EXPECT_EQ(result->name(), "FinEID v4");
    PcscMock::reset();
}
