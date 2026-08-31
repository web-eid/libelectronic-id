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
