// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#include "../common/selectcard.hpp"

#include "gtest/gtest.h"

using namespace pcsc_cpp;

TEST(electronic_id_test, getCertificate)
{
    using namespace electronic_id;

    auto cardInfo = autoSelectSupportedCard();

    EXPECT_TRUE(cardInfo);

    printCardInfo(*cardInfo);

    auto certificate = cardInfo->getCertificate(CertificateType::AUTHENTICATION);

    std::cout << "Authentication certificate: " << certificate << '\n';

    certificate = cardInfo->getCertificate(CertificateType::SIGNING);

    std::cout << "Signing certificate: " << certificate << '\n';
}
