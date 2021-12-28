/*
 * Copyright (c) 2020-2022 Estonian Information System Authority
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

#include "electronic-id/electronic-id.hpp"

#include "gtest/gtest.h"

#include <iostream>

TEST(electronic_id_test, getCertificate)
{
    using namespace electronic_id;

    auto cardInfo = autoSelectSupportedCard();

    EXPECT_TRUE(cardInfo);

    std::cout << "Selected card: " << cardInfo->eid().name() << std::endl;

    auto certificate = cardInfo->eid().getCertificate(CertificateType::AUTHENTICATION);

    std::cout << "Authentication certificate: " << pcsc_cpp::bytes2hexstr(certificate) << std::endl;

    certificate = cardInfo->eid().getCertificate(CertificateType::SIGNING);

    std::cout << "Signing certificate: " << pcsc_cpp::bytes2hexstr(certificate) << std::endl;
}
