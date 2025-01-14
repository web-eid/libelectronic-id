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
#include "../common/verify.hpp"

#include "gtest/gtest.h"

#include <iostream>

TEST(electronic_id_test, authenticate)
{
    using namespace electronic_id;
    using namespace pcsc_cpp;

    auto cardInfo = autoSelectSupportedCard();

    EXPECT_TRUE(cardInfo);

    std::cout << "Selected card: " << cardInfo->eid().name() << '\n';

    byte_vector cert = cardInfo->eid().getCertificate(CertificateType::AUTHENTICATION);

    std::cout << "Does the reader have a PIN-pad? "
              << (cardInfo->eid().smartcard().readerHasPinPad() ? "yes" : "no") << '\n';

    switch (cardInfo->eid().authSignatureAlgorithm()) {
    case JsonWebSignatureAlgorithm::ES384:
    case JsonWebSignatureAlgorithm::RS256:
    case JsonWebSignatureAlgorithm::PS256:
        break;
    default:
        // TODO: Add other algorithms as required.
        throw std::runtime_error(
            "TEST authenticate: Only ES384, RS256 and PS256 signature algorithm "
            "currently supported");
    }

    GTEST_ASSERT_GE(cardInfo->eid().authPinRetriesLeft().first, 0U);

    byte_vector pin {'1', '2', '3', '4'};
    pin.reserve(64);

    std::cout << "WARNING! Using hard-coded PIN "
              << std::string_view(reinterpret_cast<const char*>(pin.data()), pin.size()) << '\n';

    const byte_vector dataToSign {'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'};
    const JsonWebSignatureAlgorithm hashAlgo = cardInfo->eid().authSignatureAlgorithm();
    const byte_vector hash = calculateDigest(hashAlgo.hashAlgorithm(), dataToSign);
    auto signature = cardInfo->eid().signWithAuthKey(std::move(pin), hash);

    std::cout << "Authentication signature: " << signature << '\n';

    if (!verify(hashAlgo.hashAlgorithm(), cert, dataToSign, signature,
                hashAlgo == JsonWebSignatureAlgorithm::PS256)) {
        throw std::runtime_error("Signature is invalid");
    }
}
