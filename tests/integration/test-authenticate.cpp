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
#include "../common/verify.hpp"

#include "gtest/gtest.h"

#include <iostream>

TEST(electronic_id_test, authenticate)
{
    using namespace electronic_id;
    using namespace pcsc_cpp;

    auto cardInfo = autoSelectSupportedCard();

    EXPECT_TRUE(cardInfo);

    std::cout << "Selected card: " << cardInfo->eid().name() << std::endl;

    byte_vector cert = cardInfo->eid().getCertificate(CertificateType::AUTHENTICATION);

    std::cout << "Does the reader have a PIN-pad? "
              << (cardInfo->eid().smartcard().readerHasPinPad() ? "yes" : "no") << std::endl;

    if (cardInfo->eid().authSignatureAlgorithm() != JsonWebSignatureAlgorithm::ES384
        && cardInfo->eid().authSignatureAlgorithm() != JsonWebSignatureAlgorithm::RS256
        && cardInfo->eid().authSignatureAlgorithm() != JsonWebSignatureAlgorithm::PS256) {
        // TODO: Add other algorithms as required.
        throw std::runtime_error(
            "TEST authenticate: Only ES384, RS256 and PS256 signature algorithm "
            "currently supported");
    }

    GTEST_ASSERT_GE(cardInfo->eid().authPinRetriesLeft().first, 0u);

    const auto pin = cardInfo->eid().name() == "EstEID Gemalto v3.5.8"
        ? byte_vector {'0', '0', '9', '0'} // Gemalto test card default PIN1
        : byte_vector {'1', '2', '3', '4'};

    std::cout << "WARNING! Using hard-coded PIN "
              << std::string(reinterpret_cast<const char*>(pin.data()), pin.size()) << std::endl;

    const byte_vector dataToSign = {'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'};
    const JsonWebSignatureAlgorithm hashAlgo = cardInfo->eid().authSignatureAlgorithm();
    const byte_vector hash = calculateDigest(hashAlgo.hashAlgorithm(), dataToSign);
    auto signature = cardInfo->eid().signWithAuthKey(pin, hash);

    std::cout << "Authentication signature: " << pcsc_cpp::bytes2hexstr(signature) << std::endl;

    if (!verify(hashAlgo.hashAlgorithm(), cert, dataToSign, signature,
                hashAlgo == JsonWebSignatureAlgorithm::PS256)) {
        throw std::runtime_error("Signature is invalid");
    }
}
