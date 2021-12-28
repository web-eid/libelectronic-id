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

#include <algorithm>
#include <iostream>

using namespace electronic_id;
using namespace pcsc_cpp;

static void signing(const HashAlgorithm& hashAlgo)
{
    auto cardInfo = autoSelectSupportedCard();

    EXPECT_TRUE(cardInfo);

    std::cout << "Selected card: " << cardInfo->eid().name() << std::endl;

    if (!cardInfo->eid().isSupportedSigningHashAlgorithm(hashAlgo)) {
        std::string skip = "Card does not support hashing algorithm: " + std::string(hashAlgo);
        GTEST_SUCCESS_(skip.c_str());
        return;
    }

    byte_vector cert = cardInfo->eid().getCertificate(CertificateType::SIGNING);

    GTEST_ASSERT_GE(cardInfo->eid().signingPinRetriesLeft().first, 0U);

    byte_vector pin;
    if (cardInfo->eid().name() == "EstEID Gemalto v3.5.8")
        pin = byte_vector {'0', '1', '4', '9', '7'}; // Gemalto test card default PIN2
    else if (cardInfo->eid().name() == "EstEID IDEMIA v1")
        pin = byte_vector {'1', '2', '3', '4', '5'}; // EstIDEMIA test card default PIN2
    else if (cardInfo->eid().name() == "LatEID IDEMIA v1"
             || cardInfo->eid().name() == "LatEID IDEMIA v2")
        pin = byte_vector {'1', '2', '3', '4', '5', '6'}; // LatIDEMIA test card default PIN2
    else if (cardInfo->eid().name() == "FinEID v3")
        pin = byte_vector {'1', '2', '3', '4', '5', '6'}; // FinEID custom PIN
    else
        throw std::runtime_error("TEST signing: Unknown card");

    std::cout << "WARNING! Using hard-coded PIN "
              << std::string(reinterpret_cast<const char*>(pin.data()), pin.size()) << std::endl;

    const byte_vector dataToSign = {'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'};
    const byte_vector hash = calculateDigest(hashAlgo, dataToSign);
    auto signature = cardInfo->eid().signWithSigningKey(pin, hash, hashAlgo);

    std::cout << "Signing signature: " << pcsc_cpp::bytes2hexstr(signature.first) << std::endl;

    if (!verify(hashAlgo, cert, dataToSign, signature.first, false)) {
        throw std::runtime_error("Signature is invalid");
    }
}

TEST(electronic_id_test, signing_SHA256)
{
    signing(HashAlgorithm::SHA256);
}

TEST(electronic_id_test, signing_SHA3_256)
{
#if OPENSSL_VERSION_NUMBER >= 0x10101030L
    // https://github.com/openssl/openssl/commit/bf3797fe3b71d58791b20cf6bc2304284e7aaa85
    // "This OpenSSL version does not support SHA3-* algorithm";
    signing(HashAlgorithm::SHA3_256);
#endif
}
