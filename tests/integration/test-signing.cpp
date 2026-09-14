// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#include "../common/selectcard.hpp"
#include "../common/verify.hpp"

#include "gtest/gtest.h"

using namespace electronic_id;
using namespace pcsc_cpp;

static void signing(HashAlgorithm hashAlgo)
{
    auto cardInfo = autoSelectSupportedCard();

    EXPECT_TRUE(cardInfo);

    printCardInfo(*cardInfo);

    if (!cardInfo->isSupportedSigningHashAlgorithm(hashAlgo)) {
        std::string skip = "Card does not support hashing algorithm: " + std::string(hashAlgo);
        GTEST_SUCCESS_(skip.c_str());
        return;
    }

    byte_vector cert = cardInfo->getCertificate(CertificateType::SIGNING);

    GTEST_ASSERT_GE(cardInfo->signingPinInfo().retryCount, 0U);

    byte_vector pin;
    switch (cardInfo->type()) {
        using enum ElectronicID::Type;
    case ElectronicID::EstEID:
        pin = {'1', '2', '3', '4', '5'}; // EstEID test card default PIN2
        break;
    case ElectronicID::LatEID: // LatIDEMIA test card default PIN2
    case ElectronicID::FinEID: // FinEID custom PIN
        pin = {'1', '2', '3', '4', '5', '6'};
        break;
    default:
        throw std::runtime_error("TEST signing: Unknown card");
    }
    pin.reserve(64);

    std::cout << "WARNING! Using hard-coded PIN " << std::string(pin.cbegin(), pin.cend()) << '\n';

    const byte_vector dataToSign {'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'};
    const byte_vector hash = calculateDigest(hashAlgo, dataToSign);

    auto signature = cardInfo->signWithSigningKey(std::move(pin), hash, hashAlgo);

    std::cout << "Signing signature: " << signature.first << '\n';

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
