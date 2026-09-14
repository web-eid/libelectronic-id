// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#include "../common/selectcard.hpp"
#include "../common/verify.hpp"

#include "gtest/gtest.h"

TEST(electronic_id_test, authenticate)
{
    using namespace electronic_id;
    using namespace pcsc_cpp;

    auto cardInfo = autoSelectSupportedCard();

    EXPECT_TRUE(cardInfo);

    printCardInfo(*cardInfo);

    byte_vector cert = cardInfo->getCertificate(CertificateType::AUTHENTICATION);

    std::cout << "Does the reader have a PIN-pad? "
              << (cardInfo->smartcard().readerHasPinPad() ? "yes" : "no") << '\n';

    switch (cardInfo->authSignatureAlgorithm()) {
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

    GTEST_ASSERT_GE(cardInfo->authPinInfo().retryCount, 0U);

    byte_vector pin {'1', '2', '3', '4'};
    pin.reserve(64);

    std::cout << "WARNING! Using hard-coded PIN "
              << std::string_view(reinterpret_cast<const char*>(pin.data()), pin.size()) << '\n';

    const byte_vector dataToSign {'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'};
    const JsonWebSignatureAlgorithm hashAlgo = cardInfo->authSignatureAlgorithm();
    const byte_vector hash = calculateDigest(hashAlgo.hashAlgorithm(), dataToSign);
    auto signature = cardInfo->signWithAuthKey(std::move(pin), hash);

    std::cout << "Authentication signature: " << signature << '\n';

    if (!verify(hashAlgo.hashAlgorithm(), cert, dataToSign, signature,
                hashAlgo == JsonWebSignatureAlgorithm::PS256)) {
        throw std::runtime_error("Signature is invalid");
    }
}
