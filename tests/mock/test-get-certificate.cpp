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

#include "select-certificate-script.hpp"
#include "atrs.hpp"

#include <gtest/gtest.h>

using namespace electronic_id;

namespace
{
const pcsc_cpp::byte_vector dataToSign {'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '!'};
}

TEST(electronic_id_test, selectCertificateEstIDEMIA)
{
    PcscMock::setAtr(ESTEID_IDEMIA_V1_ATR);
    auto cardInfo = autoSelectSupportedCard();
    EXPECT_TRUE(cardInfo);
    EXPECT_EQ(cardInfo->eid().name(), "EstEID IDEMIA v1");

    PcscMock::setApduScript(ESTEID_IDEMIA_V1_SELECT_AUTH_CERTIFICATE_AND_AUTHENTICATE);
    auto certificateAuth = cardInfo->eid().getCertificate(CertificateType::AUTHENTICATION);
    EXPECT_EQ(certificateAuth.size(), 1031U);

    auto authRetriesLeft = cardInfo->eid().authPinRetriesLeft();
    EXPECT_EQ(authRetriesLeft.first, 3U);
    EXPECT_EQ(authRetriesLeft.second, 3);

    const JsonWebSignatureAlgorithm authAlgo = cardInfo->eid().authSignatureAlgorithm();
    EXPECT_EQ(authAlgo, JsonWebSignatureAlgorithm::ES384);
    const HashAlgorithm hashAlgo = authAlgo.hashAlgorithm();

    pcsc_cpp::byte_vector authPin {'1', '2', '3', '4'};
    authPin.reserve(12);

    const auto hash = calculateDigest(hashAlgo, dataToSign);
    const auto authSignature = cardInfo->eid().signWithAuthKey(std::move(authPin), hash);
    if (!verify(hashAlgo, certificateAuth, dataToSign, authSignature, false)) {
        throw std::runtime_error("Signature is invalid");
    }

    PcscMock::setApduScript(ESTEID_IDEMIA_V1_SELECT_SIGN_CERTIFICATE_AND_SIGNING);
    auto certificateSign = cardInfo->eid().getCertificate(CertificateType::SIGNING);
    EXPECT_EQ(certificateSign.size(), 1008U);

    auto signingRetriesLeft = cardInfo->eid().signingPinRetriesLeft();
    EXPECT_EQ(signingRetriesLeft.first, 3U);
    EXPECT_EQ(signingRetriesLeft.second, 3);

    pcsc_cpp::byte_vector signPin {'1', '2', '3', '4', '5'};
    signPin.reserve(12);

    EXPECT_EQ(cardInfo->eid().isSupportedSigningHashAlgorithm(hashAlgo), true);
    const auto signSignature =
        cardInfo->eid().signWithSigningKey(std::move(signPin), hash, hashAlgo);
    EXPECT_EQ(signSignature.second, SignatureAlgorithm::ES384);
    if (!verify(hashAlgo, certificateSign, dataToSign, signSignature.first, false)) {
        throw std::runtime_error("Signature is invalid");
    }

    PcscMock::reset();
}

TEST(electronic_id_test, selectCertificateFinV3)
{
    PcscMock::setAtr(FINEID_V3_ATR);

    auto cardInfo = autoSelectSupportedCard();
    EXPECT_TRUE(cardInfo);
    EXPECT_EQ(cardInfo->eid().name(), "FinEID v3");

    PcscMock::setApduScript(FINEID_V3_SELECT_AUTH_CERTIFICATE_AND_AUTHENTICATE);
    auto certificateAuth = cardInfo->eid().getCertificate(CertificateType::AUTHENTICATION);
    EXPECT_EQ(certificateAuth.size(), 1664U);

    auto authRetriesLeft = cardInfo->eid().authPinRetriesLeft();
    EXPECT_EQ(authRetriesLeft.first, 5U);
    EXPECT_EQ(authRetriesLeft.second, 5);

    const JsonWebSignatureAlgorithm authAlgo = cardInfo->eid().authSignatureAlgorithm();
    EXPECT_EQ(authAlgo, JsonWebSignatureAlgorithm::PS256);
    const HashAlgorithm hashAlgo = authAlgo.hashAlgorithm();

    pcsc_cpp::byte_vector authPin {'1', '2', '3', '4'};
    authPin.reserve(12);

    const auto hash = calculateDigest(hashAlgo, dataToSign);
    const auto authSignature = cardInfo->eid().signWithAuthKey(std::move(authPin), hash);
    if (!verify(hashAlgo, certificateAuth, dataToSign, authSignature, true)) {
        throw std::runtime_error("Signature is invalid");
    }

    PcscMock::setApduScript(FINEID_V3_SELECT_SIGN_CERTIFICATE_AND_SIGNING);
    auto certificateSign = cardInfo->eid().getCertificate(CertificateType::SIGNING);
    EXPECT_EQ(certificateSign.size(), 1487U);

    auto signingRetriesLeft = cardInfo->eid().signingPinRetriesLeft();
    EXPECT_EQ(signingRetriesLeft.first, 5U);
    EXPECT_EQ(signingRetriesLeft.second, 5);

    pcsc_cpp::byte_vector signPin {'1', '2', '3', '4', '5', '6'};
    signPin.reserve(12);

    EXPECT_EQ(cardInfo->eid().isSupportedSigningHashAlgorithm(hashAlgo), true);
    const auto signSignature =
        cardInfo->eid().signWithSigningKey(std::move(signPin), hash, hashAlgo);
    EXPECT_EQ(signSignature.second, SignatureAlgorithm::ES256);
    if (!verify(hashAlgo, certificateSign, dataToSign, signSignature.first, false)) {
        throw std::runtime_error("Signature is invalid");
    }

    PcscMock::reset();
}

TEST(electronic_id_test, selectCertificateFinV4)
{
    PcscMock::setAtr(FINEID_V4_ATR);

    auto cardInfo = autoSelectSupportedCard();
    EXPECT_TRUE(cardInfo);
    EXPECT_EQ(cardInfo->eid().name(), "FinEID v4");

    PcscMock::setApduScript(FINEID_V4_SELECT_AUTH_CERTIFICATE_AND_AUTHENTICATE);
    auto certificateAuth = cardInfo->eid().getCertificate(CertificateType::AUTHENTICATION);
    EXPECT_EQ(certificateAuth.size(), 1087U);

    auto authRetriesLeft = cardInfo->eid().authPinRetriesLeft();
    EXPECT_EQ(authRetriesLeft.first, 5U);
    EXPECT_EQ(authRetriesLeft.second, 5);

    const JsonWebSignatureAlgorithm authAlgo = cardInfo->eid().authSignatureAlgorithm();
    EXPECT_EQ(authAlgo, JsonWebSignatureAlgorithm::ES384);
    const HashAlgorithm hashAlgo = authAlgo.hashAlgorithm();

    pcsc_cpp::byte_vector authPin {'1', '2', '3', '4'};
    authPin.reserve(12);

    const auto hash = calculateDigest(hashAlgo, dataToSign);
    const auto authSignature = cardInfo->eid().signWithAuthKey(std::move(authPin), hash);
    if (!verify(hashAlgo, certificateAuth, dataToSign, authSignature, true)) {
        throw std::runtime_error("Signature is invalid");
    }

    PcscMock::setApduScript(FINEID_V4_SELECT_SIGN_CERTIFICATE_AND_SIGNING);
    auto certificateSign = cardInfo->eid().getCertificate(CertificateType::SIGNING);
    EXPECT_EQ(certificateSign.size(), 1144U);

    auto signingRetriesLeft = cardInfo->eid().signingPinRetriesLeft();
    EXPECT_EQ(signingRetriesLeft.first, 5U);
    EXPECT_EQ(signingRetriesLeft.second, 5);

    pcsc_cpp::byte_vector signPin {'1', '2', '3', '4', '5', '6'};
    signPin.reserve(12);

    EXPECT_EQ(cardInfo->eid().isSupportedSigningHashAlgorithm(hashAlgo), true);
    const auto signSignature =
        cardInfo->eid().signWithSigningKey(std::move(signPin), hash, hashAlgo);
    EXPECT_EQ(signSignature.second, SignatureAlgorithm::ES384);
    if (!verify(hashAlgo, certificateSign, dataToSign, signSignature.first, false)) {
        throw std::runtime_error("Signature is invalid");
    }

    PcscMock::reset();
}

TEST(electronic_id_test, selectCertificateLatV2)
{
    PcscMock::setAtr(LATEID_IDEMIA_V2_ATR);

    auto cardInfo = autoSelectSupportedCard();
    EXPECT_TRUE(cardInfo);
    EXPECT_EQ(cardInfo->eid().name(), "LatEID IDEMIA v2");

    PcscMock::setApduScript(LATEID_IDEMIA_V2_SELECT_AUTH_CERTIFICATE_AND_AUTHENTICATE);
    auto certificateAuth = cardInfo->eid().getCertificate(CertificateType::AUTHENTICATION);
    EXPECT_EQ(certificateAuth.size(), 1733U);

    auto authRetriesLeft = cardInfo->eid().authPinRetriesLeft();
    EXPECT_EQ(authRetriesLeft.first, 3U);
    EXPECT_EQ(authRetriesLeft.second, 3);

    const JsonWebSignatureAlgorithm authAlgo = cardInfo->eid().authSignatureAlgorithm();
    EXPECT_EQ(authAlgo, JsonWebSignatureAlgorithm::RS256);
    const HashAlgorithm hashAlgo = authAlgo.hashAlgorithm();

    pcsc_cpp::byte_vector authPin {'1', '2', '3', '4'};
    authPin.reserve(12);

    const auto hash = calculateDigest(hashAlgo, dataToSign);
    const auto authSignature = cardInfo->eid().signWithAuthKey(std::move(authPin), hash);
    if (!verify(hashAlgo, certificateAuth, dataToSign, authSignature, false)) {
        throw std::runtime_error("Signature is invalid");
    }

    PcscMock::setApduScript(LATEID_IDEMIA_V2_SELECT_SIGN_CERTIFICATE_AND_SIGNING);
    auto certificateSign = cardInfo->eid().getCertificate(CertificateType::SIGNING);
    EXPECT_EQ(certificateSign.size(), 2124U);

    auto signingRetriesLeft = cardInfo->eid().signingPinRetriesLeft();
    EXPECT_EQ(signingRetriesLeft.first, 3U);
    EXPECT_EQ(signingRetriesLeft.second, 3);

    pcsc_cpp::byte_vector signPin {'1', '2', '3', '4', '5', '6'};
    signPin.reserve(12);

    EXPECT_EQ(cardInfo->eid().isSupportedSigningHashAlgorithm(hashAlgo), true);
    const auto signSignature =
        cardInfo->eid().signWithSigningKey(std::move(signPin), hash, hashAlgo);
    EXPECT_EQ(signSignature.second, SignatureAlgorithm::RS256);
    if (!verify(hashAlgo, certificateSign, dataToSign, signSignature.first, false)) {
        throw std::runtime_error("Signature is invalid");
    }

    PcscMock::reset();
}
