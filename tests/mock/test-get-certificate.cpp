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

#include "electronic-id/electronic-id.hpp"

#include "select-certificate-script.hpp"
#include "atrs.hpp"

#include <gtest/gtest.h>

using namespace electronic_id;

TEST(electronic_id_test, selectCertificateEstGEMALTO)
{
    PcscMock::setAtr(ESTEID_GEMALTO_V3_5_8_COLD_ATR);
    auto cardInfo = autoSelectSupportedCard();

    PcscMock::setApduScript(ESTEID_GEMALTO_V3_5_8_GET_AUTH_CERTIFICATE_AND_AUTHENTICATE);
    EXPECT_TRUE(cardInfo);
    EXPECT_EQ(cardInfo->eid().name(), "EstEID Gemalto v3.5.8");
    auto certificateAuth = cardInfo->eid().getCertificate(CertificateType::AUTHENTICATION);
    EXPECT_EQ(certificateAuth.size(), 1611u);

    auto authRetriesLeft = cardInfo->eid().authPinRetriesLeft();
    EXPECT_EQ(authRetriesLeft.first, 3u);
    EXPECT_EQ(authRetriesLeft.second, 3);

    PcscMock::setApduScript(ESTEID_GEMALTO_V3_5_8_GET_SIGN_CERTIFICATE_AND_SIGNING);
    EXPECT_TRUE(cardInfo);
    EXPECT_EQ(cardInfo->eid().name(), "EstEID Gemalto v3.5.8");
    auto certificateSign = cardInfo->eid().getCertificate(CertificateType::SIGNING);
    EXPECT_EQ(certificateSign.size(), 1478u);

    auto signingRetriesLeft = cardInfo->eid().signingPinRetriesLeft();
    EXPECT_EQ(signingRetriesLeft.first, 3u);
    EXPECT_EQ(signingRetriesLeft.second, 3);

    PcscMock::reset();
}

TEST(electronic_id_test, selectCertificateEstIDEMIA)
{
    PcscMock::setAtr(ESTEID_IDEMIA_V1_ATR);
    auto cardInfo = autoSelectSupportedCard();
    EXPECT_TRUE(cardInfo);
    EXPECT_EQ(cardInfo->eid().name(), "EstEID IDEMIA v1");

    PcscMock::setApduScript(ESTEID_IDEMIA_V1_SELECT_AUTH_CERTIFICATE_AND_AUTHENTICATE);
    auto certificateAuth = cardInfo->eid().getCertificate(CertificateType::AUTHENTICATION);
    EXPECT_EQ(certificateAuth.size(), 1031u);

    auto authRetriesLeft = cardInfo->eid().authPinRetriesLeft();
    EXPECT_EQ(authRetriesLeft.first, 3u);
    EXPECT_EQ(authRetriesLeft.second, 3);

    const JsonWebSignatureAlgorithm authAlgo = cardInfo->eid().authSignatureAlgorithm();
    EXPECT_EQ(authAlgo, JsonWebSignatureAlgorithm::ES384);
    const HashAlgorithm hashAlgo = authAlgo.hashAlgorithm();

    const pcsc_cpp::byte_vector authPin = {'1', '2', '3', '4'};
    const pcsc_cpp::byte_vector dataToSign = {'H', 'e', 'l', 'l', 'o', ' ',
                                              'w', 'o', 'r', 'l', 'd', '!'};
    const auto hash = calculateDigest(hashAlgo, dataToSign);
    const auto authSignature = cardInfo->eid().signWithAuthKey(authPin, hash);
    if (!verify(hashAlgo, certificateAuth, dataToSign, authSignature, false)) {
        throw std::runtime_error("Signature is invalid");
    }

    PcscMock::setApduScript(ESTEID_IDEMIA_V1_SELECT_SIGN_CERTIFICATE_AND_SIGNING);
    auto certificateSign = cardInfo->eid().getCertificate(CertificateType::SIGNING);
    EXPECT_EQ(certificateSign.size(), 1008u);

    auto signingRetriesLeft = cardInfo->eid().signingPinRetriesLeft();
    EXPECT_EQ(signingRetriesLeft.first, 3u);
    EXPECT_EQ(signingRetriesLeft.second, 3);

    const pcsc_cpp::byte_vector signPin = {'1', '2', '3', '4', '5'};
    EXPECT_EQ(cardInfo->eid().isSupportedSigningHashAlgorithm(hashAlgo), true);
    const auto signSignature = cardInfo->eid().signWithSigningKey(signPin, hash, hashAlgo);
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
    EXPECT_EQ(certificateAuth.size(), 1664u);

    auto authRetriesLeft = cardInfo->eid().authPinRetriesLeft();
    EXPECT_EQ(authRetriesLeft.first, 5u);
    EXPECT_EQ(authRetriesLeft.second, 5);

    const JsonWebSignatureAlgorithm authAlgo = cardInfo->eid().authSignatureAlgorithm();
    EXPECT_EQ(authAlgo, JsonWebSignatureAlgorithm::PS256);
    const HashAlgorithm hashAlgo = authAlgo.hashAlgorithm();

    const pcsc_cpp::byte_vector authPin = {'1', '2', '3', '4'};
    const pcsc_cpp::byte_vector dataToSign = {'H', 'e', 'l', 'l', 'o', ' ',
                                              'w', 'o', 'r', 'l', 'd', '!'};
    const auto hash = calculateDigest(hashAlgo, dataToSign);
    const auto authSignature = cardInfo->eid().signWithAuthKey(authPin, hash);
    if (!verify(hashAlgo, certificateAuth, dataToSign, authSignature, true)) {
        throw std::runtime_error("Signature is invalid");
    }

    PcscMock::setApduScript(FINEID_V3_SELECT_SIGN_CERTIFICATE_AND_SIGNING);
    auto certificateSign = cardInfo->eid().getCertificate(CertificateType::SIGNING);
    EXPECT_EQ(certificateSign.size(), 1487u);

    auto signingRetriesLeft = cardInfo->eid().signingPinRetriesLeft();
    EXPECT_EQ(signingRetriesLeft.first, 5u);
    EXPECT_EQ(signingRetriesLeft.second, 5);

    const pcsc_cpp::byte_vector signPin = {'1', '2', '3', '4', '5', '6'};
    EXPECT_EQ(cardInfo->eid().isSupportedSigningHashAlgorithm(hashAlgo), true);
    const auto signSignature = cardInfo->eid().signWithSigningKey(signPin, hash, hashAlgo);
    EXPECT_EQ(signSignature.second, SignatureAlgorithm::ES256);
    if (!verify(hashAlgo, certificateSign, dataToSign, signSignature.first, false)) {
        throw std::runtime_error("Signature is invalid");
    }

    PcscMock::reset();
}

TEST(electronic_id_test, selectCertificateLat_V1)
{
    PcscMock::setAtr(LATEID_IDEMIA_V1_ATR);

    auto cardInfo = autoSelectSupportedCard();
    EXPECT_TRUE(cardInfo);
    EXPECT_EQ(cardInfo->eid().name(), "LatEID IDEMIA v1");

    PcscMock::setApduScript(LATEID_IDEMIA_V1_SELECT_AUTH_CERTIFICATE_AND_AUTHENTICATE);
    auto certificateAuth = cardInfo->eid().getCertificate(CertificateType::AUTHENTICATION);
    EXPECT_EQ(certificateAuth.size(), 1873u);

    auto authRetriesLeft = cardInfo->eid().authPinRetriesLeft();
    EXPECT_EQ(authRetriesLeft.first, 3u);
    EXPECT_EQ(authRetriesLeft.second, 3);

    const JsonWebSignatureAlgorithm authAlgo = cardInfo->eid().authSignatureAlgorithm();
    EXPECT_EQ(authAlgo, JsonWebSignatureAlgorithm::RS256);
    const HashAlgorithm hashAlgo = authAlgo.hashAlgorithm();

    const pcsc_cpp::byte_vector authPin = {'1', '2', '3', '4'};
    const pcsc_cpp::byte_vector dataToSign = {'H', 'e', 'l', 'l', 'o', ' ',
                                              'w', 'o', 'r', 'l', 'd', '!'};
    const auto hash = calculateDigest(hashAlgo, dataToSign);
    const auto authSignature = cardInfo->eid().signWithAuthKey(authPin, hash);
    if (!verify(hashAlgo, certificateAuth, dataToSign, authSignature, false)) {
        throw std::runtime_error("Signature is invalid");
    }

    PcscMock::setApduScript(LATEID_IDEMIA_V1_SELECT_SIGN_CERTIFICATE_AND_SIGNING);
    auto certificateSign = cardInfo->eid().getCertificate(CertificateType::SIGNING);
    EXPECT_EQ(certificateSign.size(), 2292u);

    auto signingRetriesLeft = cardInfo->eid().signingPinRetriesLeft();
    EXPECT_EQ(signingRetriesLeft.first, 3u);
    EXPECT_EQ(signingRetriesLeft.second, 3);

    const pcsc_cpp::byte_vector signPin = {'1', '2', '3', '4', '5', '6'};
    EXPECT_EQ(cardInfo->eid().isSupportedSigningHashAlgorithm(hashAlgo), true);
    const auto signSignature = cardInfo->eid().signWithSigningKey(signPin, hash, hashAlgo);
    EXPECT_EQ(signSignature.second, SignatureAlgorithm::RS256);
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
    EXPECT_EQ(certificateAuth.size(), 1733u);

    auto authRetriesLeft = cardInfo->eid().authPinRetriesLeft();
    EXPECT_EQ(authRetriesLeft.first, 3u);
    EXPECT_EQ(authRetriesLeft.second, 3);

    const JsonWebSignatureAlgorithm authAlgo = cardInfo->eid().authSignatureAlgorithm();
    EXPECT_EQ(authAlgo, JsonWebSignatureAlgorithm::RS256);
    const HashAlgorithm hashAlgo = authAlgo.hashAlgorithm();

    const pcsc_cpp::byte_vector authPin = {'1', '2', '3', '4'};
    const pcsc_cpp::byte_vector dataToSign = {'H', 'e', 'l', 'l', 'o', ' ',
                                              'w', 'o', 'r', 'l', 'd', '!'};
    const auto hash = calculateDigest(hashAlgo, dataToSign);
    const auto authSignature = cardInfo->eid().signWithAuthKey(authPin, hash);
    if (!verify(hashAlgo, certificateAuth, dataToSign, authSignature, false)) {
        throw std::runtime_error("Signature is invalid");
    }

    PcscMock::setApduScript(LATEID_IDEMIA_V2_SELECT_SIGN_CERTIFICATE_AND_SIGNING);
    auto certificateSign = cardInfo->eid().getCertificate(CertificateType::SIGNING);
    EXPECT_EQ(certificateSign.size(), 2124u);

    auto signingRetriesLeft = cardInfo->eid().signingPinRetriesLeft();
    EXPECT_EQ(signingRetriesLeft.first, 3u);
    EXPECT_EQ(signingRetriesLeft.second, 3);

    const pcsc_cpp::byte_vector signPin = {'1', '2', '3', '4', '5', '6'};
    EXPECT_EQ(cardInfo->eid().isSupportedSigningHashAlgorithm(hashAlgo), true);
    const auto signSignature = cardInfo->eid().signWithSigningKey(signPin, hash, hashAlgo);
    EXPECT_EQ(signSignature.second, SignatureAlgorithm::RS256);
    if (!verify(hashAlgo, certificateSign, dataToSign, signSignature.first, false)) {
        throw std::runtime_error("Signature is invalid");
    }

    PcscMock::reset();
}
