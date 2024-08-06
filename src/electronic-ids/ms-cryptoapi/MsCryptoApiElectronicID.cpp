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

#include "MsCryptoApiElectronicID.hpp"
#include "../x509.hpp"

using namespace pcsc_cpp;

namespace electronic_id
{

JsonWebSignatureAlgorithm MsCryptoApiElectronicID::authSignatureAlgorithm() const
{
    // TODO: PS256
    return getAuthAlgorithmFromCert(certData);
}

byte_vector MsCryptoApiElectronicID::signWithAuthKey(byte_vector&& /* pin */,
                                                     const byte_vector& hash) const
{
    if (certType != CertificateType::AUTHENTICATION) {
        THROW(WrongCertificateTypeError,
              "This electronic ID does not support signing with the authentication key. "
              "It contains a "
                  + std::string(certType) + " certificate.");
    }

    validateAuthHashLength(authSignatureAlgorithm(), name(), hash);

    auto signature = sign(hash, authSignatureAlgorithm().hashAlgorithm());
    return std::move(signature.first);
}

const std::set<SignatureAlgorithm>& MsCryptoApiElectronicID::supportedSigningAlgorithms() const
{
    return getSignAlgorithmFromCert(certData);
}

ElectronicID::Signature
MsCryptoApiElectronicID::signWithSigningKey(byte_vector&& /* pin */, const byte_vector& hash,
                                            const HashAlgorithm hashAlgo) const
{
    if (certType != CertificateType::SIGNING) {
        THROW(WrongCertificateTypeError,
              "This electronic ID does not support signing with the digital signature key. "
              "It contains a "
                  + std::string(certType) + " certificate.");
    }

    validateSigningHash(*this, hashAlgo, hash);

    return sign(hash, hashAlgo);
}

ElectronicID::Signature MsCryptoApiElectronicID::sign(const byte_vector& hash,
                                                      HashAlgorithm hashAlgo) const
{
    bool isRSA = signatureAlgo != SignatureAlgorithm::ES;
    BCRYPT_PKCS1_PADDING_INFO padInfo {};
    switch (hashAlgo) {
    case HashAlgorithm::SHA224:
        padInfo.pszAlgId = L"SHA224";
        break;
    case HashAlgorithm::SHA256:
        padInfo.pszAlgId = NCRYPT_SHA256_ALGORITHM;
        break;
    case HashAlgorithm::SHA384:
        padInfo.pszAlgId = NCRYPT_SHA384_ALGORITHM;
        break;
    case HashAlgorithm::SHA512:
        padInfo.pszAlgId = NCRYPT_SHA512_ALGORITHM;
        break;
    default:
        // FIXME: what about HashAlgorithm::SHA3_*?
        THROW(ArgumentFatalError,
              "Hash algorithm " + std::to_string(hashAlgo) + " is not supported");
    }

    DWORD size = 0;
    SECURITY_STATUS err =
        NCryptSignHash(key, isRSA ? &padInfo : nullptr, PBYTE(hash.data()), DWORD(hash.size()),
                       nullptr, 0, LPDWORD(&size), isRSA ? BCRYPT_PAD_PKCS1 : 0);
    if (FAILED(err)) {
        THROW(MsCryptoApiError, "Signature buffer size query failed: " + std::to_string(err));
    }

    byte_vector signature(size);
    err = NCryptSignHash(key, isRSA ? &padInfo : nullptr, PBYTE(hash.data()), DWORD(hash.size()),
                         signature.data(), DWORD(signature.size()), LPDWORD(&size),
                         isRSA ? BCRYPT_PAD_PKCS1 : 0);
    switch (err) {
    case ERROR_SUCCESS:
        break;
    case SCARD_W_CANCELLED_BY_USER:
    case ERROR_CANCELLED:
        throw VerifyPinFailed(VerifyPinFailed::Status::PIN_ENTRY_CANCEL);
    case SCARD_W_WRONG_CHV:
    case SCARD_E_INVALID_CHV:
    case ERROR_INVALID_PARAMETER:
        // TODO: find a way to avoid relying on PIN_RETRY_COUNT_PLACEHOLDER.
        throw VerifyPinFailed(VerifyPinFailed::Status::RETRY_ALLOWED, nullptr,
                              MsCryptoApiElectronicID::PIN_RETRY_COUNT_PLACEHOLDER);
    case SCARD_W_CHV_BLOCKED:
        throw VerifyPinFailed(VerifyPinFailed::Status::PIN_BLOCKED);
    default:
        THROW(MsCryptoApiError, "Signing failed with error: " + std::to_string(err));
    }

    return {signature, {signatureAlgo, hashAlgo}};
}

} // namespace electronic_id
