/*
 * Copyright (c) 2022-2024 Estonian Information System Authority
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

#pragma once

#include "electronic-id/electronic-id.hpp"
#include "pcsc-cpp/pcsc-cpp-utils.hpp"

#include <windows.h>
#include <wincrypt.h>

namespace electronic_id
{

class MsCryptoApiElectronicID : public ElectronicID
{
public:
    MsCryptoApiElectronicID(PCCERT_CONTEXT certCtx, byte_vector&& cert, CertificateType cType,
                            bool isRsa, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE k, bool freeK) :
        ElectronicID {std::make_unique<pcsc_cpp::SmartCard>()}, certContext {certCtx},
        certData {cert}, certType {cType},
        // TODO: SignatureAlgorithm::PS?
        signatureAlgo {isRsa ? SignatureAlgorithm::RS : SignatureAlgorithm::ES}, key {k},
        freeKey {freeK}
    {
    }

    ~MsCryptoApiElectronicID()
    {
        if (freeKey) {
            NCryptFreeObject(key);
        }
        CertFreeCertificateContext(certContext);
    }

    PCSC_CPP_DISABLE_COPY_MOVE(MsCryptoApiElectronicID);

    // The following placeholders are not used as the external PIN dialog manages PIN length
    // validation.
    static const int8_t PIN_RETRY_COUNT_PLACEHOLDER = -1;
    static const uint8_t PIN_LENGTH_PLACEHOLDER = 0;

private:
    // Use the external dialog provided by the CryptoAPI cryptographic service provider.
    bool providesExternalPinDialog() const override { return true; }

    byte_vector getCertificate(const CertificateType typ) const override
    {
        if (typ != certType) {
            THROW(WrongCertificateTypeError,
                  "This electronic ID does not support " + std::string(typ) + " certificates");
        }
        return certData;
    }

    JsonWebSignatureAlgorithm authSignatureAlgorithm() const override;

    PinMinMaxLength authPinMinMaxLength() const override
    {
        return {PIN_LENGTH_PLACEHOLDER, PIN_LENGTH_PLACEHOLDER};
    }

    PinRetriesRemainingAndMax authPinRetriesLeft() const override
    {
        return {uint8_t(PIN_RETRY_COUNT_PLACEHOLDER), PIN_RETRY_COUNT_PLACEHOLDER};
    }

    byte_vector signWithAuthKey(byte_vector&& pin, const byte_vector& hash) const override;

    const std::set<SignatureAlgorithm>& supportedSigningAlgorithms() const override;

    PinMinMaxLength signingPinMinMaxLength() const override
    {
        return {PIN_LENGTH_PLACEHOLDER, PIN_LENGTH_PLACEHOLDER};
    }

    PinRetriesRemainingAndMax signingPinRetriesLeft() const override
    {
        return {uint8_t(PIN_RETRY_COUNT_PLACEHOLDER), PIN_RETRY_COUNT_PLACEHOLDER};
    }

    Signature signWithSigningKey(byte_vector&& pin, const byte_vector& hash,
                                 const HashAlgorithm hashAlgo) const override;

    std::string name() const override
    {
        // TODO: use NCryptGetProperty(key, NCRYPT_NAME_PROPERTY, ...).
        return "MS CryptoAPI electronic ID";
    }
    Type type() const override { return Type::MsCryptoApiEID; }

    ElectronicID::Signature sign(const byte_vector& hash, HashAlgorithm hashAlgo) const;

    PCCERT_CONTEXT certContext;
    const byte_vector certData;
    const CertificateType certType;
    const SignatureAlgorithm signatureAlgo;
    const HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key;
    const bool freeKey;
};

} // namespace electronic_id
