/*
 * Copyright (c) 2020 The Web eID Project
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

#include "PKCS11CardManager.hpp"

namespace electronic_id
{

enum class Pkcs11ElectronicIDType {
    EstEIDIDEMIAV1,
    LitEID,
    HrvEID,
};

struct Pkcs11ElectronicIDModule
{
    std::string name;
    ElectronicID::Type type;
    std::string path;

    JsonWebSignatureAlgorithm authSignatureAlgorithm;
    std::set<SignatureAlgorithm> supportedSigningAlgorithms;
};

class Pkcs11ElectronicID : public ElectronicID
{
public:
    Pkcs11ElectronicID(pcsc_cpp::SmartCard::ptr card, Pkcs11ElectronicIDType type);

private:
    pcsc_cpp::byte_vector getCertificate(const CertificateType type) const override;

    JsonWebSignatureAlgorithm authSignatureAlgorithm() const override
    {
        return module.authSignatureAlgorithm;
    }
    PinMinMaxLength authPinMinMaxLength() const override;

    PinRetriesRemainingAndMax authPinRetriesLeft() const override;
    pcsc_cpp::byte_vector signWithAuthKey(const pcsc_cpp::byte_vector& pin,
                                          const pcsc_cpp::byte_vector& hash) const override;

    const std::set<SignatureAlgorithm>& supportedSigningAlgorithms() const override
    {
        return module.supportedSigningAlgorithms;
    }
    PinMinMaxLength signingPinMinMaxLength() const override;

    PinRetriesRemainingAndMax signingPinRetriesLeft() const override;
    Signature signWithSigningKey(const pcsc_cpp::byte_vector& pin,
                                 const pcsc_cpp::byte_vector& hash,
                                 const HashAlgorithm hashAlgo) const override;

    std::string name() const override { return module.name; }
    Type type() const override { return module.type; }

    const Pkcs11ElectronicIDModule& module;
    PKCS11CardManager manager;
    PKCS11CardManager::Token authToken;
    PKCS11CardManager::Token signingToken;
};

} // namespace electronic_id
