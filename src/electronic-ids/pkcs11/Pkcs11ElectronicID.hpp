// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#pragma once

#include "electronic-id/electronic-id.hpp"

#include "PKCS11CardManager.hpp"

namespace electronic_id
{

struct Pkcs11ElectronicIDModule
{
    const std::string name;
    const ElectronicID::Type type;
    const std::filesystem::path path;

    const int8_t retryMax;
    const bool allowsUsingLettersAndSpecialCharactersInPin;
    const bool providesExternalPinDialog;
};

class Pkcs11ElectronicID : public ElectronicID
{
public:
    explicit Pkcs11ElectronicID(ElectronicID::Type type);

private:
    bool allowsUsingLettersAndSpecialCharactersInPin() const override
    {
        return module.allowsUsingLettersAndSpecialCharactersInPin;
    }

    bool providesExternalPinDialog() const override { return module.providesExternalPinDialog; }

    byte_vector getCertificate(const CertificateType type) const override;

    JsonWebSignatureAlgorithm authSignatureAlgorithm() const override;
    PinMinMaxLength authPinMinMaxLength() const override;

    PinInfo authPinInfo() const override;
    byte_vector signWithAuthKey(byte_vector&& pin, const byte_vector& hash) const override;

    const std::set<SignatureAlgorithm>& supportedSigningAlgorithms() const override;
    PinMinMaxLength signingPinMinMaxLength() const override;

    PinInfo signingPinInfo() const override;
    Signature signWithSigningKey(byte_vector&& pin, const byte_vector& hash,
                                 const HashAlgorithm hashAlgo) const override;

    void release() const override;
    std::string name() const override { return module.name; }
    Type type() const override { return module.type; }

    const PKCS11CardManager::Token& token(CertificateType type) const;

    const Pkcs11ElectronicIDModule& module;
    mutable std::shared_ptr<PKCS11CardManager> manager;
    PKCS11CardManager::Token authToken;
    PKCS11CardManager::Token signingToken;
};

} // namespace electronic_id
