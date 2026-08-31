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

    static constexpr byte_type HrvEID_ATR[] {0x3b, 0xff, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x45,
                                             0x00, 0x31, 0xb9, 0x64, 0x04, 0x44, 0xec, 0xc1, 0x73,
                                             0x94, 0x01, 0x80, 0x82, 0x90, 0x00, 0x12};
    // https://github.com/Fedict/eid-mw/wiki/Applet-1.8
    static constexpr byte_type BelEID_ATR[] {0x3b, 0x7f, 0x96, 0x00, 0x00, 0x80, 0x31,
                                             0x80, 0x65, 0xb0, 0x85, 0x04, 0x01, 0x20,
                                             0x12, 0x0f, 0xff, 0x82, 0x90, 0x00};
    static constexpr byte_type CzeEID_ATR[] {0x3b, 0x7e, 0x94, 0x00, 0x00, 0x80, 0x25,
                                             0xd2, 0x03, 0x10, 0x01, 0x00, 0x56, 0x00,
                                             0x00, 0x00, 0x02, 0x02, 0x00};

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
