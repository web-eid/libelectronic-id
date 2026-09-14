// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#pragma once

#include "electronic-id/electronic-id.hpp"

#include "../common.hpp"

namespace electronic_id
{

class PcscElectronicID : public ElectronicID
{
public:
    using SmartCard = pcsc_cpp::SmartCard;

    explicit PcscElectronicID(SmartCard&& _card) : ElectronicID(std::move(_card)) {}

    constexpr PinMinMaxLength authPinMinMaxLength() const override { return {4, 12}; }
    constexpr JsonWebSignatureAlgorithm authSignatureAlgorithm() const override
    {
        return JsonWebSignatureAlgorithm::ES384;
    }
    const std::set<SignatureAlgorithm>& supportedSigningAlgorithms() const override
    {
        return ELLIPTIC_CURVE_SIGNATURE_ALGOS();
    }

protected:
    byte_vector getCertificate(const CertificateType type) const override
    {
        return getCertificateImpl(card.beginSession(), type);
    }

    byte_vector signWithAuthKey(byte_vector&& pin, const byte_vector& hash) const override
    {
        validateAuthHashLength(authSignatureAlgorithm(), name(), hash);
        return signWithAuthKeyImpl(card.beginSession(), std::move(pin), hash);
    }

    Signature signWithSigningKey(byte_vector&& pin, const byte_vector& hash,
                                 const HashAlgorithm hashAlgo) const override
    {
        validateSigningHash(*this, hashAlgo, hash);
        return signWithSigningKeyImpl(card.beginSession(), std::move(pin), hash, hashAlgo);
    }

    PinInfo signingPinInfo() const override { return signingPinInfoImpl(card.beginSession()); }

    PinInfo authPinInfo() const override { return authPinInfoImpl(card.beginSession()); }

    // The following pure virtual *Impl functions are the interface of all
    // PC/SC electronic ID implementations,
    // they have to be implemented when adding a new electronic ID.
    // This design follows the non-virtual interface pattern.

    virtual byte_vector getCertificateImpl(const SmartCard::Session& session,
                                           const CertificateType type) const = 0;

    virtual byte_vector signWithAuthKeyImpl(const SmartCard::Session& session, byte_vector&& pin,
                                            const byte_vector& hash) const = 0;

    virtual PinInfo authPinInfoImpl(const SmartCard::Session& session) const = 0;

    virtual Signature signWithSigningKeyImpl(const SmartCard::Session& session, byte_vector&& pin,
                                             const byte_vector& hash,
                                             const HashAlgorithm hashAlgo) const = 0;

    virtual PinInfo signingPinInfoImpl(const SmartCard::Session& session) const = 0;
};

} // namespace electronic_id
