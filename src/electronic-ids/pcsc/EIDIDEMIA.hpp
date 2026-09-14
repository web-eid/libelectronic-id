// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#pragma once

#include "PcscElectronicID.hpp"

namespace electronic_id
{

class EIDIDEMIA : public PcscElectronicID
{
public:
    struct KeyInfo
    {
        byte_type id;
        bool isECC;
    };

    using PcscElectronicID::PcscElectronicID;

protected:
    byte_vector getCertificateImpl(const SmartCard::Session& session,
                                   const CertificateType type) const override;

    PinInfo authPinInfoImpl(const SmartCard::Session& session) const override;
    virtual KeyInfo authKeyRef(const SmartCard::Session& session) const;
    byte_vector signWithAuthKeyImpl(const SmartCard::Session& session, byte_vector&& pin,
                                    const byte_vector& hash) const override;

    PinInfo signingPinInfoImpl(const SmartCard::Session& session) const override;
    virtual KeyInfo signKeyRef(const SmartCard::Session& session) const;
    Signature signWithSigningKeyImpl(const SmartCard::Session& session, byte_vector&& pin,
                                     const byte_vector& hash,
                                     const HashAlgorithm hashAlgo) const override;

    static PinInfo pinRetriesLeft(const SmartCard::Session& session, byte_type pinReference);

    static void selectMain(const SmartCard::Session& session);
    static void selectADF1(const SmartCard::Session& session);
    static void selectADF2(const SmartCard::Session& session);
};

} // namespace electronic_id
