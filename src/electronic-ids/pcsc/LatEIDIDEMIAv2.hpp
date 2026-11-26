// SPDX-FileCopyrightText: Estonian Information System Authority
// SPDX-License-Identifier: MIT

#pragma once

#include "EIDIDEMIA.hpp"

#include <map>

namespace electronic_id
{

struct TLV;

class LatEIDIDEMIAV2 : public EIDIDEMIA
{
public:
    explicit LatEIDIDEMIAV2(SmartCard&& _card);
    ~LatEIDIDEMIAV2() override;
    PCSC_CPP_DISABLE_COPY_MOVE(LatEIDIDEMIAV2);

    static constexpr byte_type ATR_COSMO_8[] {0x3b, 0xdb, 0x96, 0x00, 0x80, 0xb1, 0xfe, 0x45,
                                              0x1f, 0x83, 0x00, 0x12, 0x42, 0x8f, 0x53, 0x65,
                                              0x49, 0x44, 0x0f, 0x90, 0x00, 0x20};
    static constexpr byte_type ATR_COSMO_X[] {0x3b, 0xdc, 0x96, 0x00, 0x80, 0xb1, 0xfe, 0x45,
                                              0x1f, 0x83, 0x00, 0x12, 0x42, 0x8f, 0x54, 0x65,
                                              0x49, 0x44, 0x32, 0x0f, 0x90, 0x00, 0x12};

private:
    byte_vector getCertificateImpl(const SmartCard::Session& session,
                                   const CertificateType type) const override;

    JsonWebSignatureAlgorithm authSignatureAlgorithm() const override;

    const std::set<SignatureAlgorithm>& supportedSigningAlgorithms() const override;
    constexpr PinMinMaxLength signingPinMinMaxLength() const override { return {6, 12}; }

    std::string name() const override { return "LatEID IDEMIA v2"; }
    Type type() const override { return LatEID; }

    KeyInfo authKeyRef(const SmartCard::Session& session) const override;
    KeyInfo signKeyRef(const SmartCard::Session& session) const override;

    TLV readEF_File(const SmartCard::Session& session, byte_vector file, auto& cache) const;
    TLV readDCODInfo(const SmartCard::Session& session, byte_type type, auto& cache) const;
    KeyInfo readPrKDInfo(const SmartCard::Session& session, byte_type keyID, auto& cache) const;

    struct Private;
    std::unique_ptr<Private> data;
};

} // namespace electronic_id
