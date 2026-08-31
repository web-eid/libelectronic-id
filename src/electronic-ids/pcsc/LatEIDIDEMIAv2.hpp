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
