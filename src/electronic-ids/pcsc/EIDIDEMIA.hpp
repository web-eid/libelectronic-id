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
    byte_vector getCertificateImpl(const pcsc_cpp::SmartCard::Session& session,
                                   const CertificateType type) const override;

    PinRetriesRemainingAndMax
    authPinRetriesLeftImpl(const pcsc_cpp::SmartCard::Session& session) const override;
    JsonWebSignatureAlgorithm authSignatureAlgorithm() const override
    {
        return JsonWebSignatureAlgorithm::ES384;
    }
    virtual KeyInfo authKeyRef(const pcsc_cpp::SmartCard::Session& session) const;
    byte_vector signWithAuthKeyImpl(const pcsc_cpp::SmartCard::Session& session, byte_vector&& pin,
                                    const byte_vector& hash) const override;

    PinRetriesRemainingAndMax
    signingPinRetriesLeftImpl(const pcsc_cpp::SmartCard::Session& session) const override;
    const std::set<SignatureAlgorithm>& supportedSigningAlgorithms() const override
    {
        return ELLIPTIC_CURVE_SIGNATURE_ALGOS();
    }
    virtual KeyInfo signKeyRef(const pcsc_cpp::SmartCard::Session& session) const;
    Signature signWithSigningKeyImpl(const pcsc_cpp::SmartCard::Session& session, byte_vector&& pin,
                                     const byte_vector& hash,
                                     const HashAlgorithm hashAlgo) const override;

    static PinRetriesRemainingAndMax pinRetriesLeft(const pcsc_cpp::SmartCard::Session& session,
                                                    byte_type pinReference);

    static void selectMain(const pcsc_cpp::SmartCard::Session& session);
    static void selectADF1(const pcsc_cpp::SmartCard::Session& session);
    static void selectADF2(const pcsc_cpp::SmartCard::Session& session);
};

} // namespace electronic_id
