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

class EIDThales : public PcscElectronicID
{
public:
    using PcscElectronicID::PcscElectronicID;

protected:
    using CommandApdu = pcsc_cpp::CommandApdu;

    virtual PCSC_CPP_CONSTEXPR_VECTOR CommandApdu authCertFile() const = 0;
    virtual constexpr byte_type authPinReference() const = 0;
    virtual constexpr int8_t maximumPinRetries() const = 0;
    virtual PCSC_CPP_CONSTEXPR_VECTOR CommandApdu signCertFile() const = 0;
    virtual constexpr byte_type signingKeyReference() const = 0;

    byte_vector getCertificateImpl(const SmartCard::Session& session,
                                   const CertificateType type) const override;
    PinRetriesRemainingAndMax
    authPinRetriesLeftImpl(const SmartCard::Session& session) const override;
    PinRetriesRemainingAndMax
    signingPinRetriesLeftImpl(const SmartCard::Session& session) const override;
    byte_vector signWithAuthKeyImpl(const SmartCard::Session& session, byte_vector&& pin,
                                    const byte_vector& hash) const override;
    Signature signWithSigningKeyImpl(const SmartCard::Session& session, byte_vector&& pin,
                                     const byte_vector& hash,
                                     const HashAlgorithm hashAlgo) const override;

    PinRetriesRemainingAndMax pinRetriesLeft(const SmartCard::Session& session,
                                             byte_type pinReference) const;
    byte_vector sign(const SmartCard::Session& session, const HashAlgorithm hashAlgo,
                     const byte_vector& hash, byte_vector&& pin, byte_type pinReference,
                     PinMinMaxLength pinMinMaxLength, byte_type keyReference,
                     byte_type signatureAlgo) const;

    static constexpr byte_type AUTH_KEY_REFERENCE = 0x01;
};

} // namespace electronic_id