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

struct SelectApplicationIDCmds
{
    const pcsc_cpp::CommandApdu MAIN_AID;
    const pcsc_cpp::CommandApdu AUTH_AID;
    const pcsc_cpp::CommandApdu SIGN_AID;
};

struct SelectCertificateCmds
{
    const pcsc_cpp::CommandApdu AUTH_CERT;
    const pcsc_cpp::CommandApdu SIGN_CERT;
};

class EIDIDEMIA : public PcscElectronicID
{
public:
    explicit EIDIDEMIA(pcsc_cpp::SmartCard::ptr _card) : PcscElectronicID(std::move(_card)) {}

protected:
    byte_vector getCertificateImpl(const CertificateType type) const override;

    PinRetriesRemainingAndMax authPinRetriesLeftImpl() const override;
    byte_vector signWithAuthKeyImpl(const byte_vector& pin, const byte_vector& hash) const override;

    PinRetriesRemainingAndMax signingPinRetriesLeftImpl() const override;
    Signature signWithSigningKeyImpl(const byte_vector& pin, const byte_vector& hash,
                                     const HashAlgorithm hashAlgo) const override;

    virtual const SelectApplicationIDCmds& selectApplicationID() const;
    virtual const SelectCertificateCmds& selectCertificate() const;
    virtual void selectAuthSecurityEnv() const = 0;
    virtual pcsc_cpp::byte_type selectSignSecurityEnv() const = 0;

    virtual size_t pinBlockLength() const { return authPinMinMaxLength().second; }
    virtual byte_type signingPinReference() const { return 0x85; }
    virtual SignatureAlgorithm signingSignatureAlgorithm() const = 0;
    PinRetriesRemainingAndMax pinRetriesLeft(byte_type pinReference) const;

    virtual bool useInternalAuthenticateAndRSAWithPKCS1PaddingDuringSigning() const
    {
        return false;
    }
};

} // namespace electronic_id
