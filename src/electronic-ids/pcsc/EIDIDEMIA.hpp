/*
 * Copyright (c) 2020-2022 Estonian Information System Authority
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
    const pcsc_cpp::byte_vector MAIN_AID;
    const pcsc_cpp::byte_vector AUTH_AID;
    const pcsc_cpp::byte_vector SIGN_AID;
};

struct SelectCertificateCmds
{
    const pcsc_cpp::byte_vector AUTH_CERT;
    const pcsc_cpp::byte_vector SIGN_CERT;
};

struct ManageSecurityEnvCmds
{
    const pcsc_cpp::byte_vector AUTH_ENV;
    const pcsc_cpp::byte_vector SIGN_ENV;
};

class EIDIDEMIA : public PcscElectronicID
{
public:
    EIDIDEMIA(pcsc_cpp::SmartCard::ptr _card) : PcscElectronicID(std::move(_card)) {}

protected:
    pcsc_cpp::byte_vector getCertificateImpl(const CertificateType type) const override;

    PinRetriesRemainingAndMax authPinRetriesLeftImpl() const override;
    pcsc_cpp::byte_vector signWithAuthKeyImpl(const pcsc_cpp::byte_vector& pin,
                                              const pcsc_cpp::byte_vector& hash) const override;

    PinRetriesRemainingAndMax signingPinRetriesLeftImpl() const override;
    Signature signWithSigningKeyImpl(const pcsc_cpp::byte_vector& pin,
                                     const pcsc_cpp::byte_vector& hash,
                                     const HashAlgorithm hashAlgo) const override;

    virtual const SelectApplicationIDCmds& selectApplicationID() const;
    virtual const SelectCertificateCmds& selectCertificate() const;
    virtual const ManageSecurityEnvCmds& selectSecurityEnv() const = 0;

    virtual size_t pinBlockLength() const { return authPinMinMaxLength().second; }
    virtual pcsc_cpp::byte_vector::value_type signingPinReference() const { return 0x85; }
    virtual SignatureAlgorithm signingSignatureAlgorithm() const = 0;
    PinRetriesRemainingAndMax pinRetriesLeft(pcsc_cpp::byte_vector::value_type pinReference) const;

    virtual bool useInternalAuthenticateAndRSAWithPKCS1PaddingDuringSigning() const
    {
        return false;
    }
};

} // namespace electronic_id
