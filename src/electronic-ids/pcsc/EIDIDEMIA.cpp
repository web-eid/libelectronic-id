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

#include "EIDIDEMIA.hpp"

#include "pcsc-common.hpp"

using namespace pcsc_cpp;

namespace
{

const byte_vector::value_type PIN_PADDING_CHAR = 0xFF;
const byte_vector::value_type AUTH_PIN_REFERENCE = 0x01;

} // namespace

namespace electronic_id
{

byte_vector EIDIDEMIA::getCertificateImpl(const CertificateType type) const
{
    const std::vector<byte_vector> SELECT_AID_AND_CERT_FILE = {
        selectApplicationID().MAIN_AID,
        type.isAuthentication() ? selectApplicationID().AUTH_AID : selectApplicationID().SIGN_AID,
        type.isAuthentication() ? selectCertificate().AUTH_CERT : selectCertificate().SIGN_CERT,
    };
    return electronic_id::getCertificate(*card, SELECT_AID_AND_CERT_FILE);
}

byte_vector EIDIDEMIA::signWithAuthKeyImpl(const byte_vector& pin, const byte_vector& hash) const
{
    // Select authentication application and authentication security environment.
    transmitApduWithExpectedResponse(*card, selectApplicationID().MAIN_AID);
    transmitApduWithExpectedResponse(*card, selectApplicationID().AUTH_AID);
    transmitApduWithExpectedResponse(*card, selectSecurityEnv().AUTH_ENV);

    verifyPin(*card, AUTH_PIN_REFERENCE, pin, authPinMinMaxLength().first, pinBlockLength(),
              PIN_PADDING_CHAR);

    return internalAuthenticate(*card,
                                authSignatureAlgorithm().isRSAWithPKCS1Padding()
                                    ? addRSAOID(authSignatureAlgorithm().hashAlgorithm(), hash)
                                    : hash,
                                name());
}

ElectronicID::PinRetriesRemainingAndMax EIDIDEMIA::authPinRetriesLeftImpl() const
{
    transmitApduWithExpectedResponse(*card, selectApplicationID().MAIN_AID);
    return pinRetriesLeft(AUTH_PIN_REFERENCE);
}

ElectronicID::Signature EIDIDEMIA::signWithSigningKeyImpl(const byte_vector& pin,
                                                          const byte_vector& hash,
                                                          const HashAlgorithm hashAlgo) const
{
    // Select signing application and signing security environment.
    transmitApduWithExpectedResponse(*card, selectApplicationID().SIGN_AID);
    transmitApduWithExpectedResponse(*card, selectSecurityEnv().SIGN_ENV);

    verifyPin(*card, signingPinReference(), pin, signingPinMinMaxLength().first, pinBlockLength(),
              PIN_PADDING_CHAR);

    return {useInternalAuthenticateAndRSAWithPKCS1PaddingDuringSigning()
                ? internalAuthenticate(*card, addRSAOID(hashAlgo, hash), name())
                : computeSignature(*card, hash, name()),
            {signingSignatureAlgorithm(), hashAlgo}};
}

ElectronicID::PinRetriesRemainingAndMax EIDIDEMIA::signingPinRetriesLeftImpl() const
{
    transmitApduWithExpectedResponse(*card, selectApplicationID().SIGN_AID);
    return pinRetriesLeft(signingPinReference());
}

const SelectApplicationIDCmds& EIDIDEMIA::selectApplicationID() const
{
    static const auto selectAppIDCmds = SelectApplicationIDCmds {
        // Main AID.
        {0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00, 0x00, 0x00, 0x77, 0x01,
         0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00},
        // AWP AID.
        {0x00, 0xA4, 0x04, 0x0C, 0x0D, 0xe8, 0x28, 0xbd, 0x08, 0x0f, 0xf2, 0x50, 0x4f, 0x54, 0x20,
         0x41, 0x57, 0x50},
        // QSCD AID.
        {0x00, 0xA4, 0x04, 0x0C, 0x10, 0x51, 0x53, 0x43, 0x44, 0x20, 0x41,
         0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E},
    };
    return selectAppIDCmds;
}

const SelectCertificateCmds& EIDIDEMIA::selectCertificate() const
{
    static const auto selectCertCmds = SelectCertificateCmds {
        // Authentication certificate.
        {0x00, 0xA4, 0x02, 0x0C, 0x02, 0x34, 0x01},
        // Signing certificate.
        {0x00, 0xA4, 0x02, 0x0C, 0x02, 0x34, 0x1F},
    };
    return selectCertCmds;
}

ElectronicID::PinRetriesRemainingAndMax
EIDIDEMIA::pinRetriesLeft(byte_vector::value_type pinReference) const
{
    const pcsc_cpp::CommandApdu GET_DATA_ODD {0x00,
                                              0xCB,
                                              0x3F,
                                              0xFF,
                                              {0x4D, 0x08, 0x70, 0x06, 0xBF, 0x81,
                                               byte_vector::value_type(pinReference & 0x0F), 0x02,
                                               0xA0, 0x80},
                                              0x00};
    const auto response = card->transmit(GET_DATA_ODD);
    if (!response.isOK()) {
        THROW(SmartCardError,
              "Command GET DATA ODD failed with error "
                  + pcsc_cpp::bytes2hexstr(response.toBytes()));
    }
    return {uint8_t(response.data[13]), uint8_t(response.data[10])};
}

} // namespace electronic_id
