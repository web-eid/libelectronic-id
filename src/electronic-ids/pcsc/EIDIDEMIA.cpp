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

#include "EIDIDEMIA.hpp"

#include "pcsc-common.hpp"

using namespace pcsc_cpp;
using namespace electronic_id;

namespace
{

const byte_type PIN_PADDING_CHAR = 0xFF;
const byte_type AUTH_PIN_REFERENCE = 0x01;

} // namespace

byte_vector EIDIDEMIA::getCertificateImpl(const CertificateType type) const
{
    transmitApduWithExpectedResponse(*card, selectApplicationID().MAIN_AID);
    transmitApduWithExpectedResponse(*card,
                                     type.isAuthentication() ? selectApplicationID().AUTH_AID
                                                             : selectApplicationID().SIGN_AID);
    return electronic_id::getCertificate(*card,
                                         type.isAuthentication() ? selectCertificate().AUTH_CERT
                                                                 : selectCertificate().SIGN_CERT);
}

byte_vector EIDIDEMIA::signWithAuthKeyImpl(const byte_vector& pin, const byte_vector& hash) const
{
    // Select authentication application and authentication security environment.
    transmitApduWithExpectedResponse(*card, selectApplicationID().MAIN_AID);
    transmitApduWithExpectedResponse(*card, selectApplicationID().AUTH_AID);
    selectAuthSecurityEnv();

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
    pcsc_cpp::byte_type algo = selectSignSecurityEnv();
    auto tmp = hash;
    if (algo == 0x54) {
        constexpr size_t ECDSA384_INPUT_LENGTH = 384 / 8;
        if (tmp.size() < ECDSA384_INPUT_LENGTH) {
            // Zero-pad hashes that are shorter than SHA-384.
            tmp.insert(tmp.cbegin(), ECDSA384_INPUT_LENGTH - tmp.size(), 0x00);
        } else if (tmp.size() > ECDSA384_INPUT_LENGTH) {
            // Truncate hashes that are longer than SHA-384.
            tmp.resize(ECDSA384_INPUT_LENGTH);
        }
    }

    verifyPin(*card, signingPinReference(), pin, signingPinMinMaxLength().first, pinBlockLength(),
              PIN_PADDING_CHAR);

    return {useInternalAuthenticateAndRSAWithPKCS1PaddingDuringSigning()
                ? internalAuthenticate(*card, addRSAOID(hashAlgo, hash), name())
                : computeSignature(*card, tmp, name()),
            {signingSignatureAlgorithm(), hashAlgo}};
}

ElectronicID::PinRetriesRemainingAndMax EIDIDEMIA::signingPinRetriesLeftImpl() const
{
    transmitApduWithExpectedResponse(*card, selectApplicationID().SIGN_AID);
    return pinRetriesLeft(signingPinReference());
}

const SelectApplicationIDCmds& EIDIDEMIA::selectApplicationID() const
{
    static const SelectApplicationIDCmds selectAppIDCmds {
        // Main AID.
        {0x00,
         0xA4,
         0x04,
         0x00,
         {0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07, 0x00, 0x00, 0xFE, 0x00, 0x00, 0x01,
          0x00}},
        // AWP AID.
        {0x00,
         0xA4,
         0x04,
         0x0C,
         {0xe8, 0x28, 0xbd, 0x08, 0x0f, 0xf2, 0x50, 0x4f, 0x54, 0x20, 0x41, 0x57, 0x50}},
        // QSCD AID.
        {0x00,
         0xA4,
         0x04,
         0x0C,
         {0x51, 0x53, 0x43, 0x44, 0x20, 0x41, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F,
          0x6E}},
    };
    return selectAppIDCmds;
}

const SelectCertificateCmds& EIDIDEMIA::selectCertificate() const
{
    static const SelectCertificateCmds selectCert1Cmds {
        // Authentication certificate.
        {0x00, 0xA4, 0x02, 0x0C, {0x34, 0x01}},
        // Signing certificate.
        {0x00, 0xA4, 0x02, 0x0C, {0x34, 0x1F}},
    };
    return selectCert1Cmds;
}

ElectronicID::PinRetriesRemainingAndMax EIDIDEMIA::pinRetriesLeft(byte_type pinReference) const
{
    const pcsc_cpp::CommandApdu GET_DATA_ODD {
        0x00,
        0xCB,
        0x3F,
        0xFF,
        {0x4D, 0x08, 0x70, 0x06, 0xBF, 0x81, byte_type(pinReference & 0x0F), 0x02, 0xA0, 0x80},
        0x00};
    const auto response = card->transmit(GET_DATA_ODD);
    if (!response.isOK()) {
        THROW(SmartCardError,
              "Command GET DATA ODD failed with error "
                  + pcsc_cpp::bytes2hexstr(response.toBytes()));
    }
    if (response.data.size() < 14) {
        THROW(SmartCardError,
              "Command GET DATA ODD failed: received data size "
                  + std::to_string(response.data.size())
                  + " is less than the expected size of the PIN remaining retries offset 14");
    }
    return {uint8_t(response.data[13]), uint8_t(response.data[10])};
}
