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

constexpr byte_type PIN_PADDING_CHAR = 0xFF;
constexpr byte_type AUTH_PIN_REFERENCE = 0x01;
constexpr byte_type SIGN_PIN_REFERENCE = 0x85;
constexpr byte_type DEFAULT_AUTH_KEY_ID = 0x81;
constexpr byte_type DEFAULT_SIGN_KEY_ID = 0x9F;

const auto MAIN_AID = CommandApdu::select(0x04,
                                          {0xA0, 0x00, 0x00, 0x00, 0x77, 0x01, 0x08, 0x00, 0x07,
                                           0x00, 0x00, 0xFE, 0x00, 0x00, 0x01, 0x00});
const auto ADF1_AID = CommandApdu::select(
    0x04, {0xe8, 0x28, 0xbd, 0x08, 0x0f, 0xf2, 0x50, 0x4f, 0x54, 0x20, 0x41, 0x57, 0x50});
const auto ADF2_AID = CommandApdu::select(0x04,
                                          {0x51, 0x53, 0x43, 0x44, 0x20, 0x41, 0x70, 0x70, 0x6C,
                                           0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E});
const auto AUTH_CERT = CommandApdu::select(0x09, {0xAD, 0xF1, 0x34, 0x01});
const auto SIGN_CERT = CommandApdu::select(0x09, {0xAD, 0xF2, 0x34, 0x1F});

} // namespace

void EIDIDEMIA::selectMain() const
{
    transmitApduWithExpectedResponse(*card, MAIN_AID);
}

void EIDIDEMIA::selectADF1() const
{
    transmitApduWithExpectedResponse(*card, ADF1_AID);
}

void EIDIDEMIA::selectADF2() const
{
    transmitApduWithExpectedResponse(*card, ADF2_AID);
}

byte_vector EIDIDEMIA::getCertificateImpl(const CertificateType type) const
{
    selectMain();
    return electronic_id::getCertificate(*card, type.isAuthentication() ? AUTH_CERT : SIGN_CERT);
}

EIDIDEMIA::KeyInfo EIDIDEMIA::authKeyRef() const
{
    return {DEFAULT_AUTH_KEY_ID, true};
}

byte_vector EIDIDEMIA::signWithAuthKeyImpl(byte_vector&& pin, const byte_vector& hash) const
{
    selectADF1();
    auto [keyId, isECC] = authKeyRef();
    selectSecurityEnv(*card, 0xA4, isECC ? 0x04 : 0x02, keyId, name());

    verifyPin(*card, AUTH_PIN_REFERENCE, std::move(pin), authPinMinMaxLength().first,
              authPinMinMaxLength().second, PIN_PADDING_CHAR);

    return internalAuthenticate(*card,
                                authSignatureAlgorithm().isRSAWithPKCS1Padding()
                                    ? addRSAOID(authSignatureAlgorithm().hashAlgorithm(), hash)
                                    : hash,
                                name());
}

ElectronicID::PinRetriesRemainingAndMax EIDIDEMIA::authPinRetriesLeftImpl() const
{
    selectMain();
    return pinRetriesLeft(AUTH_PIN_REFERENCE);
}

EIDIDEMIA::KeyInfo EIDIDEMIA::signKeyRef() const
{
    return {DEFAULT_SIGN_KEY_ID, true};
}

ElectronicID::Signature EIDIDEMIA::signWithSigningKeyImpl(byte_vector&& pin,
                                                          const byte_vector& hash,
                                                          const HashAlgorithm hashAlgo) const
{
    selectADF2();
    auto [keyRef, isECC] = signKeyRef();
    selectSecurityEnv(*card, 0xB6, isECC ? 0x54 : 0x42, keyRef, name());
    auto tmp = hash;
    if (isECC) {
        constexpr size_t ECDSA384_INPUT_LENGTH = 384 / 8;
        if (tmp.size() < ECDSA384_INPUT_LENGTH) {
            // Zero-pad hashes that are shorter than SHA-384.
            tmp.insert(tmp.cbegin(), ECDSA384_INPUT_LENGTH - tmp.size(), 0x00);
        } else if (tmp.size() > ECDSA384_INPUT_LENGTH) {
            // Truncate hashes that are longer than SHA-384.
            tmp.resize(ECDSA384_INPUT_LENGTH);
        }
    }

    verifyPin(*card, SIGN_PIN_REFERENCE, std::move(pin), signingPinMinMaxLength().first,
              signingPinMinMaxLength().second, PIN_PADDING_CHAR);

    return {computeSignature(*card, tmp, name()),
            {isECC ? SignatureAlgorithm::ES : SignatureAlgorithm::RS, hashAlgo}};
}

ElectronicID::PinRetriesRemainingAndMax EIDIDEMIA::signingPinRetriesLeftImpl() const
{
    selectADF2();
    return pinRetriesLeft(SIGN_PIN_REFERENCE);
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
        THROW(SmartCardError, "Command GET DATA ODD failed with error " + response);
    }
    if (response.data.size() < 14) {
        THROW(SmartCardError,
              "Command GET DATA ODD failed: received data size "
                  + std::to_string(response.data.size())
                  + " is less than the expected size of the PIN remaining retries offset 14");
    }
    return {uint8_t(response.data[13]), uint8_t(response.data[10])};
}
