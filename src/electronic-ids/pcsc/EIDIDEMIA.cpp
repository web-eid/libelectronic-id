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

#include "../TLV.hpp"

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
const auto AUTH_CERT = CommandApdu::selectEF(0x09, {0xAD, 0xF1, 0x34, 0x01});
const auto SIGN_CERT = CommandApdu::selectEF(0x09, {0xAD, 0xF2, 0x34, 0x1F});

} // namespace

void EIDIDEMIA::selectMain(const SmartCard::Session& session)
{
    transmitApduWithExpectedResponse(session, MAIN_AID);
}

void EIDIDEMIA::selectADF1(const pcsc_cpp::SmartCard::Session& session)
{
    transmitApduWithExpectedResponse(session, ADF1_AID);
}

void EIDIDEMIA::selectADF2(const pcsc_cpp::SmartCard::Session& session)
{
    transmitApduWithExpectedResponse(session, ADF2_AID);
}

byte_vector EIDIDEMIA::getCertificateImpl(const pcsc_cpp::SmartCard::Session& session,
                                          const CertificateType type) const
{
    selectMain(session);
    // Set block lenght to 0xC0 to workaround for the 2018 v2 card, with reader Alcor Micro AU9540
    return readFile(session, type.isAuthentication() ? AUTH_CERT : SIGN_CERT, 0xC0);
}

EIDIDEMIA::KeyInfo EIDIDEMIA::authKeyRef(const pcsc_cpp::SmartCard::Session& /*session*/) const
{
    return {DEFAULT_AUTH_KEY_ID, true};
}

byte_vector EIDIDEMIA::signWithAuthKeyImpl(const pcsc_cpp::SmartCard::Session& session,
                                           byte_vector&& pin, const byte_vector& hash) const
{
    selectADF1(session);
    auto [keyId, isECC] = authKeyRef(session);
    selectSecurityEnv(session, 0xA4, isECC ? 0x04 : 0x02, keyId, name());

    verifyPin(session, AUTH_PIN_REFERENCE, std::move(pin), authPinMinMaxLength().first,
              authPinMinMaxLength().second, PIN_PADDING_CHAR);

    return internalAuthenticate(session,
                                authSignatureAlgorithm().isRSAWithPKCS1Padding()
                                    ? addRSAOID(authSignatureAlgorithm().hashAlgorithm(), hash)
                                    : hash,
                                name());
}

ElectronicID::PinRetriesRemainingAndMax
EIDIDEMIA::authPinRetriesLeftImpl(const pcsc_cpp::SmartCard::Session& session) const
{
    selectMain(session);
    return pinRetriesLeft(session, AUTH_PIN_REFERENCE);
}

EIDIDEMIA::KeyInfo EIDIDEMIA::signKeyRef(const pcsc_cpp::SmartCard::Session& /*session*/) const
{
    return {DEFAULT_SIGN_KEY_ID, true};
}

ElectronicID::Signature
EIDIDEMIA::signWithSigningKeyImpl(const pcsc_cpp::SmartCard::Session& session, byte_vector&& pin,
                                  const byte_vector& hash, const HashAlgorithm hashAlgo) const
{
    selectADF2(session);
    auto [keyRef, isECC] = signKeyRef(session);
    selectSecurityEnv(session, 0xB6, isECC ? 0x54 : 0x42, keyRef, name());
    verifyPin(session, SIGN_PIN_REFERENCE, std::move(pin), signingPinMinMaxLength().first,
              signingPinMinMaxLength().second, PIN_PADDING_CHAR);
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
    return {computeSignature(session, tmp, name()),
            {isECC ? SignatureAlgorithm::ES : SignatureAlgorithm::RS, hashAlgo}};
}

ElectronicID::PinRetriesRemainingAndMax
EIDIDEMIA::signingPinRetriesLeftImpl(const pcsc_cpp::SmartCard::Session& session) const
{
    selectADF2(session);
    return pinRetriesLeft(session, SIGN_PIN_REFERENCE);
}

ElectronicID::PinRetriesRemainingAndMax EIDIDEMIA::pinRetriesLeft(const SmartCard::Session& session,
                                                                  byte_type pinReference)
{
    auto ref = byte_type(pinReference & 0x0F);
    const pcsc_cpp::CommandApdu GET_DATA_ODD {
        0x00, 0xCB, 0x3F, 0xFF, {0x4D, 0x08, 0x70, 0x06, 0xBF, 0x81, ref, 0x02, 0xA0, 0x80}, 0x00};
    const auto response = session.transmit(GET_DATA_ODD);
    if (!response.isOK()) {
        THROW(SmartCardError, "Command GET DATA ODD failed with error " + response);
    }
    TLV info = TLV::path(TLV(response.data), 0x70, 0xBF8100 | ref, 0xA0);
    TLV max = info[0x9A];
    TLV tries = info[0x9B];
    if (max && tries) {
        return {*tries.begin, *max.begin};
    }
    THROW(SmartCardError, "Command GET DATA ODD failed: missing expected info");
}
