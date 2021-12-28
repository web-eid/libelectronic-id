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

#include "EstEIDGemalto.hpp"

#include "pcsc-common.hpp"

// ESTEID specification:
// https://www.id.ee/public/RIA-EstEID-Chip-App-v3.5.8_fix_form.pdf

using namespace pcsc_cpp;

namespace
{

const byte_vector MASTER_FILE = {0x00, 0xa4, 0x00, 0x0c};

const std::vector<byte_vector> SELECT_EE_DIR_AND_AUTH_CERT_FILE {
    MASTER_FILE,
    // Select EE directory.
    {0x00, 0xa4, 0x01, 0x0c, 0x02, 0xee, 0xee},
    // Select authentication certificate file.
    {0x00, 0xa4, 0x02, 0x0c, 0x02, 0xaa, 0xce},
};

const std::vector<byte_vector> SELECT_EE_DIR_AND_SIGN_CERT_FILE {
    MASTER_FILE,
    // Select EE directory.
    {0x00, 0xa4, 0x01, 0x0c, 0x02, 0xee, 0xee},
    // Select signing certificate file.
    {0x00, 0xa4, 0x02, 0x0c, 0x02, 0xdd, 0xce},
};

const byte_vector::value_type AUTH_PIN_REFERENCE = 0x01;
const byte_vector::value_type SIGNING_PIN_REFERENCE = 0x02;

} // namespace

namespace electronic_id
{

byte_vector EstEIDGemaltoV3_5_8::getCertificateImpl(const CertificateType type) const
{
    return electronic_id::getCertificate(*card,
                                         type.isAuthentication()
                                             ? SELECT_EE_DIR_AND_AUTH_CERT_FILE
                                             : SELECT_EE_DIR_AND_SIGN_CERT_FILE);
}

byte_vector EstEIDGemaltoV3_5_8::signWithAuthKeyImpl(const byte_vector& pin,
                                                     const byte_vector& hash) const
{
    verifyPin(*card, AUTH_PIN_REFERENCE, pin, authPinMinMaxLength().first, 0, 0);
    return internalAuthenticate(*card, hash, name());
}

ElectronicID::PinRetriesRemainingAndMax EstEIDGemaltoV3_5_8::authPinRetriesLeftImpl() const
{
    return pinRetriesLeft(AUTH_PIN_REFERENCE);
}

const std::set<SignatureAlgorithm>& EstEIDGemaltoV3_5_8::supportedSigningAlgorithms() const
{
    return ELLIPTIC_CURVE_SIGNATURE_ALGOS();
}

ElectronicID::Signature
EstEIDGemaltoV3_5_8::signWithSigningKeyImpl(const byte_vector& pin, const byte_vector& hash,
                                            const HashAlgorithm hashAlgo) const
{
    verifyPin(*card, SIGNING_PIN_REFERENCE, pin, signingPinMinMaxLength().first, 0, 0);
    return {computeSignature(*card, hash, name()), {SignatureAlgorithm::ES, hashAlgo}};
}

ElectronicID::PinRetriesRemainingAndMax EstEIDGemaltoV3_5_8::signingPinRetriesLeftImpl() const
{
    return pinRetriesLeft(SIGNING_PIN_REFERENCE);
}

ElectronicID::PinRetriesRemainingAndMax
EstEIDGemaltoV3_5_8::pinRetriesLeft(byte_vector::value_type pinReference) const
{
    static const CommandApdu PINRETRY {0x00, 0xA4, 0x02, 0x0C, {0x00, 0x16}};
    const CommandApdu READRECORD {0x00, 0xB2, pinReference, 0x04};
    transmitApduWithExpectedResponse(*card, MASTER_FILE);
    transmitApduWithExpectedResponse(*card, PINRETRY);
    const auto response = card->transmit(READRECORD);
    if (!response.isOK() || response.data.size() < 6) {
        THROW(SmartCardError,
              "Command READRECORD failed with error " + pcsc_cpp::bytes2hexstr(response.toBytes()));
    }
    return {uint8_t(response.data[5]), int8_t(3)};
}

} // namespace electronic_id
