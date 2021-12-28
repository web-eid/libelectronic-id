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

#include "FinEID.hpp"

#include "pcsc-common.hpp"

// FINEID specification:
// https://dvv.fi/documents/16079645/17324923/S1v30.pdf/0bad6ff1-1617-1b1f-ab49-56a2f36ecd38/S1v30.pdf

using namespace pcsc_cpp;

namespace
{

const byte_vector SELECT_MAIN_AID {0x00, 0xA4, 0x04, 0x00, 0x0C, 0xa0, 0x00, 0x00, 0x00,
                                   0x63, 0x50, 0x4b, 0x43, 0x53, 0x2d, 0x31, 0x35};

const byte_vector SELECT_MASTER_FILE {0x00, 0xa4, 0x00, 0x0C, 0x02, 0x3f, 0x00};

const std::vector<byte_vector> SELECT_AUTH_CERT_FILE = {
    SELECT_MAIN_AID,
    {0x00, 0xA4, 0x08, 0x0C, 0x02, 0x43, 0x31},
};
const std::vector<byte_vector> SELECT_SIGN_CERT_FILE = {
    SELECT_MAIN_AID,
    // {0x00, 0xA4, 0x08, 0x0C, 0x04, 0x50, 0x16, 0x43, 0x32}, // RSA
    {0x00, 0xA4, 0x08, 0x0C, 0x04, 0x50, 0x16, 0x43, 0x35}, // ECDSA
};

const byte_vector::value_type PIN_PADDING_CHAR = 0x00;
const byte_vector::value_type AUTH_PIN_REFERENCE = 0x11;
const byte_vector::value_type SIGNING_PIN_REFERENCE = 0x82;
const byte_vector::value_type AUTH_KEY_REFERENCE = 0x01;
// const byte_vector::value_type SIGNING_KEY_REFERENCE = 0x02; // RSA
const byte_vector::value_type SIGNING_KEY_REFERENCE = 0x03;
// const byte_vector::value_type RSA_PKCS15_ALGO = 0x02;
const byte_vector::value_type ECDSA_ALGO = 0x04;
const byte_vector::value_type RSA_PSS_ALGO = 0x05;

} // namespace

namespace electronic_id
{

byte_vector FinEIDv3::getCertificateImpl(const CertificateType type) const
{
    return electronic_id::getCertificate(
        *card, type.isAuthentication() ? SELECT_AUTH_CERT_FILE : SELECT_SIGN_CERT_FILE);
}

byte_vector FinEIDv3::signWithAuthKeyImpl(const byte_vector& pin, const byte_vector& hash) const
{
    return sign(authSignatureAlgorithm().hashAlgorithm(), hash, pin, AUTH_PIN_REFERENCE,
                authPinMinMaxLength(), AUTH_KEY_REFERENCE, RSA_PSS_ALGO, 0);
}

ElectronicID::PinRetriesRemainingAndMax FinEIDv3::authPinRetriesLeftImpl() const
{
    return pinRetriesLeft(AUTH_PIN_REFERENCE);
}

const std::set<SignatureAlgorithm>& FinEIDv3::supportedSigningAlgorithms() const
{
    return ELLIPTIC_CURVE_SIGNATURE_ALGOS();
}

ElectronicID::Signature FinEIDv3::signWithSigningKeyImpl(const byte_vector& pin,
                                                         const byte_vector& hash,
                                                         const HashAlgorithm hashAlgo) const
{
    return {sign(hashAlgo, hash, pin, SIGNING_PIN_REFERENCE, signingPinMinMaxLength(),
                 SIGNING_KEY_REFERENCE, ECDSA_ALGO, 0x40),
            {SignatureAlgorithm::ES, hashAlgo}};
}

ElectronicID::PinRetriesRemainingAndMax FinEIDv3::signingPinRetriesLeftImpl() const
{
    return pinRetriesLeft(SIGNING_PIN_REFERENCE);
}

byte_vector FinEIDv3::sign(const HashAlgorithm hashAlgo, const byte_vector& hash,
                           const byte_vector& pin, byte_vector::value_type pinReference,
                           PinMinMaxLength pinMinMaxLength, byte_vector::value_type keyReference,
                           byte_vector::value_type signatureAlgo, byte_vector::value_type LE) const
{
    if (signatureAlgo != ECDSA_ALGO && hashAlgo.isSHA3()) {
        THROW(ArgumentFatalError, "No OID for algorithm " + std::string(hashAlgo));
    }

    switch (hashAlgo) {
    case HashAlgorithm::SHA224:
    case HashAlgorithm::SHA3_224:
        signatureAlgo |= 0x30;
        break;
    case HashAlgorithm::SHA256:
    case HashAlgorithm::SHA3_256:
        signatureAlgo |= 0x40;
        break;
    case HashAlgorithm::SHA384:
    case HashAlgorithm::SHA3_384:
        signatureAlgo |= 0x50;
        break;
    case HashAlgorithm::SHA512:
    case HashAlgorithm::SHA3_512:
        signatureAlgo |= 0x60;
        break;
    default:
        THROW(ArgumentFatalError, "No OID for algorithm " + std::string(hashAlgo));
    }

    transmitApduWithExpectedResponse(*card, SELECT_MASTER_FILE);

    verifyPin(*card, pinReference, pin, pinMinMaxLength.first, pinMinMaxLength.second,
              PIN_PADDING_CHAR);
    // Select security environment for COMPUTE SIGNATURE.
    byte_vector selectSecurityEnv {0x00, 0x22,          0x41, 0xB6, 0x06,        0x80,
                                   0x01, signatureAlgo, 0x84, 0x01, keyReference};
    transmitApduWithExpectedResponse(*card, selectSecurityEnv);

    auto tlv = byte_vector {0x90, byte_vector::value_type(hash.size())};
    tlv.insert(tlv.cend(), hash.cbegin(), hash.cend());

    const auto computeSignature = CommandApdu {{0x00, 0x2A, 0x90, 0xA0}, tlv};
    const auto response = card->transmit(computeSignature);

    if (response.sw1 == ResponseApdu::WRONG_LENGTH) {
        THROW(SmartCardError,
              "Wrong data length in command COMPUTE SIGNATURE argument: "
                  + bytes2hexstr(response.toBytes()));
    }
    if (response.sw1 != ResponseApdu::OK) {
        THROW(SmartCardError,
              "Command COMPUTE SIGNATURE failed with error " + bytes2hexstr(response.toBytes()));
    }

    const auto getSignature = CommandApdu {0x00, 0x2A, 0x9E, 0x9A, {}, LE};
    const auto signature = card->transmit(getSignature);

    if (signature.sw1 == ResponseApdu::WRONG_LENGTH) {
        THROW(SmartCardError,
              "Wrong data length in command GET SIGNATURE argument: "
                  + bytes2hexstr(response.toBytes()));
    }
    if (signature.sw1 != ResponseApdu::OK) {
        THROW(SmartCardError,
              "Command GET SIGNATURE failed with error " + bytes2hexstr(response.toBytes()));
    }

    return signature.data;
}

ElectronicID::PinRetriesRemainingAndMax
FinEIDv3::pinRetriesLeft(byte_vector::value_type pinReference) const
{
    const pcsc_cpp::CommandApdu GET_DATA {
        0x00, 0xCB, 0x00, 0xFF, {0xA0, 0x03, 0x83, 0x01, pinReference}};
    const auto response = card->transmit(GET_DATA);
    if (!response.isOK()) {
        THROW(SmartCardError,
              "Command GET DATA failed with error " + pcsc_cpp::bytes2hexstr(response.toBytes()));
    }
    return {uint8_t(response.data[20]), int8_t(5)};
}

} // namespace electronic_id
