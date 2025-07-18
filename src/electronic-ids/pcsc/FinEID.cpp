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

#include "FinEID.hpp"

#include "../TLV.hpp"

#include "pcsc-common.hpp"

#include <array>

// FINEID specification:
// App 3.0:
// https://dvv.fi/documents/16079645/17324923/S1v30.pdf/0bad6ff1-1617-1b1f-ab49-56a2f36ecd38/S1v30.pdf
// Imp 3.0:
// https://dvv.fi/documents/16079645/17324923/S4-1v30%20(1).pdf/9ed19b95-098d-ec6b-6f31-8147d1f87663/S4-1v30%20(1).pdf
// Imp 3.1:
// https://dvv.fi/documents/16079645/17324992/S4-1v31.pdf/ca3e699e-fae8-aea2-9ce3-28846d2ae95a/S4-1v31.pdf
// App 4.0:
// https://dvv.fi/documents/16079645/17324992/S1v40+(1).pdf/56a167fe-9f26-1fda-7d76-cfbbb29d184e/S1v40+(1).pdf
// Imp 4.0:
// https://dvv.fi/documents/16079645/17324992/S4-1v40.pdf/55bddc08-6893-b4b4-73fa-24dced600198/S4-1v40.pdf

using namespace pcsc_cpp;

namespace
{

const auto SELECT_MAIN_AID = CommandApdu::select(
    0x04, {0xa0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4b, 0x43, 0x53, 0x2d, 0x31, 0x35});
const auto SELECT_AUTH_CERT_FILE = CommandApdu::selectEF(0x08, {0x43, 0x31});
const auto SELECT_AUTH_CERT_FILE_EST = CommandApdu::selectEF(0x08, {0xAD, 0xF1, 0x34, 0x11});
const auto SELECT_SIGN_CERT_FILE_V3 = CommandApdu::selectEF(0x08, {0x50, 0x16, 0x43, 0x35});
const auto SELECT_SIGN_CERT_FILE_V4 = CommandApdu::selectEF(0x08, {0x50, 0x16, 0x43, 0x32});
const auto SELECT_SIGN_CERT_FILE_EST = CommandApdu::selectEF(0x08, {0xAD, 0xF2, 0x34, 0x21});

constexpr byte_type PIN_PADDING_CHAR = 0x00;
constexpr byte_type AUTH_PIN_REFERENCE = 0x11;
constexpr byte_type AUTH_PIN_REFERENCE_EST = 0x81;
constexpr byte_type SIGNING_PIN_REFERENCE = 0x82;
constexpr byte_type AUTH_KEY_REFERENCE = 0x01;
constexpr byte_type SIGNING_KEY_REFERENCE_V3 = 0x03;
constexpr byte_type SIGNING_KEY_REFERENCE_V4 = 0x02;
constexpr byte_type SIGNING_KEY_REFERENCE_EST = 0x05;
constexpr byte_type ECDSA_ALGO = 0x04;
constexpr byte_type RSA_PSS_ALGO = 0x05;

} // namespace

namespace electronic_id
{

byte_vector FinEIDv3::getCertificateImpl(const pcsc_cpp::SmartCard::Session& session,
                                         const CertificateType type) const
{
    selectFile(session, SELECT_MAIN_AID);
    return readFile(session,
                    type.isAuthentication() ? SELECT_AUTH_CERT_FILE : SELECT_SIGN_CERT_FILE_V3);
}

byte_vector FinEIDv3::signWithAuthKeyImpl(const pcsc_cpp::SmartCard::Session& session,
                                          byte_vector&& pin, const byte_vector& hash) const
{
    return sign(session, authSignatureAlgorithm().hashAlgorithm(), hash, std::move(pin),
                AUTH_PIN_REFERENCE, authPinMinMaxLength(), AUTH_KEY_REFERENCE, RSA_PSS_ALGO);
}

ElectronicID::PinRetriesRemainingAndMax
FinEIDv3::authPinRetriesLeftImpl(const pcsc_cpp::SmartCard::Session& session) const
{
    return pinRetriesLeft(session, AUTH_PIN_REFERENCE);
}

const std::set<SignatureAlgorithm>& FinEIDv3::supportedSigningAlgorithms() const
{
    return ELLIPTIC_CURVE_SIGNATURE_ALGOS();
}

ElectronicID::Signature
FinEIDv3::signWithSigningKeyImpl(const pcsc_cpp::SmartCard::Session& session, byte_vector&& pin,
                                 const byte_vector& hash, const HashAlgorithm hashAlgo) const
{
    return {sign(session, hashAlgo, hash, std::move(pin), SIGNING_PIN_REFERENCE,
                 signingPinMinMaxLength(), SIGNING_KEY_REFERENCE_V3, ECDSA_ALGO),
            {SignatureAlgorithm::ES, hashAlgo}};
}

ElectronicID::PinRetriesRemainingAndMax
FinEIDv3::signingPinRetriesLeftImpl(const pcsc_cpp::SmartCard::Session& session) const
{
    return pinRetriesLeft(session, SIGNING_PIN_REFERENCE);
}

byte_vector FinEIDv3::sign(const pcsc_cpp::SmartCard::Session& session,
                           const HashAlgorithm hashAlgo, const byte_vector& hash, byte_vector&& pin,
                           byte_type pinReference, PinMinMaxLength pinMinMaxLength,
                           byte_type keyReference, byte_type signatureAlgo) const
{
    if (signatureAlgo != ECDSA_ALGO && hashAlgo.isSHA3()) {
        THROW(ArgumentFatalError, "No OID for algorithm " + std::string(hashAlgo));
    }

    switch (hashAlgo) {
        using enum HashAlgorithm::HashAlgorithmEnum;
    case SHA224:
    case SHA3_224:
        signatureAlgo |= 0x30;
        break;
    case SHA256:
    case SHA3_256:
        signatureAlgo |= 0x40;
        break;
    case SHA384:
    case SHA3_384:
        signatureAlgo |= 0x50;
        break;
    case SHA512:
    case SHA3_512:
        signatureAlgo |= 0x60;
        break;
    default:
        THROW(ArgumentFatalError, "No OID for algorithm " + std::string(hashAlgo));
    }

    verifyPin(session, pinReference, std::move(pin), pinMinMaxLength, PIN_PADDING_CHAR);
    // Select security environment for COMPUTE SIGNATURE.
    selectSecurityEnv(session, 0xB6, signatureAlgo, keyReference, name());

    byte_vector tlv {0x90, byte_type(hash.size())};
    tlv.insert(tlv.cend(), hash.cbegin(), hash.cend());

    const CommandApdu computeSignature {0x00, 0x2A, 0x90, 0xA0, std::move(tlv)};
    const auto response = session.transmit(computeSignature);

    if (response.sw1 == ResponseApdu::WRONG_LENGTH) {
        THROW(SmartCardError,
              "Wrong data length in command COMPUTE SIGNATURE argument: " + response);
    }
    if (!response.isOK()) {
        THROW(SmartCardError, "Command COMPUTE SIGNATURE failed with error " + response);
    }

    const CommandApdu getSignature {0x00, 0x2A, 0x9E, 0x9A, 0x00};
    auto signature = session.transmit(getSignature);

    if (signature.sw1 == ResponseApdu::WRONG_LENGTH) {
        THROW(SmartCardError, "Wrong data length in command GET SIGNATURE argument: " + response);
    }
    if (!signature.isOK()) {
        THROW(SmartCardError, "Command GET SIGNATURE failed with error " + signature);
    }

    return std::move(signature.data);
}

ElectronicID::PinRetriesRemainingAndMax
FinEIDv3::pinRetriesLeft(const pcsc_cpp::SmartCard::Session& session, byte_type pinReference) const
{
    const auto GET_DATA = smartcard().protocol() == SmartCard::Protocol::T1
        ? CommandApdu {0x00, 0xCB, 0x00, 0xFF, {0xA0, 0x03, 0x83, 0x01, pinReference}, 0x00}
        : CommandApdu {0x00, 0xCB, 0x00, 0xFF, {0xA0, 0x03, 0x83, 0x01, pinReference}};
    const auto response = session.transmit(GET_DATA);
    if (!response.isOK()) {
        THROW(SmartCardError, "Command GET DATA failed with error " + response);
    }
    if (TLV tlv(response.data); tlv.tag == 0xA0) {
        if (TLV info = tlv[0xdf21]) {
            return {*info.begin, maximumPinRetries()};
        }
    }
    THROW(SmartCardError,
          "Command GET DATA failed: received data does not contain the PIN remaining retries info");
}

byte_vector FinEIDv4::getCertificateImpl(const pcsc_cpp::SmartCard::Session& session,
                                         const CertificateType type) const
{
    selectFile(session, SELECT_MAIN_AID);
    return readFile(session,
                    type.isAuthentication() ? SELECT_AUTH_CERT_FILE : SELECT_SIGN_CERT_FILE_V4);
}

byte_vector FinEIDv4::signWithAuthKeyImpl(const pcsc_cpp::SmartCard::Session& session,
                                          byte_vector&& pin, const byte_vector& hash) const
{
    return sign(session, authSignatureAlgorithm().hashAlgorithm(), hash, std::move(pin),
                AUTH_PIN_REFERENCE, authPinMinMaxLength(), AUTH_KEY_REFERENCE, ECDSA_ALGO);
}

ElectronicID::Signature
FinEIDv4::signWithSigningKeyImpl(const pcsc_cpp::SmartCard::Session& session, byte_vector&& pin,
                                 const byte_vector& hash, const HashAlgorithm hashAlgo) const
{
    return {sign(session, hashAlgo, hash, std::move(pin), SIGNING_PIN_REFERENCE,
                 signingPinMinMaxLength(), SIGNING_KEY_REFERENCE_V4, ECDSA_ALGO),
            {SignatureAlgorithm::ES, hashAlgo}};
}

byte_vector EstEIDTHALES::getCertificateImpl(const pcsc_cpp::SmartCard::Session& session,
                                             const CertificateType type) const
{
    selectFile(session, SELECT_MAIN_AID);
    return readFile(
        session, type.isAuthentication() ? SELECT_AUTH_CERT_FILE_EST : SELECT_SIGN_CERT_FILE_EST);
}

byte_vector EstEIDTHALES::signWithAuthKeyImpl(const pcsc_cpp::SmartCard::Session& session,
                                              byte_vector&& pin, const byte_vector& hash) const
{
    return sign(session, authSignatureAlgorithm().hashAlgorithm(), hash, std::move(pin),
                AUTH_PIN_REFERENCE_EST, authPinMinMaxLength(), AUTH_KEY_REFERENCE, ECDSA_ALGO);
}

ElectronicID::PinRetriesRemainingAndMax
EstEIDTHALES::authPinRetriesLeftImpl(const pcsc_cpp::SmartCard::Session& session) const
{
    return pinRetriesLeft(session, AUTH_PIN_REFERENCE_EST);
}

ElectronicID::Signature
EstEIDTHALES::signWithSigningKeyImpl(const pcsc_cpp::SmartCard::Session& session, byte_vector&& pin,
                                     const byte_vector& hash, const HashAlgorithm hashAlgo) const
{
    return {sign(session, hashAlgo, hash, std::move(pin), SIGNING_PIN_REFERENCE,
                 signingPinMinMaxLength(), SIGNING_KEY_REFERENCE_EST, ECDSA_ALGO),
            {SignatureAlgorithm::ES, hashAlgo}};
}

} // namespace electronic_id
