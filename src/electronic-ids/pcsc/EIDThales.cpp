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

#include "EIDThales.hpp"

#include "pcsc-common.hpp"

#include "../TLV.hpp"

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
// EstEID specification:
// https://www.id.ee/wp-content/uploads/2025/03/tdc_est_eid_developer_guide.pdf

using namespace pcsc_cpp;
using namespace electronic_id;

namespace
{

constexpr byte_type PIN_PADDING_CHAR = 0x00;
constexpr byte_type ECDSA_ALGO = 0x04;

const auto SELECT_MAIN_AID = CommandApdu::select(
    0x04, {0xa0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4b, 0x43, 0x53, 0x2d, 0x31, 0x35});

} // namespace

ElectronicID::PinInfo EIDThales::authPinInfoImpl(const SmartCard::Session& session) const
{
    return pinRetriesLeft(session, authPinReference(), true);
}

byte_vector EIDThales::getCertificateImpl(const SmartCard::Session& session,
                                          const CertificateType type) const
{
    selectFile(session, SELECT_MAIN_AID);
    return readFile(session, type.isAuthentication() ? authCertFile() : signCertFile());
}

ElectronicID::PinInfo EIDThales::pinRetriesLeft(const SmartCard::Session& session,
                                                byte_type pinReference, bool pinActive) const
{
    const auto& GET_DATA = smartcard().protocol() == SmartCard::Protocol::T1
        ? CommandApdu {0x00, 0xCB, 0x00, 0xFF, {0xA0, 0x03, 0x83, 0x01, pinReference}, 0x00}
        : CommandApdu {0x00, 0xCB, 0x00, 0xFF, {0xA0, 0x03, 0x83, 0x01, pinReference}};
    const auto response = session.transmit(GET_DATA);
    if (!response.isOK()) {
        THROW(SmartCardError, "Command GET DATA failed with error " + response);
    }
    if (TLV info = TLV(response.data).find(0xA0); TLV count = info[0xdf21]) {
        TLV pinChanged = info[0xdf2f];
        return {*count.begin, maximumPinRetries(), pinActive || !pinChanged || *pinChanged.begin};
    }
    THROW(SmartCardError,
          "Command GET DATA failed: received data does not contain the PIN remaining retries info");
}

byte_vector EIDThales::sign(const SmartCard::Session& session, const HashAlgorithm hashAlgo,
                            const byte_vector& hash, byte_vector&& pin, byte_type pinReference,
                            PinMinMaxLength pinMinMaxLength, byte_type keyReference,
                            byte_type signatureAlgo) const
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

ElectronicID::PinInfo EIDThales::signingPinInfoImpl(const SmartCard::Session& session) const
{
    return pinRetriesLeft(session, SIGNING_PIN_REFERENCE, true);
}

byte_vector EIDThales::signWithAuthKeyImpl(const SmartCard::Session& session, byte_vector&& pin,
                                           const byte_vector& hash) const
{
    return sign(session, authSignatureAlgorithm().hashAlgorithm(), hash, std::move(pin),
                authPinReference(), authPinMinMaxLength(), AUTH_KEY_REFERENCE, ECDSA_ALGO);
}

ElectronicID::Signature EIDThales::signWithSigningKeyImpl(const SmartCard::Session& session,
                                                          byte_vector&& pin,
                                                          const byte_vector& hash,
                                                          const HashAlgorithm hashAlgo) const
{
    return {sign(session, hashAlgo, hash, std::move(pin), SIGNING_PIN_REFERENCE,
                 signingPinMinMaxLength(), signingKeyReference(), ECDSA_ALGO),
            {SignatureAlgorithm::ES, hashAlgo}};
}
