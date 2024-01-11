/*
 * Copyright (c) 2020-2023 Estonian Information System Authority
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

#include "electronic-ids/pcsc/EstEIDGemalto.hpp"
#include "electronic-ids/pcsc/EstEIDIDEMIA.hpp"
#include "electronic-ids/pcsc/FinEID.hpp"
#include "electronic-ids/pcsc/LatEIDIDEMIAv1.hpp"
#include "electronic-ids/pcsc/LatEIDIDEMIAv2.hpp"

#include "electronic-ids/pkcs11/Pkcs11ElectronicID.hpp"

#include "pcsc-cpp/pcsc-cpp-utils.hpp"

#include "magic_enum/magic_enum.hpp"

#include <map>
#include <numeric>
#include <sstream>

using namespace pcsc_cpp;
using namespace electronic_id;
using namespace std::string_literals;

namespace
{
    // Add a structure for ElectronicID Type because, in Belgium, there's a token to identify the EId Card
    // but this token has a mask that must be applied during comparison.
    struct ElectronicIDType
    {
        const byte_vector token;
        const byte_vector mask;

        friend bool operator<(const ElectronicIDType& lhs, const ElectronicIDType& rhs)
        {
            if (lhs.token.size() != rhs.token.size())
                return lhs.token < rhs.token;

            byte_vector lToken;
            if (rhs.mask.size() != 0) {
                for (size_t i = 0; i < lhs.token.size(); ++i)
                    if (i < rhs.mask.size())
                        lToken.push_back(lhs.token.at(i) & rhs.mask.at(i));
                    else
                        lToken.push_back(lhs.token.at(i));
            }
            else {
                lToken = lhs.token;
            }
            byte_vector rToken;
            if (lhs.mask.size() != 0) {
                for (size_t i = 0; i < rhs.token.size(); ++i)
                    if (i < lhs.mask.size())
                        rToken.push_back(rhs.token.at(i) & lhs.mask.at(i));
                    else
                        rToken.push_back(rhs.token.at(i));
            }
            else {
                rToken = rhs.token;
            }

            return lToken < rToken;
        }
    };

using ElectronicIDConstructor = std::function<ElectronicID::ptr(const Reader&)>;

template <typename T>
constexpr auto constructor(const Reader& reader)
{
    return std::make_unique<T>(reader.connectToCard());
}

template <Pkcs11ElectronicIDType value>
constexpr auto constructor(const Reader&)
{
    return std::make_unique<Pkcs11ElectronicID>(value);
}

// Supported cards.
const std::map<ElectronicIDType, ElectronicIDConstructor> SUPPORTED_ATRS {
    // EstEID Gemalto v3.5.8 cold
    {ElectronicIDType {{0x3b, 0xfa, 0x18, 0x00, 0x00, 0x80, 0x31, 0xfe, 0x45, 0xfe,
      0x65, 0x49, 0x44, 0x20, 0x2f, 0x20, 0x50, 0x4b, 0x49, 0x03},
                       {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
     constructor<EstEIDGemaltoV3_5_8>},
    // EstEID Gemalto v3.5.8 warm
    {ElectronicIDType {{0x3b, 0xfe, 0x18, 0x00, 0x00, 0x80, 0x31, 0xfe, 0x45, 0x80, 0x31, 0x80,
      0x66, 0x40, 0x90, 0xa4, 0x16, 0x2a, 0x00, 0x83, 0x0f, 0x90, 0x00, 0xef},
                       {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
     constructor<EstEIDGemaltoV3_5_8>},
    // EstEID Idemia v1.0
    {ElectronicIDType {{0x3b, 0xdb, 0x96, 0x00, 0x80, 0xb1, 0xfe, 0x45, 0x1f, 0x83, 0x00,
      0x12, 0x23, 0x3f, 0x53, 0x65, 0x49, 0x44, 0x0f, 0x90, 0x00, 0xf1},
                       {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
     constructor<EstEIDIDEMIAV1>},
    // FinEID v3.0
    {ElectronicIDType {{0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0,
      0x85, 0x03, 0x00, 0xEF, 0x12, 0x00, 0xF6, 0x82, 0x90, 0x00},
                       {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
     constructor<FinEIDv3>},
    // FinEID v3.1
    {ElectronicIDType {{0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0,
      0x85, 0x04, 0x02, 0x1B, 0x12, 0x00, 0xF6, 0x82, 0x90, 0x00},
                       {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
     constructor<FinEIDv3>},
    // FinEID v4.0
    {ElectronicIDType {{0x3B, 0x7F, 0x96, 0x00, 0x00, 0x80, 0x31, 0xB8, 0x65, 0xB0,
      0x85, 0x05, 0x00, 0x11, 0x12, 0x24, 0x60, 0x82, 0x90, 0x00},
                       {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
     constructor<FinEIDv4>},
    // LatEID Idemia v1.0
    {ElectronicIDType {{0x3b, 0xdd, 0x18, 0x00, 0x81, 0x31, 0xfe, 0x45, 0x90, 0x4c, 0x41,
      0x54, 0x56, 0x49, 0x41, 0x2d, 0x65, 0x49, 0x44, 0x90, 0x00, 0x8c},
                       {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
     constructor<LatEIDIDEMIAV1>},
    // LatEID Idemia v2.0
    {ElectronicIDType {{0x3b, 0xdb, 0x96, 0x00, 0x80, 0xb1, 0xfe, 0x45, 0x1f, 0x83, 0x00,
      0x12, 0x42, 0x8f, 0x53, 0x65, 0x49, 0x44, 0x0f, 0x90, 0x00, 0x20},
                       {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
     constructor<LatEIDIDEMIAV2>},
    // LitEID
    {ElectronicIDType {{0x3B, 0x9D, 0x18, 0x81, 0x31, 0xFC, 0x35, 0x80, 0x31, 0xC0, 0x69,
      0x4D, 0x54, 0x43, 0x4F, 0x53, 0x73, 0x02, 0x05, 0x05, 0xD3},
                       {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff}},
     constructor<Pkcs11ElectronicIDType::LitEIDv3>},
    // HrvEID
    {ElectronicIDType {{0x3b, 0xff, 0x13, 0x00, 0x00, 0x81, 0x31, 0xfe, 0x45, 0x00, 0x31, 0xb9, 0x64,
      0x04, 0x44, 0xec, 0xc1, 0x73, 0x94, 0x01, 0x80, 0x82, 0x90, 0x00, 0x12},
                       {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
     constructor<Pkcs11ElectronicIDType::HrvEID>},
    // BelEIDV1_7
    {ElectronicIDType {{0x3b, 0x98, 0x13, 0x40, 0x0a, 0xa5, 0x03, 0x01, 0x01, 0x01, 0xad, 0x13, 0x11},
                       {0xff, 0xff, 0x00, 0xff, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}},
     constructor<Pkcs11ElectronicIDType::BelEIDV1_7>},
    // BelEIDV1_8
    {ElectronicIDType {{0x3b, 0x7f, 0x96, 0x00, 0x00, 0x80, 0x31, 0x80, 0x65, 0xb0,
      0x85, 0x04, 0x01, 0x20, 0x12, 0x0f, 0xff, 0x82, 0x90, 0x00},
                       {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
     constructor<Pkcs11ElectronicIDType::BelEIDV1_8>},
    // CzeEID
    {ElectronicIDType {{0x3b, 0x7e, 0x94, 0x00, 0x00, 0x80, 0x25, 0xd2, 0x03, 0x10, 0x01, 0x00, 0x56, 0x00, 0x00,
      0x00, 0x02, 0x02, 0x00},
                       {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff}},
     constructor<Pkcs11ElectronicIDType::CzeEID>},
};

inline std::string byteVectorToHexString(const byte_vector& bytes)
{
    std::ostringstream hexStringBuilder;

    hexStringBuilder << std::setfill('0') << std::hex;

    for (const auto byte : bytes) {
        hexStringBuilder << std::setw(2) << static_cast<short>(byte);
    }

    return hexStringBuilder.str();
}

const auto SUPPORTED_ALGORITHMS = std::map<std::string, HashAlgorithm> {
    {"SHA-224"s, HashAlgorithm::SHA224},    {"SHA-256"s, HashAlgorithm::SHA256},
    {"SHA-384"s, HashAlgorithm::SHA384},    {"SHA-512"s, HashAlgorithm::SHA512},
    {"SHA3-224"s, HashAlgorithm::SHA3_224}, {"SHA3-256"s, HashAlgorithm::SHA3_256},
    {"SHA3-384"s, HashAlgorithm::SHA3_384}, {"SHA3-512"s, HashAlgorithm::SHA3_512},
};

} // namespace

namespace electronic_id
{

bool isCardSupported(const pcsc_cpp::byte_vector& atr)
{
    ElectronicIDType atrToken = {atr, {}};
    return SUPPORTED_ATRS.count(atrToken);
}

ElectronicID::ptr getElectronicID(const pcsc_cpp::Reader& reader)
{
    try {
        ElectronicIDType atrToken = {reader.cardAtr, {}};
        const auto& eidConstructor = SUPPORTED_ATRS.at(atrToken);
        return eidConstructor(reader);
    } catch (const std::out_of_range&) {
        // It should be verified that the card is supported with isCardSupported() before
        // calling getElectronicID(), so it is a programming error if out_of_range occurs here.
        THROW(ProgrammingError,
              "Card with ATR '" + byteVectorToHexString(reader.cardAtr) + "' is not supported");
    }
}

bool ElectronicID::isSupportedSigningHashAlgorithm(const HashAlgorithm hashAlgo) const
{
    auto supported = supportedSigningAlgorithms();
    return std::any_of(supported.cbegin(), supported.cend(),
                       [hashAlgo](SignatureAlgorithm signAlgo) { return signAlgo == hashAlgo; });
}

AutoSelectFailed::AutoSelectFailed(Reason r) :
    Error(std::string("Auto-select card failed, reason: ") + std::string(magic_enum::enum_name(r))),
    _reason(r)
{
}

VerifyPinFailed::VerifyPinFailed(const Status s, const observer_ptr<pcsc_cpp::ResponseApdu> ra,
                                 const int8_t r) :
    Error(std::string("Verify PIN failed, status: ") + std::string(magic_enum::enum_name(s))
          + (ra ? ", response: " + pcsc_cpp::bytes2hexstr(ra->toBytes()) : "")),
    _status(s), _retries(r)
{
}

HashAlgorithm::HashAlgorithm(const std::string& algoName)
{
    if (!SUPPORTED_ALGORITHMS.count(algoName)) {
        THROW(ArgumentFatalError,
              "Hash algorithm is not valid, supported algorithms are "
                  + allSupportedAlgorithmNames());
    }
    value = SUPPORTED_ALGORITHMS.at(algoName);
}

HashAlgorithm::operator std::string() const
{
    const auto algoNameValuePair =
        std::find_if(SUPPORTED_ALGORITHMS.begin(), SUPPORTED_ALGORITHMS.end(),
                     [this](const auto& pair) { return pair.second == value; });
    return algoNameValuePair != SUPPORTED_ALGORITHMS.end() ? algoNameValuePair->first : "UNKNOWN";
}

std::string HashAlgorithm::allSupportedAlgorithmNames()
{
    static auto SUPPORTED_ALGORITHM_NAMES = std::string {};
    if (SUPPORTED_ALGORITHM_NAMES.empty()) {
        SUPPORTED_ALGORITHM_NAMES = std::accumulate(
            std::next(SUPPORTED_ALGORITHMS.begin()), SUPPORTED_ALGORITHMS.end(),
            SUPPORTED_ALGORITHMS.begin()->first,
            [](auto result, const auto& value) { return result + ", "s + value.first; });
    }
    return SUPPORTED_ALGORITHM_NAMES;
}

pcsc_cpp::byte_vector HashAlgorithm::rsaOID(const HashAlgorithmEnum hash)
{
    switch (hash) {
    case HashAlgorithm::SHA224:
        return {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c};
    case HashAlgorithm::SHA256:
        return {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    case HashAlgorithm::SHA384:
        return {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};
    case HashAlgorithm::SHA512:
        return {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};
    case HashAlgorithm::SHA3_224:
        return {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x07, 0x05, 0x00, 0x04, 0x1c};
    case HashAlgorithm::SHA3_256:
        return {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x08, 0x05, 0x00, 0x04, 0x20};
    case HashAlgorithm::SHA3_384:
        return {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x09, 0x05, 0x00, 0x04, 0x30};
    case HashAlgorithm::SHA3_512:
        return {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                0x65, 0x03, 0x04, 0x02, 0x0A, 0x05, 0x00, 0x04, 0x40};
    default:
        THROW(ArgumentFatalError, "No OID for algorithm " + std::string(HashAlgorithm(hash)));
    }
}

CertificateType::operator std::string() const
{
    return std::string(magic_enum::enum_name(value));
}

JsonWebSignatureAlgorithm::operator std::string() const
{
    return std::string(magic_enum::enum_name(value));
}

SignatureAlgorithm::operator std::string() const
{
    return std::string(magic_enum::enum_name(value));
}

} // namespace electronic_id
