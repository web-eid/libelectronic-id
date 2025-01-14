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

#pragma once

#include "pcsc-cpp/pcsc-cpp.hpp"

#include <set>
#include <string>

namespace electronic_id
{

class CertificateType
{
public:
    enum CertificateTypeEnum : int8_t { AUTHENTICATION, SIGNING, NONE = -1 };

    CertificateType() = default;
    constexpr CertificateType(const CertificateTypeEnum _value) : value(_value) {}

    bool isAuthentication() const { return value == AUTHENTICATION; }

    bool isSigning() const { return value == SIGNING; }

    constexpr bool operator==(const CertificateType other) const { return value == other.value; }
    operator std::string() const;

private:
    CertificateTypeEnum value = NONE;
};

class HashAlgorithm
{
public:
    enum HashAlgorithmEnum : int16_t {
        SHA224 = 224, // SHA2
        SHA256 = 256,
        SHA384 = 384,
        SHA512 = 512,

        SHA3_224 = 224 * 10, // SHA3
        SHA3_256 = 256 * 10,
        SHA3_384 = 384 * 10,
        SHA3_512 = 512 * 10,

        NONE = -1
    };

    HashAlgorithm() = default;
    constexpr HashAlgorithm(const HashAlgorithmEnum _value) : value(_value) {}
    // String conversion constructor.
    HashAlgorithm(const std::string&);

    constexpr bool operator==(HashAlgorithmEnum other) const { return value == other; }
    constexpr operator HashAlgorithmEnum() const { return value; }

    operator std::string() const;

    constexpr size_t hashByteLength() const
    {
        return size_t(value <= SHA512 ? value / 8 : (value / 10) / 8);
    }

    constexpr bool isSHA2() const
    {
        return value >= HashAlgorithm::SHA224 && value <= HashAlgorithm::SHA512;
    }

    constexpr bool isSHA3() const
    {
        return value >= HashAlgorithm::SHA3_224 && value <= HashAlgorithm::SHA3_512;
    }

    static std::string allSupportedAlgorithmNames();
    static pcsc_cpp::byte_vector rsaOID(const HashAlgorithmEnum hash);

private:
    HashAlgorithmEnum value = NONE;
};

/** Signature algorithms */
class SignatureAlgorithm
{
public:
    enum SignatureAlgorithmEnum {
        // ECDSA
        ES = 1 << 13,
        ES224 = ES | int16_t(HashAlgorithm::SHA224),
        ES256 = ES | int16_t(HashAlgorithm::SHA256),
        ES384 = ES | int16_t(HashAlgorithm::SHA384),
        ES512 = ES | int16_t(HashAlgorithm::SHA512),
        ES3_224 = ES | int16_t(HashAlgorithm::SHA3_224),
        ES3_256 = ES | int16_t(HashAlgorithm::SHA3_256),
        ES3_384 = ES | int16_t(HashAlgorithm::SHA3_384),
        ES3_512 = ES | int16_t(HashAlgorithm::SHA3_512),
        // RSASSA-PSS
        PS = 1 << 14,
        PS224 = PS | int16_t(HashAlgorithm::SHA224),
        PS256 = PS | int16_t(HashAlgorithm::SHA256),
        PS384 = PS | int16_t(HashAlgorithm::SHA384),
        PS512 = PS | int16_t(HashAlgorithm::SHA512),
        PS3_224 = PS | int16_t(HashAlgorithm::SHA3_224),
        PS3_256 = PS | int16_t(HashAlgorithm::SHA3_256),
        PS3_384 = PS | int16_t(HashAlgorithm::SHA3_384),
        PS3_512 = PS | int16_t(HashAlgorithm::SHA3_512),
        // RSASSA-PKCS1-v1_5
        RS = 1 << 15,
        RS224 = RS | int16_t(HashAlgorithm::SHA224),
        RS256 = RS | int16_t(HashAlgorithm::SHA256),
        RS384 = RS | int16_t(HashAlgorithm::SHA384),
        RS512 = RS | int16_t(HashAlgorithm::SHA512),
        RS3_224 = RS | int16_t(HashAlgorithm::SHA3_224),
        RS3_256 = RS | int16_t(HashAlgorithm::SHA3_256),
        RS3_384 = RS | int16_t(HashAlgorithm::SHA3_384),
        RS3_512 = RS | int16_t(HashAlgorithm::SHA3_512),
        NONE = -1
    };

    constexpr SignatureAlgorithm(const SignatureAlgorithmEnum _value) : value(_value) {}
    constexpr SignatureAlgorithm(const SignatureAlgorithmEnum key, const HashAlgorithm hash) :
        value(SignatureAlgorithmEnum(key | int16_t(hash)))
    {
    }

    constexpr bool operator==(HashAlgorithm other) const
    {
        return other.operator==(operator HashAlgorithm());
    }
    constexpr bool operator==(SignatureAlgorithmEnum other) const { return value == other; }

    constexpr operator HashAlgorithm() const
    {
        return HashAlgorithm::HashAlgorithmEnum(value & ~(ES | PS | RS));
    }

    constexpr operator SignatureAlgorithmEnum() const { return value; }

    operator std::string() const;

private:
    SignatureAlgorithmEnum value = NONE;
};

/** JSON Web Signature algorithms as defined in RFC 7518, section 3. */
class JsonWebSignatureAlgorithm
{
public:
    enum JsonWebSignatureAlgorithmEnum : int8_t {
        ES256, // ECDSA
        ES384,
        ES512,
        PS256, // RSASSA-PSS
        PS384,
        PS512,
        RS256, // RSASSA-PKCS1-v1_5
        RS384,
        RS512,
        NONE = -1
    };

    constexpr JsonWebSignatureAlgorithm(const JsonWebSignatureAlgorithmEnum _value) : value(_value)
    {
    }

    constexpr bool operator==(JsonWebSignatureAlgorithmEnum other) const { return value == other; }
    constexpr operator JsonWebSignatureAlgorithmEnum() const { return value; }

    operator std::string() const;

    constexpr HashAlgorithm hashAlgorithm() const
    {
        switch (value) {
        case ES256:
        case PS256:
        case RS256:
            return HashAlgorithm::SHA256;
        case ES384:
        case PS384:
        case RS384:
            return HashAlgorithm::SHA384;
        case ES512:
        case PS512:
        case RS512:
            return HashAlgorithm::SHA512;
        default:
            throw std::logic_error("JsonWebSignatureAlgorithm::hashAlgorithm(): Invalid value "
                                   + std::to_string(value));
        }
    }

    constexpr bool isRSAWithPKCS1Padding()
    {
        return value == RS256 || value == RS384 || value == RS512;
    }

    constexpr size_t hashByteLength() const { return hashAlgorithm().hashByteLength(); }

private:
    JsonWebSignatureAlgorithmEnum value = NONE;
};

} // namespace electronic_id
