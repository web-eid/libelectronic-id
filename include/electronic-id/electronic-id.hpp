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

#include "enums.hpp"

#include <optional>
#include <functional>

namespace electronic_id
{

/** Interface for all electronic ID cards and tokens, contains cryptographic
 * operations and card information. */
class ElectronicID
{
public:
    using ptr = std::shared_ptr<ElectronicID>;
    using PinMinMaxLength = std::pair<uint8_t, uint8_t>;
    using PinRetriesRemainingAndMax = std::pair<uint8_t, int8_t>;
    using byte_vector = pcsc_cpp::byte_vector;
    using byte_type = pcsc_cpp::byte_type;
    using Signature = std::pair<byte_vector, SignatureAlgorithm>;

    enum Type : uint8_t {
        EstEID,
        FinEID,
        LatEID,
        LitEID,
        HrvEID,
        BelEID,
        CzeEID,
        LuxtrustV2,
        LuxEID,
#ifdef _WIN32
        MsCryptoApiEID,
#endif
    };

    virtual ~ElectronicID() = default;
    PCSC_CPP_DISABLE_COPY_MOVE(ElectronicID);

    // Function for retrieving the authentication and signing certificates.
    virtual pcsc_cpp::byte_vector getCertificate(const CertificateType type) const = 0;

    // Functions related to authentication.
    virtual JsonWebSignatureAlgorithm authSignatureAlgorithm() const = 0;

    virtual PinMinMaxLength authPinMinMaxLength() const = 0;

    virtual PinRetriesRemainingAndMax authPinRetriesLeft() const = 0;

    virtual pcsc_cpp::byte_vector signWithAuthKey(byte_vector&& pin,
                                                  const byte_vector& hash) const = 0;

    // Functions related to signing.
    virtual const std::set<SignatureAlgorithm>& supportedSigningAlgorithms() const = 0;

    bool isSupportedSigningHashAlgorithm(const HashAlgorithm hashAlgo) const;

    virtual PinMinMaxLength signingPinMinMaxLength() const = 0;

    virtual PinRetriesRemainingAndMax signingPinRetriesLeft() const = 0;

    virtual Signature signWithSigningKey(byte_vector&& pin, const byte_vector& hash,
                                         const HashAlgorithm hashAlgo) const = 0;

    // General functions.
    virtual bool allowsUsingLettersAndSpecialCharactersInPin() const { return false; }
    virtual bool providesExternalPinDialog() const { return false; }

    /** Extension point for releasing the resources held by the ElectronicID object.
     * By default, this function does nothing. It serves as an extension point for
     * Pkcs11ElectronicID which needs to release the PKCS#11 module before the application exits to
     * prevent potential crashes. */
    virtual void release() const {}

    virtual std::string name() const = 0;
    virtual Type type() const = 0;

    virtual pcsc_cpp::SmartCard const& smartcard() const { return card; }

protected:
    ElectronicID(pcsc_cpp::SmartCard&& _card) noexcept : card(std::move(_card)) {}

    pcsc_cpp::SmartCard card;
};

using ElectronicIDConstructor = std::function<ElectronicID::ptr(const pcsc_cpp::Reader&)>;

std::optional<ElectronicIDConstructor> findMaskedATR(const pcsc_cpp::byte_vector& atr);

bool isCardSupported(const pcsc_cpp::byte_vector& atr);

ElectronicID::ptr getElectronicID(const pcsc_cpp::Reader& reader);

/** Automatic card selection that either returns a vector of electronic ID pointers with available
 * supported cards or throws AutoSelectFailed. */
std::vector<ElectronicID::ptr> availableSupportedCards();

/** Base class for fatal errors in parameters or environment conditions that do not allow retrying.
 */
class FatalError : public std::runtime_error
{
protected:
    using std::runtime_error::runtime_error;
};

/** Fatal error caused by violating application logic pre-/post-conditions or invariants. */
class ProgrammingError : public FatalError
{
    using FatalError::FatalError;
};

/** Fatal error caused by input arguments. */
class ArgumentFatalError : public FatalError
{
    using FatalError::FatalError;
};

/** Base class for non-fatal errors, possibly allowing retry. */
class Error : public std::runtime_error
{
protected:
    using std::runtime_error::runtime_error;
};

/** An error that can possibly be mitigated by changing the smart card in the reader. */
class SmartCardChangeRequiredError : public Error
{
    using Error::Error;
};

/** Attempt to perform an operation with a wrong certificate type. */
class WrongCertificateTypeError : public Error
{
    using Error::Error;
};

/** Non-fatal error caused by the smart card services layer. */
class SmartCardError : public Error
{
    using Error::Error;
};

/** Non-fatal error caused by the PKCS #11 layer. */
class Pkcs11Error : public Error
{
    using Error::Error;
};

/** The PKCS#11 library and/or slot does not recognize the token in the slot. */
class Pkcs11TokenNotRecognized : public Pkcs11Error
{
    using Pkcs11Error::Pkcs11Error;
};

/** Smart card was not present in its slot at the time that a PKCS#11 function was invoked. */
class Pkcs11TokenNotPresent : public Error
{
    using Error::Error;
};

/** Smart card was removed from its slot during the execution of a PKCS#11 function. */
class Pkcs11TokenRemoved : public Error
{
    using Error::Error;
};

#ifdef _WIN32
class MsCryptoApiError : public Error
{
    using Error::Error;
};
#endif

/** Communicates why auto-select failed to the caller. */
class AutoSelectFailed : public Error
{
public:
    enum class Reason : uint8_t {
        SERVICE_NOT_RUNNING,
        NO_READERS,
        SINGLE_READER_NO_CARD,
        SINGLE_READER_UNSUPPORTED_CARD,
        MULTIPLE_READERS_NO_CARD,
        MULTIPLE_READERS_NO_SUPPORTED_CARD
    };

    explicit AutoSelectFailed(Reason r);

    Reason reason() const { return _reason; }

private:
    Reason _reason;
};

/** Communicates why PIN verification failed to the caller. */
class VerifyPinFailed : public Error
{
public:
    // Non-owning observing pointer.
    template <typename T>
    using observer_ptr = T*;

    enum class Status : uint8_t {
        RETRY_ALLOWED,
        INVALID_PIN_LENGTH,
        PIN_ENTRY_TIMEOUT,
        PIN_ENTRY_CANCEL,
        PIN_ENTRY_DISABLED,
        // Retry not allowed starting from PIN_BLOCKED.
        PIN_BLOCKED,
        UNKNOWN_ERROR
    };

    explicit VerifyPinFailed(const Status s,
                             const observer_ptr<pcsc_cpp::ResponseApdu> ra = nullptr,
                             const int8_t retries = 0);

    Status status() const { return _status; }
    int8_t retries() const { return _retries; }

private:
    Status _status;
    int8_t _retries;
};

} // namespace electronic_id
