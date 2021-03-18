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

#include "Pkcs11ElectronicID.hpp"

#include "../common.hpp"

#include <map>

#ifdef _WIN32
#undef UNICODE
#include <Shlobj.h>
#include <Shlwapi.h>
#include <Knownfolders.h>
#else
#include <unistd.h>
#endif

namespace
{

std::string lithuanianPKCS11Path(bool v2)
{
#ifdef _WIN32
    PWSTR programFiles = 0;
    SHGetKnownFolderPath(FOLDERID_ProgramFiles, 0, nullptr, &programFiles);
    std::wstring path = programFiles;
    CoTaskMemFree(programFiles);
    path += v2 ? L"\\PWPW\\pwpw-card-pkcs11.dll" : L"\\Softemia\\mcard\\mcard-pkcs11.dll";
    int len = WideCharToMultiByte(CP_UTF8, 0, path.data(), int(path.size()), nullptr, 0, nullptr,
                                  nullptr);
    std::string out(size_t(len), 0);
    WideCharToMultiByte(CP_UTF8, 0, path.data(), int(path.size()), &out[0], len, nullptr, nullptr);
    return out;
#elif defined(__APPLE__)
    static const std::string path1("/Library/PWPW-Card/lib/pwpw-card-pkcs11.so");
    static const std::string path2("/Library/mCard/lib/mcard-pkcs11.so");
    return v2 ? path1 : path2;
#else
    static const std::string path1("/usr/lib64/pwpw-card-pkcs11.so");
    static const std::string path2("/usr/lib/pwpw-card-pkcs11.so");
    static const std::string path3("/usr/lib/mcard-pkcs11.so");
    return v2 ? (access(path1.c_str(), F_OK) == 0 ? path1 : path2) : path3;
#endif
}

const std::map<electronic_id::Pkcs11ElectronicIDType, electronic_id::Pkcs11ElectronicIDModule>
    SUPPORTED_PKCS11_MODULES = {
        // EstEIDIDEMIAV1 configuration is here only for testing,
        // it is not enabled in getElectronicID().
        {electronic_id::Pkcs11ElectronicIDType::EstEIDIDEMIAV1,
         {
             "EstEID IDEMIA v1 (PKCS#11)", // name
             electronic_id::ElectronicID::Type::EstEID, // type
             "opensc-pkcs11.so", // path

             electronic_id::JsonWebSignatureAlgorithm::ES384, // authSignatureAlgorithm
             electronic_id::ELLIPTIC_CURVE_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
             3,
         }},
        {electronic_id::Pkcs11ElectronicIDType::LitEIDv2,
         {
             "Lithuanian eID (PKCS#11)", // name
             electronic_id::ElectronicID::Type::LitEID, // type
             lithuanianPKCS11Path(true), // path

             electronic_id::JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
             electronic_id::RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
             -1,
         }},
        {electronic_id::Pkcs11ElectronicIDType::LitEIDv3,
         {
             "Lithuanian eID (PKCS#11)", // name
             electronic_id::ElectronicID::Type::LitEID, // type
             lithuanianPKCS11Path(false), // path

             electronic_id::JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
             electronic_id::RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
             -1,
         }},
        {electronic_id::Pkcs11ElectronicIDType::HrvEID,
         {
             "Croatian eID (PKCS#11)", // name
             electronic_id::ElectronicID::Type::HrvEID, // type
             "/usr/lib/akd/eidmiddleware/pkcs11/libEidPkcs11.so", // path

             electronic_id::JsonWebSignatureAlgorithm::RS256, // authSignatureAlgorithm
             electronic_id::RSA_SIGNATURE_ALGOS(), // supportedSigningAlgorithms
         }},
};

const electronic_id::Pkcs11ElectronicIDModule&
getModule(electronic_id::Pkcs11ElectronicIDType eidType)
{
    try {
        return SUPPORTED_PKCS11_MODULES.at(eidType);
    } catch (const std::out_of_range&) {
        THROW(electronic_id::ProgrammingError,
              "Unknown Pkcs11ElectronicIDType enum value '" + std::to_string(int(eidType)) + "'");
    }
}

} // namespace

namespace electronic_id
{

Pkcs11ElectronicID::Pkcs11ElectronicID(pcsc_cpp::SmartCard::ptr _card,
                                       Pkcs11ElectronicIDType type) :
    ElectronicID(std::move(_card)),
    module(getModule(type)), manager(module.path)
{
    bool seenAuthToken = false;
    bool seenSigningToken = false;

    for (const auto& token : manager.tokens()) {
        const auto certType = token.certificateType();
        if (certType.isAuthentication()) {
            authToken = token;
            seenAuthToken = true;
        } else {
            signingToken = token;
            seenSigningToken = true;
        }
    }
    if (!(seenAuthToken && seenSigningToken)) {
        THROW(SmartCardChangeRequiredError, "Either authentication or signing token is missing");
    }
}

pcsc_cpp::byte_vector Pkcs11ElectronicID::getCertificate(const CertificateType type) const
{
    return type.isAuthentication() ? authToken.cert : signingToken.cert;
}

ElectronicID::PinMinMaxLength Pkcs11ElectronicID::authPinMinMaxLength() const
{
    return {authToken.minPinLen, authToken.maxPinLen};
}

ElectronicID::PinRetriesRemainingAndMax Pkcs11ElectronicID::authPinRetriesLeft() const
{
    return {authToken.retry, module.retryMax};
}

pcsc_cpp::byte_vector Pkcs11ElectronicID::signWithAuthKey(const pcsc_cpp::byte_vector& pin,
                                                          const pcsc_cpp::byte_vector& hash) const
{
    try {
        validateAuthHashLength(authSignatureAlgorithm(), name(), hash);

        const auto signature =
            manager.sign(authToken, hash, authSignatureAlgorithm().hashAlgorithm(),
                         reinterpret_cast<const char*>(pin.data()), pin.size());
        return signature.first;
    } catch (const VerifyPinFailed& e) {
        // Catch and rethrow the VerifyPinFailed error with -1 to inform the caller of the special
        // case where the card does not return the remaining retry count. This is arguably a
        // somewhat inelegant workaround caused by module.retryMax not being available inside
        // PKCS11CardManager. We should eventually consider improving this.
        if (e.status() == VerifyPinFailed::Status::RETRY_ALLOWED && module.retryMax == -1) {
            throw VerifyPinFailed(VerifyPinFailed::Status::RETRY_ALLOWED, nullptr, -1);
        }
        throw;
    }
}

ElectronicID::PinMinMaxLength Pkcs11ElectronicID::signingPinMinMaxLength() const
{
    return {signingToken.minPinLen, signingToken.maxPinLen};
}

ElectronicID::PinRetriesRemainingAndMax Pkcs11ElectronicID::signingPinRetriesLeft() const
{
    return {signingToken.retry, module.retryMax};
}

ElectronicID::Signature Pkcs11ElectronicID::signWithSigningKey(const pcsc_cpp::byte_vector& pin,
                                                               const pcsc_cpp::byte_vector& hash,
                                                               const HashAlgorithm hashAlgo) const
{
    try {
        validateSigningHash(*this, hashAlgo, hash);

        // TODO: add step for supported algo detection before sign(), see if () below.
        auto signature = manager.sign(signingToken, hash, hashAlgo,
                                      reinterpret_cast<const char*>(pin.data()), pin.size());

        if (!module.supportedSigningAlgorithms.count(signature.second)) {
            THROW(SmartCardChangeRequiredError,
                  "Signature algorithm " + std::string(signature.second) + " is not supported by "
                      + name());
        }

        return signature;
    } catch (const VerifyPinFailed& e) {
        // Same issue as in signWithAuthKey().
        if (e.status() == VerifyPinFailed::Status::RETRY_ALLOWED && module.retryMax == -1) {
            throw VerifyPinFailed(VerifyPinFailed::Status::RETRY_ALLOWED, nullptr, -1);
        }
        throw;
    }
}

} // namespace electronic_id
