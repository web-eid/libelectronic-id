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

#include "Pkcs11ElectronicID.hpp"

#include <map>

#ifdef _WIN32
#undef UNICODE
#include <Shlobj.h>
#include <Shlwapi.h>
#endif

using namespace electronic_id;
using namespace std::string_literals;
namespace fs = std::filesystem;

namespace
{

#ifdef _WIN32
inline auto getKnownFolderPath(REFKNOWNFOLDERID knownFolderId)
{
    PWSTR knownFolder = 0;
    SHGetKnownFolderPath(knownFolderId, 0, nullptr, &knownFolder);
    fs::path path = knownFolder;
    CoTaskMemFree(knownFolder);
    return path;
}

inline auto programFilesPath()
{
    return getKnownFolderPath(FOLDERID_ProgramFiles);
}

inline auto system32Path()
{
    return getKnownFolderPath(FOLDERID_System);
}
#endif

inline fs::path lithuanianPKCS11ModulePath()
{
#ifdef _WIN32
    return programFilesPath() / L"Softemia/mcard/mcard-pkcs11.dll";
#elif defined(__APPLE__)
    return "/Library/mCard/lib/mcard-pkcs11.so";
#else
    return "/usr/lib/mcard-pkcs11.so";
#endif
}

inline fs::path croatianPkcs11ModulePath()
{
#ifdef _WIN32
    fs::path certiliaPath =
        programFilesPath() / L"AKD/Certilia Middleware/pkcs11/AkdEidPkcs11_64.dll";
    fs::path eidPath = programFilesPath() / L"AKD/eID Middleware/pkcs11/AkdEidPkcs11_64.dll";
    return fs::exists(certiliaPath) ? certiliaPath : eidPath;
#elif defined __APPLE__
    // The driver provider installs the library to /usr/local/lib/pkcs11, but
    // sandboxed applications cannot access /usr/local/ due to macOS restrictions.
    // To make the solution work, the library libEidPkcs11.dylib and License.bin must be
    // copied to /Library/AKD/pkcs11, which is accessible in sandboxed environments:
    //
    //  sudo mkdir -p /Library/AKD/pkcs11
    //  sudo cp -a /usr/local/lib/pkcs11/{libEidPkcs11.dylib,License.bin} /Library/AKD/pkcs11/
    //
    // This workaround is required until the driver provider addresses the issue.
    // NB! This is not tested.
    return "/Library/AKD/pkcs11/libEidPkcs11.dylib";
#else // Linux
    fs::path certiliaPath = "/usr/lib/akd/certiliamiddleware/pkcs11/libEidPkcs11.so";
    fs::path eidPath = "/usr/lib/akd/eidmiddleware/pkcs11/libEidPkcs11.so";
    return fs::exists(certiliaPath) ? certiliaPath : eidPath;
#endif
}

inline fs::path belgianPkcs11ModulePath()
{
#ifdef _WIN32
    return system32Path() / L"beidpkcs11.dll";
#elif defined __APPLE__
    return "/Library/Belgium Identity "
           "Card/Pkcs11/beid-pkcs11.bundle/Contents/MacOS/libbeidpkcs11.dylib";
#else // Linux
    return "/usr/lib/x86_64-linux-gnu/libbeidpkcs11.so.0";
#endif
}

inline fs::path czechPkcs11ModulePath()
{
#ifdef _WIN32
    return system32Path() / L"eopproxyp11.dll";
#elif defined __APPLE__
    return "/usr/local/lib/eOPCZE/libeopproxyp11.dylib";
#else // Linux
    return "/usr/lib/x86_64-linux-gnu/libeopproxyp11.so";
#endif
}

inline fs::path luxembourgPkcs11ModulePath()
{
#ifdef _WIN32
    return programFilesPath() / L"Gemalto/Classic Client/BIN/gclib.dll";
#elif defined __APPLE__
    return "/Library/Frameworks/Pkcs11ClassicClient.framework/Versions/A/Pkcs11ClassicClient/"
           "libgclib.dylib";
#else // Linux
    return "/usr/lib/pkcs11/libgclib.so";
#endif
}

const std::map<ElectronicID::Type, Pkcs11ElectronicIDModule> SUPPORTED_PKCS11_MODULES {
    // EstEID configuration is here only for testing,
    // it is not enabled in getElectronicID().
    {ElectronicID::Type::EstEID,
     {
         "EstEID IDEMIA v1 (PKCS#11)"s, // name
         ElectronicID::Type::EstEID, // type
         fs::path("opensc-pkcs11.so"), // path

         3,
         false,
         false,
     }},
    {ElectronicID::Type::LitEID,
     {
         "Lithuanian eID (PKCS#11)"s, // name
         ElectronicID::Type::LitEID, // type
         lithuanianPKCS11ModulePath().make_preferred(), // path

         3,
         false,
         false,
     }},
    {ElectronicID::Type::HrvEID,
     {
         "Croatian eID (PKCS#11)"s, // name
         ElectronicID::Type::HrvEID, // type
         croatianPkcs11ModulePath().make_preferred(), // path

         3,
         true,
         false,
     }},
    {ElectronicID::Type::BelEID,
     {
         "Belgian eID (PKCS#11)"s, // name
         ElectronicID::Type::BelEID, // type
         belgianPkcs11ModulePath().make_preferred(), // path

         3,
         true,
         true,
     }},
    {ElectronicID::Type::CzeEID,
     {
         "Czech eID (PKCS#11)"s, // name
         ElectronicID::Type::CzeEID, // type
         czechPkcs11ModulePath().make_preferred(), // path

         3,
         true,
         false,
     }},
    {ElectronicID::Type::LuxtrustV2,
     {
         "LuxtrustV2 eID (PKCS#11)"s, // name
         ElectronicID::Type::LuxtrustV2, // type
         luxembourgPkcs11ModulePath().make_preferred(), // path

         3,
         true,
         false,
     }},
    {ElectronicID::Type::LuxEID,
     {
         "Luxembourg eID (PKCS#11)"s, // name
         ElectronicID::Type::LuxEID, // type
         luxembourgPkcs11ModulePath().make_preferred(), // path

         3,
         true,
         true,
     }},
};

const Pkcs11ElectronicIDModule& getModule(ElectronicID::Type eidType)
{
    try {
        return SUPPORTED_PKCS11_MODULES.at(eidType);
    } catch (const std::out_of_range&) {
        THROW(ProgrammingError,
              "Unknown Pkcs11ElectronicIDType enum value '" + std::to_string(int(eidType)) + "'");
    }
}

} // namespace

Pkcs11ElectronicID::Pkcs11ElectronicID(ElectronicID::Type type) :
    ElectronicID {{}}, module {getModule(type)}, manager {PKCS11CardManager::instance(module.path)}
{
    REQUIRE_NON_NULL(manager)

    bool seenAuthToken = false;
    bool seenSigningToken = false;

    for (const auto& token : manager->tokens()) {
        const auto certType = certificateType(token.cert);
        if (certType.isAuthentication()) {
            authToken = token;
            seenAuthToken = true;
        } else if (certType.isSigning()) {
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

JsonWebSignatureAlgorithm Pkcs11ElectronicID::authSignatureAlgorithm() const
{
    return getAuthAlgorithmFromCert(authToken.cert);
}

ElectronicID::PinMinMaxLength Pkcs11ElectronicID::authPinMinMaxLength() const
{
    return {authToken.minPinLen, authToken.maxPinLen};
}

ElectronicID::PinRetriesRemainingAndMax Pkcs11ElectronicID::authPinRetriesLeft() const
{
    return {authToken.retry, module.retryMax};
}

pcsc_cpp::byte_vector Pkcs11ElectronicID::signWithAuthKey(byte_vector&& pin,
                                                          const byte_vector& hash) const
{
    REQUIRE_NON_NULL(manager)

    try {
        validateAuthHashLength(authSignatureAlgorithm(), name(), hash);

        const auto signature =
            manager->sign(authToken, hash, authSignatureAlgorithm().hashAlgorithm(),
                          module.providesExternalPinDialog,
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

const std::set<SignatureAlgorithm>& Pkcs11ElectronicID::supportedSigningAlgorithms() const
{
    return getSignAlgorithmFromCert(signingToken.cert);
}

ElectronicID::PinMinMaxLength Pkcs11ElectronicID::signingPinMinMaxLength() const
{
    return {signingToken.minPinLen, signingToken.maxPinLen};
}

ElectronicID::PinRetriesRemainingAndMax Pkcs11ElectronicID::signingPinRetriesLeft() const
{
    return {signingToken.retry, module.retryMax};
}

ElectronicID::Signature Pkcs11ElectronicID::signWithSigningKey(byte_vector&& pin,
                                                               const byte_vector& hash,
                                                               const HashAlgorithm hashAlgo) const
{
    REQUIRE_NON_NULL(manager)

    try {
        validateSigningHash(*this, hashAlgo, hash);

        // TODO: add step for supported algo detection before sign(), see if () below.
        auto signature =
            manager->sign(signingToken, hash, hashAlgo, module.providesExternalPinDialog,
                          reinterpret_cast<const char*>(pin.data()), pin.size());

        if (!supportedSigningAlgorithms().count(signature.second)) {
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

void Pkcs11ElectronicID::release() const
{
    manager.reset();
}
