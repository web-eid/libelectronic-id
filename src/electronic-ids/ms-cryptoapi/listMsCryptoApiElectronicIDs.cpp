/*
 * Copyright (c) 2022-2024 Estonian Information System Authority
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

#include "listMsCryptoApiElectronicIDs.hpp"
#include "MsCryptoApiElectronicID.hpp"

#include <windows.h>
#include <wincrypt.h>

#include "../scope.hpp"
#include "../x509.hpp"

using namespace std::string_literals;

namespace electronic_id
{

// Enumerates all certificates and converts the valid hardware-based ones to MsCryptoApiElectronicID
// objects.
std::vector<CardInfo::ptr> listMsCryptoApiElectronicIDs()
{
    HCERTSTORE sys =
        CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING, 0,
                      CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG, L"MY");
    if (!sys) {
        THROW(MsCryptoApiError, "Failed to open certificate store");
    }
    auto closeCertStore = stdext::make_scope_exit([=]() { CertCloseStore(sys, 0); });

    std::vector<CardInfo::ptr> msCryptoApiElectronicIDs;
    pcsc_cpp::Reader dummyReader {
        nullptr,
        L"Dummy reader for MS CryptoAPI tokens"s,
        {},
        flag_set<pcsc_cpp::Reader::Status> {pcsc_cpp::Reader::Status::PRESENT},
    };

    PCCERT_CONTEXT cert = nullptr;
    while ((cert = CertEnumCertificatesInStore(sys, cert)) != nullptr) {
        pcsc_cpp::byte_vector certData(cert->pbCertEncoded,
                                       cert->pbCertEncoded + cert->cbCertEncoded);

        CertificateType certType {CertificateType::NONE};
        try {
            certType = certificateType(certData);
        } catch (const std::exception&) {
            // Ignore invalid certificates.
            continue;
        }
        if (certType == CertificateType::NONE) {
            continue;
        }

        // Initially, acquire the key handle with CRYPT_ACQUIRE_SILENT_FLAG to avoid driver dialogs.
        DWORD flags = CRYPT_ACQUIRE_CACHE_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG
            | CRYPT_ACQUIRE_SILENT_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG;
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key = 0;
        DWORD spec = 0;
        BOOL freeKey = FALSE;
        CryptAcquireCertificatePrivateKey(cert, flags, nullptr, &key, &spec, &freeKey);
        if (!key) {
            continue;
        }
        auto freeKeyScopeGuard = stdext::make_scope_exit([=]() {
            if (freeKey) {
                NCryptFreeObject(key);
            }
        });

        if (spec != CERT_NCRYPT_KEY_SPEC) {
            // We don't support old non-CNG CSPs.
            // TODO: _log("Not CERT_NCRYPT_KEY_SPEC");
            continue;
        }

        NCRYPT_PROV_HANDLE prov = 0;
        DWORD type = 0, size = sizeof(prov);
        SECURITY_STATUS err =
            NCryptGetProperty(key, NCRYPT_PROVIDER_HANDLE_PROPERTY, PBYTE(&prov), size, &size, 0);
        if (FAILED(err)) {
            continue; // TODO: log.
        }
        if (!prov) {
            continue;
        }
        auto freeProvider = stdext::make_scope_exit([=]() { NCryptFreeObject(prov); });

        size = sizeof(type);
        err = NCryptGetProperty(prov, NCRYPT_IMPL_TYPE_PROPERTY, PBYTE(&type), size, &size, 0);
        if (FAILED(err)) {
            continue; // TODO: log.
        }

        if ((type & (NCRYPT_IMPL_HARDWARE_FLAG | NCRYPT_IMPL_REMOVABLE_FLAG)) == 0) {
            continue; // TODO: log.
        }

        std::wstring algo(5, 0);
        err = NCryptGetProperty(key, NCRYPT_ALGORITHM_GROUP_PROPERTY, PBYTE(algo.data()),
                                DWORD(algo.size() + 1) * 2, &size, 0);
        if (FAILED(err)) {
            continue; // TODO: log.
        }
        algo.resize(size / 2 - 1);
        // TODO: use algo.starts_with(L"EC") when migrating to C++20.
        if (algo != L"RSA" && algo.rfind(L"EC", 0) != 0) {
            // We only support RSA and ECC algorithms.
            continue; // TODO: log.
        }

        // Acquire the key again without the CRYPT_ACQUIRE_SILENT_FLAG as QSCD devices
        // may fail with NTE_SILENT_CONTEXT otherwise in case they require PIN entry through the
        // driver UI. To avoid reusing the key handle, omit CRYPT_ACQUIRE_CACHE_FLAG as well.
        // MsCryptoApiElectronicID will take ownership of the key in the next step.
        flags = CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG;
        key = 0;
        spec = 0;
        freeKey = FALSE;
        CryptAcquireCertificatePrivateKey(cert, flags, nullptr, &key, &spec, &freeKey);
        if (!key) {
            continue;
        }

        // The certificate context must also remain alive to use the key, so call
        // CertDuplicateCertificateContext() to increment its reference count to keep it alive.
        // MsCryptoApiElectronicID frees the certificate context itself.
        auto eid = std::make_unique<MsCryptoApiElectronicID>(CertDuplicateCertificateContext(cert),
                                                             std::move(certData), certType,
                                                             algo == L"RSA", key, freeKey);

        msCryptoApiElectronicIDs.push_back(std::make_shared<CardInfo>(dummyReader, std::move(eid)));
    }

    // CertEnumCertificatesInStore() function frees the CERT_CONTEXT referenced by non-NULL values
    // of the PCCERT_CONTEXT parameter. The last CERT_CONTEXT has to be freed manually.
    if (cert) {
        CertFreeCertificateContext(cert); // TODO: figure out a way to use scope guard here.
    }
    return msCryptoApiElectronicIDs;
}

} // namespace electronic_id
