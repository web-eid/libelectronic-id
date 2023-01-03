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

/*
 * PKCS11CardManager.hpp from Chrome Token Signing Native Host.
 */

#pragma once

#include "pkcs11.h"

#include "electronic-id/electronic-id.hpp"

#include "../common.hpp"
#include "../scope.hpp"
#include "../x509.hpp"

#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include <filesystem>
#include <functional>

#ifdef _WIN32
#include <Windows.h>
#else
#include <dlfcn.h>
#endif

#define C(API, ...) Call(__func__, __FILE__, __LINE__, "C_" #API, fl->C_##API, __VA_ARGS__)

// HANDLE is captured by copy into the lambda, so the auto* function argument is unused,
// it is only required for satisfying std::unique_ptr constructor requirements.
#define SCOPE_GUARD_SESSION(HANDLE, CLOSE)                                                         \
    std::unique_ptr<decltype(HANDLE), std::function<void(decltype(HANDLE)*)>>(                     \
        &HANDLE, [HANDLE, this](auto*) { C(CLOSE, HANDLE); })

namespace electronic_id
{

class PKCS11CardManager
{
public:
    PKCS11CardManager(const std::filesystem::path& module)
    {
        CK_C_GetFunctionList C_GetFunctionList = nullptr;
        std::string error;
#ifdef _WIN32
        library = LoadLibraryW(module.c_str());
        if (library) {
            C_GetFunctionList = CK_C_GetFunctionList(GetProcAddress(library, "C_GetFunctionList"));
        } else {
            LPSTR msg = nullptr;
            FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
                               | FORMAT_MESSAGE_IGNORE_INSERTS,
                           nullptr, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                           LPSTR(&msg), 0, nullptr);
            error = msg;
            LocalFree(msg);
        }
#else
        library = dlopen(module.c_str(), RTLD_LOCAL | RTLD_NOW);
        if (library) {
            C_GetFunctionList = CK_C_GetFunctionList(dlsym(library, "C_GetFunctionList"));
        } else {
            error = dlerror();
        }
#endif

        if (!C_GetFunctionList) {
            THROW(SmartCardChangeRequiredError,
                  "C_GetFunctionList loading failed for module '" + module.string() + "', error "
                      + error);
        }
        Call(__func__, __FILE__, __LINE__, "C_GetFunctionList", C_GetFunctionList, &fl);
        if (!fl) {
            THROW(SmartCardChangeRequiredError, "C_GetFunctionList: CK_FUNCTION_LIST_PTR is null");
        }
        C(Initialize, nullptr);
    }

    ~PKCS11CardManager()
    {
        if (!library)
            return;
        // Don't let exceptions out of destructor.
        try {
            C(Finalize, nullptr);
        } catch (...) {
            // TODO: _log(... C_Finalize error ...)
        }
#ifdef _WIN32
        FreeLibrary(library);
#else
        dlclose(library);
#endif
    }

    PCSC_CPP_DISABLE_COPY_MOVE(PKCS11CardManager);

    struct Token
    {
        std::string label;
        std::string serialNumber;
        CK_SLOT_ID slotID;
        std::vector<CK_BYTE> cert, certID;
        int8_t retry;
        bool pinpad;
        CK_ULONG minPinLen, maxPinLen;
    };

    std::vector<Token> tokens() const
    {
        CK_ULONG slotCount = 0;
        C(GetSlotList, CK_BBOOL(CK_TRUE), nullptr, &slotCount);
        std::vector<CK_SLOT_ID> slotIDs(slotCount);
        C(GetSlotList, CK_BBOOL(CK_TRUE), slotIDs.data(), &slotCount);

        std::vector<Token> result;
        for (CK_SLOT_ID slotID : slotIDs) {
            CK_TOKEN_INFO tokenInfo;
            try {
                C(GetTokenInfo, slotID, &tokenInfo);
            } catch (const Pkcs11Error&) {
                continue;
            }
            CK_SESSION_HANDLE session = 0;
            C(OpenSession, slotID, CKF_SERIAL_SESSION, nullptr, nullptr, &session);

            for (CK_OBJECT_HANDLE obj : findObject(session, CKO_CERTIFICATE)) {
                result.push_back({
                    std::string(reinterpret_cast<const char*>(tokenInfo.label),
                                sizeof(tokenInfo.label)),
                    std::string(reinterpret_cast<const char*>(tokenInfo.serialNumber),
                                sizeof(tokenInfo.serialNumber)),
                    slotID,
                    attribute(session, obj, CKA_VALUE),
                    attribute(session, obj, CKA_ID),
                    pinRetryCount(tokenInfo.flags),
                    (tokenInfo.flags & CKF_PROTECTED_AUTHENTICATION_PATH) > 0,
                    tokenInfo.ulMinPinLen,
                    tokenInfo.ulMaxPinLen,
                });
            }

            C(CloseSession, session);
        }
        return result;
    }

    electronic_id::ElectronicID::Signature sign(const Token& token,
                                                const std::vector<CK_BYTE>& hash,
                                                electronic_id::HashAlgorithm hashAlgo,
                                                const char* pin, size_t pinSize) const
    {
        CK_SESSION_HANDLE session = 0;
        C(OpenSession, token.slotID, CKF_SERIAL_SESSION, nullptr, nullptr, &session);
        auto closeSessionGuard = SCOPE_GUARD_SESSION(session, CloseSession);

        try {
            C(Login, session, CKU_USER, CK_CHAR_PTR(pin), CK_ULONG(pinSize));
        } catch (const VerifyPinFailed& e) {
            if (e.status() != VerifyPinFailed::Status::RETRY_ALLOWED)
                throw;
            try {
                CK_TOKEN_INFO tokenInfo;
                C(GetTokenInfo, token.slotID, &tokenInfo);
                throw VerifyPinFailed(VerifyPinFailed::Status::RETRY_ALLOWED, nullptr,
                                      pinRetryCount(tokenInfo.flags));
            } catch (const Pkcs11Error&) {
                throw e;
            }
        }

        auto logoutSessionGuard = SCOPE_GUARD_SESSION(session, Logout);

        if (token.certID.empty()) {
            THROW(Pkcs11Error, "Cannot access private key handle: certificate ID is empty");
        }
        std::vector<CK_OBJECT_HANDLE> privateKeyHandle =
            findObject(session, CKO_PRIVATE_KEY, token.certID);
        if (privateKeyHandle.empty()) {
            THROW(Pkcs11Error, "Cannot access private key handle: key not found");
        }
        if (privateKeyHandle.size() > 1) {
            THROW(Pkcs11Error, "Cannot access private key handle: found multiple keys");
        }
        // TODO: _log("Found %i private keys in slot, using key ID %x", privateKeyHandle.size(),
        //      token.certID.data());

        CK_KEY_TYPE keyType = CKK_RSA;
        CK_ATTRIBUTE attribute = {CKA_KEY_TYPE, &keyType, sizeof(keyType)};
        C(GetAttributeValue, session, privateKeyHandle[0], &attribute, 1ul);

        const electronic_id::SignatureAlgorithm signatureAlgorithm = {
            keyType == CKK_ECDSA ? electronic_id::SignatureAlgorithm::ES
                                 : electronic_id::SignatureAlgorithm::RS,
            hashAlgo};

        CK_MECHANISM mechanism = {keyType == CKK_ECDSA ? CKM_ECDSA : CKM_RSA_PKCS, nullptr, 0};
        C(SignInit, session, &mechanism, privateKeyHandle[0]);
        std::vector<CK_BYTE> hashWithPaddingOID =
            keyType == CKK_RSA ? addRSAOID(hashAlgo, hash) : hash;

        CK_ULONG signatureLength = 0;
        C(Sign, session, hashWithPaddingOID.data(), CK_ULONG(hashWithPaddingOID.size()), nullptr,
          &signatureLength);
        std::vector<CK_BYTE> signature(signatureLength);
        C(Sign, session, hashWithPaddingOID.data(), CK_ULONG(hashWithPaddingOID.size()),
          signature.data(), &signatureLength);

        return {signature, signatureAlgorithm};
    }

private:
    template <typename Func, typename... Args>
    static void Call(const char* function, const char* file, int line, const char* apiFunction,
                     Func func, Args... args)
    {
        CK_RV rv = func(args...);
        switch (rv) {
        case CKR_OK:
        case CKR_CRYPTOKI_ALREADY_INITIALIZED:
            break;
        case CKR_FUNCTION_CANCELED:
            throw VerifyPinFailed(VerifyPinFailed::Status::PIN_ENTRY_CANCEL);
        case CKR_PIN_INCORRECT:
            throw VerifyPinFailed(VerifyPinFailed::Status::RETRY_ALLOWED);
        case CKR_PIN_LEN_RANGE:
            throw VerifyPinFailed(VerifyPinFailed::Status::INVALID_PIN_LENGTH);
        case CKR_PIN_LOCKED:
            throw VerifyPinFailed(VerifyPinFailed::Status::PIN_BLOCKED);
        case CKR_TOKEN_NOT_RECOGNIZED:
            THROW_WITH_CALLER_INFO(SmartCardChangeRequiredError,
                                   std::string(apiFunction) + ": token not recognized", file, line,
                                   function);
        case CKR_TOKEN_NOT_PRESENT:
            THROW_WITH_CALLER_INFO(Pkcs11TokenNotPresent,
                                   std::string(apiFunction) + ": token not present", file, line,
                                   function);
        case CKR_DEVICE_REMOVED:
            THROW_WITH_CALLER_INFO(Pkcs11TokenRemoved,
                                   std::string(apiFunction) + ": token was removed", file, line,
                                   function);
        case CKR_USER_NOT_LOGGED_IN: {
            // Special case for C_Logout as it returns CKR_USER_NOT_LOGGED_IN with Croatian eID card
            // when exiting sign().
            const auto fn = std::string(apiFunction);
            if (fn != "C_Logout") {
                THROW_WITH_CALLER_INFO(Pkcs11Error,
                                       fn + " failed with return code " + pcsc_cpp::int2hexstr(rv),
                                       file, line, function);
            };
            break;
        }
        default:
            THROW_WITH_CALLER_INFO(Pkcs11Error,
                                   std::string(apiFunction) + " failed with return code "
                                       + pcsc_cpp::int2hexstr(rv),
                                   file, line, function);
        }
    }

    std::vector<CK_BYTE> attribute(CK_SESSION_HANDLE session, CK_OBJECT_CLASS obj,
                                   CK_ATTRIBUTE_TYPE attr) const
    {
        CK_ATTRIBUTE attribute = {attr, nullptr, 0};
        C(GetAttributeValue, session, obj, &attribute, 1ul);
        std::vector<CK_BYTE> data(attribute.ulValueLen);
        attribute.pValue = data.data();
        C(GetAttributeValue, session, obj, &attribute, 1ul);
        return data;
    }

    std::vector<CK_OBJECT_HANDLE> findObject(CK_SESSION_HANDLE session, CK_OBJECT_CLASS objectClass,
                                             const std::vector<CK_BYTE>& id = {}) const
    {
        CK_BBOOL btrue = CK_TRUE;
        std::vector<CK_ATTRIBUTE> searchAttribute {
            {CKA_CLASS, &objectClass, CK_ULONG(sizeof(objectClass))},
            {CKA_TOKEN, &btrue, CK_ULONG(sizeof(btrue))}};
        if (!id.empty()) {
            searchAttribute.push_back({CKA_ID, CK_VOID_PTR(id.data()), CK_ULONG(id.size())});
        }
        C(FindObjectsInit, session, searchAttribute.data(), CK_ULONG(searchAttribute.size()));
        CK_ULONG objectCount = 32;
        std::vector<CK_OBJECT_HANDLE> objectHandle(objectCount);
        C(FindObjects, session, objectHandle.data(), CK_ULONG(objectHandle.size()), &objectCount);
        C(FindObjectsFinal, session);
        objectHandle.resize(objectCount);
        return objectHandle;
    }

    static int8_t pinRetryCount(CK_FLAGS flags)
    {
        // As PKCS#11 does not provide an API for querying remaining PIN retries, we currently
        // simply assume max retry count of 3, which is quite common. We might need to revisit this
        // in the future once it becomes a problem.
        if (flags & CKF_USER_PIN_LOCKED) {
            return 0;
        }
        if (flags & CKF_USER_PIN_FINAL_TRY) {
            return 1;
        }
        if (flags & CKF_USER_PIN_COUNT_LOW) {
            return 2;
        }
        return 3;
    }

#ifdef _WIN32
    HINSTANCE library = 0;
#else
    void* library = nullptr;
#endif
    CK_FUNCTION_LIST_PTR fl = nullptr;
};

} // namespace electronic_id
